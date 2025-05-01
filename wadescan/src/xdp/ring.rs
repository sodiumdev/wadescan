use std::{
    slice::from_raw_parts_mut,
    sync::atomic::{AtomicU32, Ordering},
};

use libc::*;

use crate::xdp::{
    libc::{MapFlags, Mmap, Protection, RingAddressOffsets},
    socket::XdpError,
};

pub enum RingOffset {
    Fill,
    Completion,
    Tx,
    Rx,
}

impl RingOffset {
    #[inline]
    pub const fn id(&self) -> i64 {
        match self {
            RingOffset::Fill => XDP_UMEM_PGOFF_FILL_RING as _,
            RingOffset::Completion => XDP_UMEM_PGOFF_COMPLETION_RING as _,
            RingOffset::Tx => XDP_PGOFF_TX_RING,
            RingOffset::Rx => XDP_PGOFF_RX_RING,
        }
    }
}

pub struct Ring<'a, T> {
    cached_prod: u32,
    cached_cons: u32,
    pub(crate) mask: usize,
    size: u32,

    producer: &'a AtomicU32,
    consumer: &'a AtomicU32,
    pub(crate) ring: &'a mut [T],

    flags: &'a AtomicU32,

    _mmap: Mmap<'a>,
}

unsafe impl<T> Send for Ring<'_, T> {}
unsafe impl<T> Sync for Ring<'_, T> {}

impl<T> Ring<'_, T> {
    pub fn new(
        fd: i32,
        size: u32,
        ring_offsets: &RingAddressOffsets,
        offset: RingOffset,
    ) -> Result<Self, XdpError> {
        let mmap = Mmap::new(
            fd,
            offset.id(),
            ring_offsets.desc as usize + size as usize * size_of::<T>(),
            Protection::READ | Protection::WRITE,
            MapFlags::SHARED | MapFlags::POPULATE,
        )?;

        let producer = unsafe { AtomicU32::from_ptr(mmap.offset(ring_offsets.producer).as_ptr()) };
        let consumer = unsafe { AtomicU32::from_ptr(mmap.offset(ring_offsets.consumer).as_ptr()) };

        let (cached_prod, cached_cons) = match offset {
            RingOffset::Fill => (0, size),
            RingOffset::Completion => (0, 0),
            RingOffset::Tx => (
                producer.load(Ordering::Relaxed),
                consumer.load(Ordering::Relaxed) + size,
            ),
            RingOffset::Rx => (
                producer.load(Ordering::Relaxed),
                consumer.load(Ordering::Relaxed),
            ),
        };

        Ok(Self {
            cached_prod,
            cached_cons,
            mask: (size - 1) as usize,
            size,
            producer,
            consumer,
            ring: unsafe {
                from_raw_parts_mut(mmap.offset(ring_offsets.desc).as_ptr(), size as usize)
            },
            flags: unsafe { AtomicU32::from_ptr(mmap.offset(ring_offsets.flags).as_ptr()) },
            _mmap: mmap,
        })
    }

    #[inline]
    pub fn needs_wakeup(&self) -> bool {
        (self.flags.load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP) != 0
    }

    #[inline]
    pub fn nb_free(&mut self, batch_size: u32) -> u32 {
        let free_entries = self.cached_cons - self.cached_prod;
        if free_entries >= batch_size {
            return free_entries;
        }

        self.cached_cons = self.consumer.load(Ordering::Acquire) + self.size;
        self.cached_cons - self.cached_prod
    }

    #[inline]
    pub fn nb_available(&mut self, batch_size: u32) -> u32 {
        let mut entries = self.cached_prod - self.cached_cons;
        if entries == 0 {
            self.cached_prod = self.producer.load(Ordering::Acquire);
            entries = self.cached_prod - self.cached_cons;
        }

        u32::min(entries, batch_size)
    }

    #[inline]
    pub fn reserve(&mut self, batch_size: u32) -> Option<u32> {
        if self.nb_free(batch_size) < batch_size {
            return None;
        }

        let index = self.cached_prod;
        self.cached_prod += batch_size;

        Some(index)
    }

    #[inline]
    pub fn submit(&mut self, batch_size: u32) -> u32 {
        self.producer.fetch_add(batch_size, Ordering::Release)
    }

    #[inline]
    pub fn peek(&mut self, batch_size: u32) -> u32 {
        let entries = self.nb_available(batch_size);
        self.cached_cons += entries;

        entries
    }

    #[inline]
    pub fn release(&mut self, nb: u32) -> u32 {
        self.consumer.fetch_add(nb, Ordering::Release)
    }
}
