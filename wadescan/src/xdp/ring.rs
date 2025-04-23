use std::{
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};

use libc::*;

use crate::xdp::{
    libc::{MapFlags, Mmap, MmapOffsets, Protection},
    socket::SocketError,
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
    mask: usize,
    size: u32,

    _mmap: Mmap<'a>,

    producer: &'a AtomicU32,
    consumer: &'a AtomicU32,
    ring: NonNull<T>,
}

impl<T> Ring<'_, T> {
    pub fn new(
        fd: i32,
        size: u32,
        offsets: &MmapOffsets,
        offset: RingOffset,
    ) -> Result<Self, SocketError> {
        let ring_offsets = match offset {
            RingOffset::Fill => &offsets.fill_ring,
            RingOffset::Completion => &offsets.completion_ring,
            RingOffset::Tx => &offsets.tx_ring,
            RingOffset::Rx => &offsets.rx_ring,
        };

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
            ring: mmap.offset(ring_offsets.desc),
            _mmap: mmap,
        })
    }

    #[inline]
    pub fn nb_free(&mut self, nb: u32) -> u32 {
        let free_entries = self.cached_cons - self.cached_prod;
        if free_entries >= nb {
            return free_entries;
        }

        self.cached_cons = self.consumer.load(Ordering::Acquire) + self.size;
        self.cached_cons - self.cached_prod
    }

    #[inline]
    pub fn nb_available(&mut self, nb: u32) -> u32 {
        let mut entries = self.cached_prod - self.cached_cons;
        if entries == 0 {
            self.cached_prod = self.producer.load(Ordering::Acquire);
            entries = self.cached_prod - self.cached_cons;
        }

        u32::min(entries, nb)
    }

    #[inline]
    pub fn reserve(&mut self, nb: u32) -> u32 {
        if self.nb_free(nb) < nb {
            return 0;
        }

        self.cached_prod += nb;

        nb
    }

    #[inline]
    pub fn submit(&mut self, nb: u32) {
        self.producer.fetch_add(nb, Ordering::Release);
    }

    #[inline]
    pub fn peek(&mut self, nb: u32) -> u32 {
        let entries = self.nb_available(nb);
        self.cached_cons += entries;

        entries
    }

    #[inline]
    pub fn release(&mut self, nb: u32) {
        self.consumer.fetch_add(nb, Ordering::Release);
    }

    #[inline]
    pub unsafe fn get_unchecked_mut(&mut self, index: usize) -> &mut T {
        unsafe { self.ring.add(index & self.mask).as_mut() }
    }
}
