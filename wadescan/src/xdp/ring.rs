use std::{
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};

use libc::*;

use crate::xdp::{
    libc::{
        MapFlags, Mmap, MmapOffsets, Protection, SocketOption,
        sockopt::{XdpUmemCompletionRing, XdpUmemFillRing, XdpUmemRxRing, XdpUmemTxRing},
    },
    socket::SocketError,
};

pub struct Ring<'a> {
    cached_prod: u32,
    cached_cons: u32,
    mask: usize,
    size: u32,

    producer: &'a AtomicU32,
    consumer: &'a AtomicU32,
    ring: NonNull<u8>,
}

impl Ring<'_> {
    #[inline]
    pub fn fill(fd: i32, size: u32, offsets: &MmapOffsets) -> Result<Self, SocketError> {
        XdpUmemFillRing::set(fd, &size)?;

        let area = Mmap::new(
            fd,
            XDP_UMEM_PGOFF_FILL_RING as _,
            offsets.fill_ring.desc as usize + size as usize * size_of::<__u64>(),
            Protection::READ | Protection::WRITE,
            MapFlags::SHARED | MapFlags::POPULATE,
        )?;

        let producer =
            unsafe { AtomicU32::from_ptr(area.offset(offsets.fill_ring.producer).as_ptr()) };
        let consumer =
            unsafe { AtomicU32::from_ptr(area.offset(offsets.fill_ring.consumer).as_ptr()) };

        Ok(Self {
            cached_prod: 0,
            cached_cons: size,
            mask: (size - 1) as usize,
            size,
            producer,
            consumer,
            ring: area.offset(offsets.fill_ring.desc),
        })
    }

    #[inline]
    pub fn completion(fd: i32, size: u32, offsets: &MmapOffsets) -> Result<Self, SocketError> {
        XdpUmemCompletionRing::set(fd, &size)?;

        let area = Mmap::new(
            fd,
            XDP_UMEM_PGOFF_COMPLETION_RING as _,
            offsets.completion_ring.desc as usize + size as usize * size_of::<__u64>(),
            Protection::READ | Protection::WRITE,
            MapFlags::SHARED | MapFlags::POPULATE,
        )?;

        let producer =
            unsafe { AtomicU32::from_ptr(area.offset(offsets.completion_ring.producer).as_ptr()) };
        let consumer =
            unsafe { AtomicU32::from_ptr(area.offset(offsets.completion_ring.consumer).as_ptr()) };

        Ok(Self {
            cached_prod: 0,
            cached_cons: 0,
            mask: (size - 1) as usize,
            size,
            producer,
            consumer,
            ring: area.offset(offsets.completion_ring.desc),
        })
    }

    #[inline]
    pub fn rx(fd: i32, size: u32, offsets: &MmapOffsets) -> Result<Self, SocketError> {
        XdpUmemRxRing::set(fd, &size)?;

        let area = Mmap::new(
            fd,
            XDP_PGOFF_RX_RING,
            offsets.rx_ring.desc as usize + size as usize * size_of::<xdp_desc>(),
            Protection::READ | Protection::WRITE,
            MapFlags::SHARED | MapFlags::POPULATE,
        )?;

        let producer =
            unsafe { AtomicU32::from_ptr(area.offset(offsets.rx_ring.producer).as_ptr()) };
        let consumer =
            unsafe { AtomicU32::from_ptr(area.offset(offsets.rx_ring.consumer).as_ptr()) };

        Ok(Self {
            cached_prod: producer.load(Ordering::Relaxed),
            cached_cons: consumer.load(Ordering::Relaxed),
            mask: (size - 1) as usize,
            size,
            producer,
            consumer,
            ring: area.offset(offsets.rx_ring.desc),
        })
    }

    #[inline]
    pub fn tx(fd: i32, size: u32, offsets: &MmapOffsets) -> Result<Self, SocketError> {
        XdpUmemTxRing::set(fd, &size)?;

        let area = Mmap::new(
            fd,
            XDP_PGOFF_TX_RING,
            offsets.tx_ring.desc as usize + size as usize * size_of::<xdp_desc>(),
            Protection::READ | Protection::WRITE,
            MapFlags::SHARED | MapFlags::POPULATE,
        )?;

        let producer =
            unsafe { AtomicU32::from_ptr(area.offset(offsets.tx_ring.producer).as_ptr()) };
        let consumer =
            unsafe { AtomicU32::from_ptr(area.offset(offsets.tx_ring.consumer).as_ptr()) };

        Ok(Self {
            cached_prod: producer.load(Ordering::Relaxed),
            cached_cons: consumer.load(Ordering::Relaxed) + size,
            mask: (size - 1) as usize,
            size,
            producer,
            consumer,
            ring: area.offset(offsets.tx_ring.desc),
        })
    }

    #[inline]
    pub fn nb_free(&mut self, nb: __u32) -> __u32 {
        let free_entries = self.cached_cons - self.cached_prod;
        if free_entries >= nb {
            return free_entries;
        }

        self.cached_cons = self.consumer.load(Ordering::Acquire) + self.size;
        self.cached_cons - self.cached_prod
    }

    #[inline]
    pub fn nb_available(&mut self, nb: u32) -> u32 {
        let mut entries = self.cached_cons - self.cached_prod;
        if entries == 0 {
            self.cached_prod = self.producer.load(Ordering::Acquire);
            entries = self.cached_cons - self.cached_prod;
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
        if entries > 0 {
            self.cached_cons += entries;
        }

        entries
    }

    #[inline]
    pub fn release(&mut self, nb: u32) {
        self.consumer.fetch_add(nb, Ordering::Release);
    }

    #[inline]
    pub unsafe fn get_unchecked_mut(&mut self, index: usize) -> &mut xdp_desc {
        unsafe { self.ring.cast().add(index & self.mask).as_mut() }
    }
}
