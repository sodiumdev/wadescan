use std::{
    io::Error,
    os::fd::{AsRawFd, RawFd},
    ptr::NonNull,
};

use libc::*;
use serde::{Deserialize, Serialize};

use crate::xdp::{
    libc::{
        Descriptor, SocketOption, Umem,
        sockopt::{
            SocketBusyPoll, SocketBusyPollBudget, SocketOptionKind, SocketPreferBusyPoll,
            XdpMmapOffsets, XdpRxRing, XdpTxRing, XdpUmemCompletionRing, XdpUmemFillRing,
            XdpUmemReg,
        },
    },
    ring::{Ring, RingOffset},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct UmemConfig {
    pub fill_ring_size: u32,
    pub completion_ring_size: u32,
    pub chunk_count: usize,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SocketConfig {
    pub rx_ring_size: u32,
    pub tx_ring_size: u32,
    pub bind_flags: u16,
    pub interface_index: u32,
    pub queue_id: u32,
    pub busy_poll_budget: Option<i32>,
}

#[derive(Debug)]
pub enum SocketError {
    Socket(Error),
    Mmap(Error),
    SetSocketOption { inner: Error, opt: SocketOptionKind },
    GetSocketOption { inner: Error, opt: SocketOptionKind },
    Bind(Error),
}

pub struct XdpSocket<'a> {
    fd: c_int,

    umem: Umem<'a>,

    pub fill_ring: Ring<'a, u64>,
    pub completion_ring: Ring<'a, u64>,
    pub rx_ring: Ring<'a, Descriptor>,
    pub tx_ring: Ring<'a, Descriptor>,
}

impl XdpSocket<'_> {
    pub fn new(
        socket_config: &SocketConfig,
        umem_config: &UmemConfig,
    ) -> Result<Self, SocketError> {
        let fd = unsafe { socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(SocketError::Socket(Error::last_os_error()));
        }

        let umem = Umem::new(umem_config)?;
        XdpUmemReg::set(fd, &umem)?;

        XdpUmemFillRing::set(fd, &umem_config.fill_ring_size)?;
        XdpUmemCompletionRing::set(fd, &umem_config.completion_ring_size)?;
        XdpRxRing::set(fd, &socket_config.rx_ring_size)?;
        XdpTxRing::set(fd, &socket_config.tx_ring_size)?;

        let offsets = XdpMmapOffsets::get(fd)?;

        let fill_ring =
            Ring::<u64>::new(fd, umem_config.fill_ring_size, &offsets, RingOffset::Fill)?;
        let completion_ring = Ring::<u64>::new(
            fd,
            umem_config.completion_ring_size,
            &offsets,
            RingOffset::Completion,
        )?;
        let rx_ring =
            Ring::<Descriptor>::new(fd, socket_config.rx_ring_size, &offsets, RingOffset::Rx)?;
        let tx_ring =
            Ring::<Descriptor>::new(fd, socket_config.tx_ring_size, &offsets, RingOffset::Tx)?;

        if let Some(busy_poll_budget) = &socket_config.busy_poll_budget {
            SocketPreferBusyPoll::set(fd, &1)?;
            SocketBusyPoll::set(fd, &20)?;
            SocketBusyPollBudget::set(fd, busy_poll_budget)?;
        }

        let sxdp = sockaddr_xdp {
            sxdp_family: PF_XDP as _,
            sxdp_flags: socket_config.bind_flags,
            sxdp_ifindex: socket_config.interface_index,
            sxdp_queue_id: socket_config.queue_id,
            sxdp_shared_umem_fd: 0,
        };

        if unsafe {
            bind(
                fd,
                &raw const sxdp as *const _,
                size_of::<sockaddr_xdp>() as socklen_t,
            )
        } != 0
        {
            return Err(SocketError::Bind(Error::last_os_error()));
        }

        Ok(XdpSocket {
            fd,

            umem,

            fill_ring,
            completion_ring,
            rx_ring,
            tx_ring,
        })
    }

    #[inline]
    pub fn get<T>(&self, addr: usize) -> NonNull<T> {
        unsafe { self.umem.mmap.area.add(addr).cast() }
    }

    #[inline]
    pub fn submit_tx(&mut self, batch_size: u32) -> u32 {
        let got = self.tx_ring.reserve(batch_size);
        if got > 0 {
            self.tx_ring.submit(got);
        }

        got
    }

    #[inline]
    pub fn complete_tx(&mut self, batch_size: u32) -> u32 {
        let got = self.completion_ring.peek(batch_size);
        if got != 0 {
            self.completion_ring.release(got);
        }

        got
    }
}

impl AsRawFd for XdpSocket<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for XdpSocket<'_> {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}
