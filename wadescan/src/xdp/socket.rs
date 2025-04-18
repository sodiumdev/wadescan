use std::{
    io::Error,
    os::fd::{AsRawFd, RawFd},
    ptr::{NonNull, null},
};

use libc::*;
use serde::{Deserialize, Serialize};

use crate::xdp::{
    libc::{
        SocketOption, Umem,
        sockopt::{
            SocketBusyPoll, SocketBusyPollBudget, SocketOptionKind, SocketPreferBusyPoll,
            XdpMmapOffsets, XdpUmemReg,
        },
    },
    ring::Ring,
};

pub struct XdpSocket<'a> {
    fd: c_int,

    umem: Umem<'a>,

    fill_ring: Ring<'a>,
    completion_ring: Ring<'a>,
    rx_ring: Ring<'a>,
    tx_ring: Ring<'a>,
}

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

        let offsets = XdpMmapOffsets::get(fd)?;

        let fill_ring = Ring::fill(fd, umem_config.fill_ring_size, &offsets)?;
        let completion_ring = Ring::completion(fd, umem_config.completion_ring_size, &offsets)?;
        let rx_ring = Ring::rx(fd, socket_config.rx_ring_size, &offsets)?;
        let tx_ring = Ring::tx(fd, socket_config.tx_ring_size, &offsets)?;

        if let Some(busy_poll_budget) = &socket_config.busy_poll_budget {
            SocketPreferBusyPoll::set(fd, &1)?;
            SocketBusyPoll::set(fd, &20)?;
            SocketBusyPollBudget::set(fd, busy_poll_budget)?;
        }

        let sxdp = sockaddr_xdp {
            sxdp_family: PF_XDP as __u16,
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
    pub unsafe fn desc(&mut self, index: usize) -> &mut xdp_desc {
        unsafe { self.tx_ring.get_unchecked_mut(index) }
    }

    #[inline]
    pub fn get<T>(&self, addr: usize) -> NonNull<T> {
        unsafe { self.umem.area.area.byte_add(addr) }.cast()
    }

    #[inline]
    pub fn kick_tx(&mut self) -> ssize_t {
        unsafe { sendto(self.fd, null(), 0, MSG_DONTWAIT, null(), 0) }
    }

    #[inline]
    pub fn submit_tx(&mut self, batch_size: __u32) -> __u32 {
        let got = self.tx_ring.reserve(batch_size);
        if got > 0 {
            self.tx_ring.submit(got);
        }

        got
    }

    #[inline]
    pub fn complete_tx(&mut self, batch_size: __u32) -> __u32 {
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

impl AsRawFd for &XdpSocket<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
