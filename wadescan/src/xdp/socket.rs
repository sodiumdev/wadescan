use std::{
    io::Error,
    os::fd::{AsRawFd, RawFd},
    ptr::null,
};

use libc::*;

use crate::xdp::libc::{
    FrCr, RxTx, SocketOption, Umem,
    sockopt::{
        SocketBusyPoll, SocketBusyPollBudget, SocketOptionKind, SocketPreferBusyPoll,
        XdpMmapOffsets, XdpUmemReg,
    },
};

pub struct UmemOptions {
    pub chunk_count: usize,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

pub struct SocketOptions {
    pub rx_ring_size: u32,
    pub tx_ring_size: u32,
    pub busy_poll_budget: i32,
}

#[derive(Debug)]
pub enum XdpError {
    Socket(Error),
    Mmap(Error),
    SetSocketOption { inner: Error, opt: SocketOptionKind },
    GetSocketOption { inner: Error, opt: SocketOptionKind },
    Bind(Error),
}

pub struct XdpSocket {
    fd: RawFd,
}

impl XdpSocket {
    pub fn new() -> Result<Self, XdpError> {
        let fd = unsafe { socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(XdpError::Socket(Error::last_os_error()));
        }

        Ok(XdpSocket { fd })
    }

    #[inline]
    pub fn frcr<'a>(
        &self,
        umem: &Umem<'a>,
        fill_size: u32,
        completion_size: u32,
    ) -> Result<FrCr<'a>, XdpError> {
        XdpUmemReg::set(self.fd, umem)?;

        let offsets = XdpMmapOffsets::get(self.fd)?;

        FrCr::new(self.fd, &offsets, fill_size, completion_size)
    }

    #[inline]
    pub fn rxtx<'a>(&self, rx_size: u32, tx_size: u32) -> Result<RxTx<'a>, XdpError> {
        let offsets = XdpMmapOffsets::get(self.fd)?;

        RxTx::new(self.fd, &offsets, rx_size, tx_size)
    }

    #[inline]
    pub fn busy_poll(&self, budget: i32) -> Result<(), XdpError> {
        SocketPreferBusyPoll::set(self.fd, &1)?;
        SocketBusyPoll::set(self.fd, &20)?;
        SocketBusyPollBudget::set(self.fd, &budget)?;

        Ok(())
    }

    #[inline]
    pub fn bind(
        &self,
        flags: u16,
        interface_index: u32,
        queue_id: u32,
        shared_umem_fd: u32,
    ) -> Result<(), XdpError> {
        let sxdp = sockaddr_xdp {
            sxdp_family: PF_XDP as _,
            sxdp_flags: flags,
            sxdp_ifindex: interface_index,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: shared_umem_fd,
        };

        if unsafe {
            bind(
                self.fd,
                &raw const sxdp as *const _,
                size_of::<sockaddr_xdp>() as socklen_t,
            )
        } != 0
        {
            return Err(XdpError::Bind(Error::last_os_error()));
        }

        Ok(())
    }

    #[inline]
    pub fn wake(&self) -> Result<(), Error> {
        let ret = unsafe { sendto(self.fd, null(), 0, MSG_DONTWAIT, null(), 0) };

        if ret < 0 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }
}

unsafe impl Send for XdpSocket {}
unsafe impl Sync for XdpSocket {}

impl AsRawFd for XdpSocket {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}
