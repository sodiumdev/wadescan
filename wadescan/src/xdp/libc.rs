use std::{
    io::{Error, ErrorKind},
    marker::PhantomData,
    mem::MaybeUninit,
    ops::Deref,
    ptr::{NonNull, null_mut},
};

use bitflags::bitflags;
use futures::TryStreamExt;
use libc::*;

use crate::xdp::{
    libc::sockopt::SocketOptionKind,
    socket::{SocketError, UmemConfig},
};

pub const SO_PREFER_BUSY_POLL: c_int = 69;
pub const SO_BUSY_POLL_BUDGET: c_int = 70;

pub trait SocketOption<T>: Copy + Default {
    const TYPE: SocketOptionKind;
    const LEVEL: c_int;
    const NAME: c_int;

    #[inline]
    fn set(fd: i32, value: &T) -> Result<(), SocketError> {
        if unsafe {
            setsockopt(
                fd,
                Self::LEVEL,
                Self::NAME,
                value as *const T as *const _,
                size_of::<T>() as _,
            )
        } != 0
        {
            return Err(SocketError::SetSocketOption {
                inner: Error::last_os_error(),
                opt: Self::TYPE,
            });
        }

        Ok(())
    }

    #[inline]
    fn get(fd: i32) -> Result<T, SocketError> {
        let mut uninit = MaybeUninit::<T>::uninit();
        let mut size = size_of::<T>() as socklen_t;
        if unsafe {
            getsockopt(
                fd,
                Self::LEVEL,
                Self::NAME,
                uninit.as_mut_ptr() as *mut _,
                &raw mut size,
            )
        } != 0
        {
            return Err(SocketError::GetSocketOption {
                inner: Error::last_os_error(),
                opt: Self::TYPE,
            });
        }

        Ok(unsafe { uninit.assume_init() })
    }
}

pub mod sockopt {
    use libc::*;

    use crate::xdp::libc::{
        MmapOffsets, SO_BUSY_POLL_BUDGET, SO_PREFER_BUSY_POLL, SocketOption, Umem,
    };

    macro_rules! option_of {
        ($($stname:ident, $ty:ty, $level:expr, $name:expr)*) => {
            #[derive(Copy, Clone, Debug)]
            pub enum SocketOptionKind {
                $($stname),*
            }

            $(
            #[derive(Copy, Clone, Default, Debug)]
            pub struct $stname;

            impl SocketOption<$ty> for $stname {
                const TYPE: SocketOptionKind = SocketOptionKind::$stname;
                const LEVEL: c_int = $level;
                const NAME: c_int = $name;
            }
            )*
        };
    }

    option_of!(
        XdpUmemReg, Umem<'_>, SOL_XDP, XDP_UMEM_REG
        XdpUmemFillRing, c_uint, SOL_XDP, XDP_UMEM_FILL_RING
        XdpUmemCompletionRing, c_uint, SOL_XDP, XDP_UMEM_COMPLETION_RING
        XdpRxRing, c_uint, SOL_XDP, XDP_RX_RING
        XdpTxRing, c_uint, SOL_XDP, XDP_TX_RING
        XdpMmapOffsets, MmapOffsets, SOL_XDP, XDP_MMAP_OFFSETS
        SocketBusyPoll, c_int, SOL_SOCKET, SO_BUSY_POLL
        SocketPreferBusyPoll, c_int, SOL_SOCKET, SO_PREFER_BUSY_POLL
        SocketBusyPollBudget, c_int, SOL_SOCKET, SO_BUSY_POLL_BUDGET
    );
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Protection: c_int {
        const NONE = PROT_NONE;
        const READ = PROT_READ;
        const WRITE = PROT_WRITE;
        const EXEC = PROT_EXEC;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MapFlags: c_int {
        const SHARED = MAP_SHARED;
        const PRIVATE = MAP_PRIVATE;
        const LOCKED = MAP_LOCKED;
        const NORESERVE = MAP_NORESERVE;
        const ANONYMOUS = MAP_ANONYMOUS;
        const POPULATE = MAP_POPULATE;
    }
}

#[repr(C)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

#[repr(C)]
pub struct RingAddressOffsets {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

#[repr(C)]
pub struct MmapOffsets {
    pub rx_ring: RingAddressOffsets,
    pub tx_ring: RingAddressOffsets,
    pub fill_ring: RingAddressOffsets,
    pub completion_ring: RingAddressOffsets,
}

#[repr(C)]
pub struct Mmap<'a> {
    _phantom: PhantomData<&'a u8>,
    // guaranteed 64-bit for 64-bit systems
    pub(crate) area: NonNull<u8>,
    len: u64,
}

impl Mmap<'_> {
    #[inline]
    pub fn new(
        fd: i32,
        offset: i64,
        len: usize,
        prot: Protection,
        flags: MapFlags,
    ) -> Result<Self, SocketError> {
        let area = unsafe { mmap(null_mut(), len, prot.bits(), flags.bits(), fd, offset) };
        if area == MAP_FAILED {
            return Err(SocketError::Mmap(Error::last_os_error()));
        }

        Ok(Self {
            _phantom: Default::default(),
            area: NonNull::new(area.cast()).ok_or_else(|| {
                SocketError::Mmap(Error::new(ErrorKind::InvalidData, "mmap result is null!"))
            })?,
            len: len as _,
        })
    }

    #[inline]
    pub fn offset<T>(&self, offset: u64) -> NonNull<T> {
        unsafe { self.area.add(offset as usize) }.cast()
    }
}

impl Drop for Mmap<'_> {
    fn drop(&mut self) {
        unsafe {
            munmap(self.area.as_ptr().cast(), self.len as _);
        }
    }
}

#[repr(C)]
pub struct Umem<'a> {
    pub(crate) mmap: Mmap<'a>,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

impl Umem<'_> {
    #[inline]
    pub fn new(umem_config: &UmemConfig) -> Result<Self, SocketError> {
        Ok(Self {
            mmap: Mmap::new(
                -1,
                0,
                umem_config.chunk_count * umem_config.chunk_size as usize,
                Protection::READ | Protection::WRITE | Protection::EXEC,
                MapFlags::PRIVATE | MapFlags::ANONYMOUS | MapFlags::NORESERVE,
            )?,
            chunk_size: umem_config.chunk_size,
            headroom: umem_config.headroom,
            flags: umem_config.flags,
            tx_metadata_len: size_of::<xsk_tx_metadata>() as _,
        })
    }
}
