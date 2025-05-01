use std::{
    io::{Error, ErrorKind},
    marker::PhantomData,
    mem::MaybeUninit,
    ops::{Deref, Index, IndexMut, RangeFrom},
    os::fd::{AsRawFd, RawFd},
    ptr::{NonNull, null_mut, slice_from_raw_parts, slice_from_raw_parts_mut},
    slice::SliceIndex,
};

use bitflags::bitflags;
use futures::TryStreamExt;
use libc::*;

use crate::xdp::{
    libc::sockopt::{
        SocketOptionKind, XdpRxRing, XdpTxRing, XdpUmemCompletionRing, XdpUmemFillRing,
    },
    ring::{Ring, RingOffset},
    socket::{UmemOptions, XdpError},
};

pub const SO_PREFER_BUSY_POLL: c_int = 69;
pub const SO_BUSY_POLL_BUDGET: c_int = 70;

pub trait SocketOption<T>: Copy + Default {
    const TYPE: SocketOptionKind;
    const LEVEL: c_int;
    const NAME: c_int;

    #[inline]
    fn set(fd: i32, value: &T) -> Result<(), XdpError> {
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
            return Err(XdpError::SetSocketOption {
                inner: Error::last_os_error(),
                opt: Self::TYPE,
            });
        }

        Ok(())
    }

    #[inline]
    fn get(fd: i32) -> Result<T, XdpError> {
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
            return Err(XdpError::GetSocketOption {
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
    _phantom: PhantomData<&'a [u8]>,
    // guaranteed 64-bit for 64-bit systems
    // for any other bit systems, this will break
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
    ) -> Result<Self, XdpError> {
        let area = unsafe { mmap(null_mut(), len, prot.bits(), flags.bits(), fd, offset) };
        if std::ptr::eq(area, MAP_FAILED) {
            return Err(XdpError::Mmap(Error::last_os_error()));
        }

        Ok(Self {
            _phantom: Default::default(),
            area: NonNull::new(area.cast()).ok_or_else(|| {
                XdpError::Mmap(Error::new(ErrorKind::InvalidData, "mmap result is null!"))
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

pub struct FrCr<'a> {
    fill: Ring<'a, u64>,
    completion: Ring<'a, u64>,
}

impl<'a> FrCr<'a> {
    #[inline]
    pub(crate) fn new(
        fd: RawFd,
        offsets: &MmapOffsets,
        fill_size: u32,
        completion_size: u32,
    ) -> Result<Self, XdpError> {
        XdpUmemFillRing::set(fd, &fill_size)?;
        XdpUmemCompletionRing::set(fd, &completion_size)?;

        let fill = Ring::<u64>::new(fd, fill_size, &offsets.fill_ring, RingOffset::Fill)?;
        let completion = Ring::<u64>::new(
            fd,
            completion_size,
            &offsets.completion_ring,
            RingOffset::Completion,
        )?;

        Ok(Self { fill, completion })
    }

    #[inline]
    pub fn complete(&mut self, batch_size: u32) -> u32 {
        let got = self.completion.peek(batch_size);
        if got != 0 {
            self.completion.release(got);
        }

        got
    }
}

pub struct RxTx<'a> {
    pub rx: Ring<'a, Descriptor>,
    pub tx: Ring<'a, Descriptor>,
}

impl RxTx<'_> {
    #[inline]
    pub(crate) fn new(
        fd: RawFd,
        offsets: &MmapOffsets,
        rx_ring: u32,
        tx_ring: u32,
    ) -> Result<Self, XdpError> {
        XdpRxRing::set(fd, &rx_ring)?;
        XdpTxRing::set(fd, &tx_ring)?;

        let rx = Ring::<Descriptor>::new(fd, rx_ring, &offsets.rx_ring, RingOffset::Rx)?;
        let tx = Ring::<Descriptor>::new(fd, tx_ring, &offsets.tx_ring, RingOffset::Tx)?;

        Ok(Self { rx, tx })
    }
}

impl Index<u64> for RxTx<'_> {
    type Output = Descriptor;

    #[inline]
    fn index(&self, index: u64) -> &Descriptor {
        &self.tx.ring[index as usize & self.tx.mask]
    }
}

impl IndexMut<u64> for RxTx<'_> {
    #[inline]
    fn index_mut(&mut self, index: u64) -> &mut Descriptor {
        &mut self.tx.ring[index as usize & self.tx.mask]
    }
}

#[repr(C)]
pub struct Umem<'a> {
    mmap: Mmap<'a>,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

impl Umem<'_> {
    #[inline]
    pub fn new(umem_config: &UmemOptions) -> Result<Self, XdpError> {
        Ok(Self {
            mmap: Mmap::new(
                -1,
                0,
                umem_config.chunk_count * umem_config.chunk_size as usize,
                Protection::READ | Protection::WRITE,
                MapFlags::PRIVATE | MapFlags::ANONYMOUS | MapFlags::NORESERVE,
            )?,
            chunk_size: umem_config.chunk_size,
            headroom: umem_config.headroom,
            flags: umem_config.flags,
            tx_metadata_len: size_of::<xsk_tx_metadata>() as _,
        })
    }

    #[inline]
    pub fn reset_flags(&mut self) {
        self.flags = 0;
    }
}

#[inline]
fn get_noubcheck(index: usize, slice: *const Umem) -> *const [u8] {
    slice_from_raw_parts(
        unsafe { (&*slice).mmap.area.add(index).as_ptr() },
        unsafe { &*slice }.mmap.len as usize - index,
    )
}

#[inline]
fn get_noubcheck_mut(index: usize, slice: *mut Umem) -> *mut [u8] {
    slice_from_raw_parts_mut(
        unsafe { (&*slice).mmap.area.add(index).as_ptr() },
        unsafe { &*slice }.mmap.len as usize - index,
    )
}

unsafe impl<'a> SliceIndex<Umem<'a>> for RangeFrom<usize> {
    type Output = [u8];

    #[inline]
    fn get(self, slice: &Umem<'a>) -> Option<&'a [u8]> {
        if self.start > slice.mmap.len as usize {
            return None;
        }

        Some(unsafe { &*get_noubcheck(self.start, slice as *const _) })
    }

    #[inline]
    fn get_mut(self, slice: &mut Umem<'a>) -> Option<&'a mut [u8]> {
        if self.start < slice.mmap.len as usize {
            Some(unsafe { &mut *get_noubcheck_mut(self.start, slice as *mut _) })
        } else {
            None
        }
    }

    #[inline]
    unsafe fn get_unchecked(self, slice: *const Umem<'a>) -> *const [u8] {
        unsafe {
            core::hint::assert_unchecked(self.start < (&*slice).mmap.len as usize);
        }

        get_noubcheck(self.start, slice)
    }

    #[inline]
    unsafe fn get_unchecked_mut(self, slice: *mut Umem<'a>) -> *mut [u8] {
        unsafe {
            core::hint::assert_unchecked(self.start < (&*slice).mmap.len as usize);
        }

        get_noubcheck_mut(self.start, slice)
    }

    #[inline]
    fn index(self, slice: &Umem<'a>) -> &'a [u8] {
        if self.start < slice.mmap.len as usize {
            unsafe { &*get_noubcheck(self.start, slice as *const _) }
        } else {
            panic!("out of bounds")
        }
    }

    #[inline]
    fn index_mut(self, slice: &mut Umem<'a>) -> &'a mut [u8] {
        if self.start < slice.mmap.len as usize {
            unsafe { &mut *get_noubcheck_mut(self.start, slice as *mut _) }
        } else {
            panic!("out of bounds")
        }
    }
}

impl Index<RangeFrom<usize>> for Umem<'_> {
    type Output = [u8];

    #[inline]
    fn index(&self, index: RangeFrom<usize>) -> &[u8] {
        index.index(self)
    }
}

impl IndexMut<RangeFrom<usize>> for Umem<'_> {
    #[inline]
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut [u8] {
        index.index_mut(self)
    }
}
