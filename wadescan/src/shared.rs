use std::{cell::UnsafeCell, net::Ipv4Addr, ops::Deref, sync::Arc};

use mongodb::bson::{Bson, DateTime};

use crate::mode::ScanMode;

pub const FRAME_SIZE: u32 = 1 << 12;

#[derive(Debug)]
pub struct ServerInfo {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub found_at: DateTime,
    pub found_by: ScanMode,
    pub response: Bson,
}

#[repr(transparent)]
#[derive(Default, Debug, Clone)]
pub struct SharedData {
    inner: Arc<InnerSharedData>,
}

impl Deref for SharedData {
    type Target = InnerSharedData;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Default, Debug)]
pub struct InnerSharedData {
    // when the mode goes from None to Some(_), the scanner has started
    mode: UnsafeCell<Option<ScanMode>>,
}

unsafe impl Send for InnerSharedData {}
unsafe impl Sync for InnerSharedData {}

impl InnerSharedData {
    #[inline(always)]
    pub fn get_mode(&self) -> &Option<ScanMode> {
        unsafe { &*self.mode.get() }
    }

    // should be only called by the scanner
    #[inline(always)]
    pub fn set_mode(&self, mode: ScanMode) {
        unsafe { *self.mode.get() = Some(mode) }
    }
}

pub trait BsonExt {
    fn as_int(&self) -> Option<i64>;
}

impl BsonExt for Bson {
    #[inline]
    fn as_int(&self) -> Option<i64> {
        match *self {
            Bson::Int32(i) => Some(i as i64),
            Bson::Int64(i) => Some(i),
            _ => None,
        }
    }
}
