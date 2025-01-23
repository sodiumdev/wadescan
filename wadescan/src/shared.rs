use std::{cell::UnsafeCell, net::Ipv4Addr, ops::Deref, sync::Arc};

use mongodb::{
    bson,
    bson::{doc, DateTime, Document},
};

use crate::{mode::ScanMode, ping::Response};

pub const FRAME_SIZE: u32 = 1 << 12;

#[derive(Debug)]
pub struct ServerInfo {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub found_at: DateTime,
    pub found_by: ScanMode,
    pub response: Response,
}

impl From<ServerInfo> for Document {
    fn from(value: ServerInfo) -> Self {
        doc! {
            "ip": value.ip.to_bits(),
            "port": value.port as u32,
            "found_at": value.found_at,
            "found_by": value.found_by,
            "response": bson::to_bson(&value.response).unwrap()
        }
    }
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
