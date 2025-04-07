use std::net::Ipv4Addr;

use mongodb::bson::{Bson, DateTime};

pub const FRAME_SIZE: u32 = 1 << 12;

#[derive(Debug)]
pub struct ServerInfo {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub found_at: DateTime,
    pub response: Bson,
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
