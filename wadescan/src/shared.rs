use std::net::Ipv4Addr;

use crate::ping::Response;

pub const FRAME_SIZE: u32 = 1 << 12;

#[derive(Debug)]
pub struct ServerInfo {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub response: Response,
}
