use std::net::Ipv4Addr;

use crate::ping::Response;

#[derive(Debug)]
pub struct ServerInfo {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub response: Response,
}

#[derive(Clone)]
pub struct SharedState {}
