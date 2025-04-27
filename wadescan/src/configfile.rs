use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize, Deserialize, Debug)]
pub struct Configfile {
    pub scanner: ScannerConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScannerConfig {
    pub source_port: u16,
    pub xdp: XdpConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct XdpConfig {
    pub umem: UmemConfig,
    pub ring: RingConfig,
    pub socket: SocketConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RingConfig {
    pub fill: u32,
    pub completion: u32,
    pub rx: u32,
    pub tx: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SocketConfig {
    pub busy_poll_budget: i32,
    pub queue_ids: Box<[u32]>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UmemConfig {
    pub chunk_count: usize,
    pub chunk_size: ChunkSize,
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Copy, Clone)]
#[repr(u32)]
pub enum ChunkSize {
    TwoK = 2048,
    FourK = 4096,
}

pub fn parse(filename: &str) -> anyhow::Result<Configfile> {
    let content = std::fs::read_to_string(filename).context("reading file")?;

    toml::from_str(&content).context("deserializing file")
}
