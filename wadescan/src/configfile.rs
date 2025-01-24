use std::{fs, num::NonZeroU32, time::Duration};

use anyhow::Context;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};

#[derive(Deserialize)]
pub struct Configfile {
    pub database: DatabaseConfig,
    pub ping: PingConfig,
    pub scanner: ScannerConfig,
    pub purger: PurgerConfig,
    pub printer: PrinterConfig,
    pub sender: SenderConfig,
}

#[derive(Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub name: String,
    pub collection_name: String,
    pub threads: usize,
}

#[derive(Deserialize)]
pub struct PingConfig {
    pub address: String,
    pub port: u16,
    pub protocol_version: i32,
}

#[serde_as]
#[derive(Deserialize)]
pub struct ScannerConfig {
    #[serde_as(as = "DurationSeconds<u64>")]
    pub settling_delay: Duration,

    pub target: ScannerTarget,
}

#[derive(Deserialize)]
pub struct ScannerTarget {
    pub pps: u64,
    pub r#for: u64,
}

impl From<ScannerTarget> for u64 {
    #[inline(always)]
    fn from(value: ScannerTarget) -> Self {
        value.pps * value.r#for
    }
}

#[serde_as]
#[derive(Deserialize)]
pub struct PurgerConfig {
    #[serde_as(as = "DurationSeconds<u64>")]
    pub interval: Duration,

    #[serde_as(as = "DurationSeconds<u64>")]
    pub timeout: Duration,
}

#[serde_as]
#[derive(Deserialize)]
pub struct PrinterConfig {
    #[serde_as(as = "DurationSeconds<u64>")]
    pub interval: Duration,
}

#[derive(Deserialize)]
pub struct SenderConfig {
    pub interface_name: String,
    pub umem_size: usize,
    pub complete_size: u32,
    pub tx_size: NonZeroU32,
}

#[inline]
pub fn parse_file(input: &str) -> anyhow::Result<Configfile> {
    let input = fs::read_to_string(input).context(format!(
        "couldn't find {input}, maybe you forgot to rename config.example.toml?"
    ))?;

    toml::from_str(&input).context("failed to parse TOML")
}
