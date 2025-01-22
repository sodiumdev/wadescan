use std::{fs, time::Duration};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};

#[derive(Default, Serialize, Deserialize)]
pub struct Configfile {
    pub database: DatabaseConfig,
    pub ping: PingConfig,
    pub scanner: ScannerConfig,
    pub purger: PurgerConfig,
    pub printer: PrinterConfig,
    pub sender: SenderConfig,
}

#[derive(Default, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub name: String,
    pub collection_name: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct PingConfig {
    pub address: String,
    pub port: u16,
    pub protocol_version: i32,
}

#[serde_as]
#[derive(Default, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub interface_name: String,

    #[serde_as(as = "DurationSeconds<u64>")]
    pub tick_interval: Duration,
}

#[serde_as]
#[derive(Default, Serialize, Deserialize)]
pub struct PurgerConfig {
    #[serde_as(as = "DurationSeconds<u64>")]
    pub interval: Duration,

    #[serde_as(as = "DurationSeconds<u64>")]
    pub timeout: Duration,
}

#[serde_as]
#[derive(Default, Serialize, Deserialize)]
pub struct PrinterConfig {
    #[serde_as(as = "DurationSeconds<u64>")]
    pub interval: Duration,
}

#[derive(Default, Serialize, Deserialize)]
pub struct SenderConfig {
    pub umem_size: u8,
    pub complete_size: u8,
    pub tx_size: u8,
}

#[inline]
pub fn parse_file(input: &str) -> anyhow::Result<Configfile> {
    let input = fs::read_to_string(input).context(format!(
        "couldn't find {input}, maybe you forgot to rename config.example.toml?"
    ))?;

    toml::from_str(&input).context("failed to parse TOML")
}
