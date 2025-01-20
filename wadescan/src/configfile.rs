use std::{fs, time::Duration};

use serde::{Deserialize, Serialize};

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

#[derive(Default, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub interface_name: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct PurgerConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

#[derive(Default, Serialize, Deserialize)]
pub struct PrinterConfig {
    pub interval: Duration,
}

#[derive(Default, Serialize, Deserialize)]
pub struct SenderConfig {
    pub umem_size: u8,
    pub complete_size: u8,
    pub tx_size: u8,
}

pub fn parse_file(input: &str) -> Option<Configfile> {
    let input = fs::read_to_string(input).ok()?;

    parse(&input)
}

fn parse(input: &str) -> Option<Configfile> {
    toml::from_str(input).ok()
}
