use serde::Deserialize;
use std::fs;
use std::time::Duration;

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
    pub collection_name: String
}

#[derive(Deserialize)]
pub struct PingConfig {
    pub address: String,
    pub port: u16,
    pub protocol_version: i32
}

#[derive(Deserialize)]
pub struct ScannerConfig {
    pub interface_name: String
}

#[derive(Deserialize)]
pub struct PurgerConfig {
    pub interval: Duration,
    pub timeout: Duration
}

#[derive(Deserialize)]
pub struct PrinterConfig {
    pub interval: Duration
}

#[derive(Deserialize)]
pub struct SenderConfig {
    pub threads: usize
}

pub fn parse_file(input: &str) -> Option<Configfile> {
    let input = fs::read_to_string(input).ok()?;

    parse(&input)
}

fn parse(input: &str) -> Option<Configfile> {
    toml::from_str(input).ok()
}
