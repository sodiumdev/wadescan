// thanks mat

use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};

use anyhow::{Context, anyhow, bail};
use futures::TryStreamExt;
use mongodb::{
    Collection,
    bson::{Bson, Document, doc},
};
use serde::{Deserialize, Serialize};
use statrs::distribution::{Beta, ContinuousCDF};

use crate::{range::ScanRange, shared::BsonExt};

macro_rules! scan_mode {
    ($($variant:ident),*) => {
        #[repr(u8)]
        #[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
        pub enum ScanMode {
            $($variant),*
        }

        #[inline(always)]
        const fn _count(_a: &str) -> usize {
            1
        }

        impl ScanMode {
            #[inline]
            pub const fn name(&self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant)),*
                }
            }
        }

        static MODES: &[ScanMode] = &[
            $(ScanMode::$variant),*
        ];

        impl FromStr for ScanMode {
            type Err = ();

            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s {
                    $(stringify!($variant) => Self::$variant),*,

                    _ => return Err(())
                })
            }
        }
    };
}

scan_mode!(
    Slash0,
    Slash0FewPorts,
    Slash0FilteredByAsn,
    Slash0SomeFilteredByAsn,
    Slash0FilteredBySlash24,
    Slash0FilteredBySlash24Top128PortsUniform,
    Slash0FilteredBySlash24Top1024PortsUniform,
    Slash0FilteredBySlash24TopPortsWeighted,
    Slash16,
    Slash16AllPorts,
    Slash16RangePorts,
    Slash24,
    Slash24AllPorts,
    Slash24RangePorts,
    Slash32AllPorts,
    Slash32RangePorts
);

impl From<ScanMode> for Bson {
    fn from(value: ScanMode) -> Self {
        Self::String(value.name().to_string())
    }
}

impl ScanMode {
    #[inline]
    pub async fn ranges(
        &self,
        collection: &Collection<Document>,
    ) -> anyhow::Result<Vec<ScanRange>> {
        match self {
            ScanMode::Slash0FewPorts => slash0_few_ports(collection).await,
            ScanMode::Slash0FilteredByAsn => slash0_asn(collection).await,
            ScanMode::Slash0SomeFilteredByAsn => slash0_some_asn(collection).await,
            ScanMode::Slash0FilteredBySlash24 => slash0_slash24(collection).await,
            ScanMode::Slash0FilteredBySlash24Top128PortsUniform => {
                slash0_slash24_top128(collection).await
            }
            ScanMode::Slash0FilteredBySlash24Top1024PortsUniform => {
                slash0_slash24_top1024(collection).await
            }
            ScanMode::Slash0FilteredBySlash24TopPortsWeighted => {
                slash0_slash24_top_weighted(collection).await
            }
            ScanMode::Slash0 => slash0(collection),
            ScanMode::Slash24AllPorts => slash24_all_ports(collection).await,
            ScanMode::Slash24 => slash24(collection).await,
            ScanMode::Slash24RangePorts => slash24_range(collection).await,
            ScanMode::Slash16 => slash16(collection).await,
            ScanMode::Slash16AllPorts => slash16_all_ports(collection).await,
            ScanMode::Slash16RangePorts => slash16_range(collection).await,
            ScanMode::Slash32AllPorts => slash32_all(collection).await,
            ScanMode::Slash32RangePorts => slash32_range(collection).await,
        }
    }
}

#[inline(always)]
async fn slash0_few_ports(collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    let mut cursor = collection
        .aggregate([
            doc! {
                "$group": {
                    "_id": "$port",
                    "count": { "$sum": 1 }
                }
            },
            doc! {
                "$sort": {
                    "_id": 1,
                    "count": -1
                }
            },
            doc! {
                "$limit": 64
            },
        ])
        .await
        .context("aggregating data")?;

    let mut ranges = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        ranges.push(ScanRange::single_port(
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            doc.get("_id").and_then(|r| r.as_i32()).unwrap() as u16,
        ));
    }

    Ok(ranges)
}

#[inline(always)]
async fn slash0_asn(_collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

#[inline(always)]
async fn slash0_some_asn(_collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

#[inline(always)]
async fn slash0_slash24(_collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

#[inline(always)]
async fn slash0_slash24_top128(
    _collection: &Collection<Document>,
) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

#[inline(always)]
async fn slash0_slash24_top1024(
    _collection: &Collection<Document>,
) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

#[inline(always)]
async fn slash0_ranges(_collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

#[inline(always)]
async fn slash0_slash24_top_weighted(
    _collection: &Collection<Document>,
) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

#[inline(always)]
fn slash0(_collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    Ok(vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )])
}

#[inline(always)]
async fn slash24_all_ports(collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    let mut cursor = collection
        .aggregate([doc! {
            "$group": {
                "_id": { "$floor": { "$divide": ["$ip", 256] } },
            }
        }])
        .await
        .context("aggregating data")?;

    let mut ranges = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        let ip24 = doc.get("_id").and_then(|r| r.as_int()).unwrap() as u32;
        let ip24_a = ((ip24 >> 16) & 0xFF) as u8;
        let ip24_b = ((ip24 >> 8) & 0xFF) as u8;
        let ip24_c = (ip24 & 0xFF) as u8;

        ranges.push(ScanRange {
            addr_start: Ipv4Addr::new(ip24_a, ip24_b, ip24_c, 0),
            addr_end: Ipv4Addr::new(ip24_a, ip24_b, ip24_c, 255),
            port_start: 1024,
            port_end: 65535,
        });
    }

    Ok(ranges)
}

#[inline(always)]
async fn slash24_range(collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    let mut cursor = collection
        .aggregate([
            doc! {
                "$group": {
                    "_id": { "$floor": { "$divide": ["$ip", 256] } },
                    "min_port": { "$min": "$port" },
                    "max_port": { "$max": "$port" }
                }
            },
            doc! {
                "$project": {
                    "_id": 0,
                    "ip": "$_id",
                    "min_port": 1,
                    "max_port": 1,
                }
            },
        ])
        .await
        .context("aggregating data")?;

    let mut ranges = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        let ip24 = doc.get("ip").and_then(|r| r.as_int()).unwrap() as u32;
        let ip24_a = ((ip24 >> 16) & 0xFF) as u8;
        let ip24_b = ((ip24 >> 8) & 0xFF) as u8;
        let ip24_c = (ip24 & 0xFF) as u8;

        ranges.push(ScanRange {
            addr_start: Ipv4Addr::new(ip24_a, ip24_b, ip24_c, 0),
            addr_end: Ipv4Addr::new(ip24_a, ip24_b, ip24_c, 255),
            port_start: doc.get("min_port").and_then(|val| val.as_int()).unwrap() as u16,
            port_end: doc.get("max_port").and_then(|val| val.as_int()).unwrap() as u16,
        });
    }

    Ok(ranges)
}

#[inline(always)]
async fn slash24(collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    let mut cursor = collection
        .aggregate([
            doc! {
                "$group": {
                    "_id": { "$floor": { "$divide": ["$ip", 256] } },
                    "top_ports": {
                        "$push": "$port"
                    }
                }
            },
            doc! {
                "$project": {
                    "_id": 0,
                    "ip": "$_id",
                    "top_ports": { "$slice": ["$top_ports", 64] }
                }
            },
        ])
        .await
        .context("aggregating data")?;

    let mut ranges = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        let ip24 = doc.get("ip").and_then(|r| r.as_int()).unwrap() as u32;
        let ip24_a = ((ip24 >> 16) & 0xFF) as u8;
        let ip24_b = ((ip24 >> 8) & 0xFF) as u8;
        let ip24_c = (ip24 & 0xFF) as u8;

        for port in doc.get_array("top_ports")? {
            ranges.push(ScanRange::single_port(
                Ipv4Addr::new(ip24_a, ip24_b, ip24_c, 0),
                Ipv4Addr::new(ip24_a, ip24_b, ip24_c, 255),
                port.as_int().ok_or(anyhow!("port not int somehow"))? as u16,
            ));
        }
    }

    Ok(ranges)
}

#[inline(always)]
async fn slash16(collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    let mut cursor = collection
        .aggregate([
            doc! {
                "$group": {
                    "_id": { "$floor": { "$divide": ["$ip", 65536] } },
                    "top_ports": {
                        "$push": "$port"
                    }
                }
            },
            doc! {
                "$project": {
                    "_id": 0,
                    "ip": "$_id",
                    "top_ports": { "$slice": ["$top_ports", 64] }
                }
            },
        ])
        .await
        .context("aggregating data")?;

    let mut ranges = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        let ip24 = doc.get("ip").and_then(|r| r.as_int()).unwrap() as u32;
        let ip24_a = ((ip24 >> 8) & 0xFF) as u8;
        let ip24_b = (ip24 & 0xFF) as u8;

        for port in doc.get_array("top_ports")? {
            ranges.push(ScanRange::single_port(
                Ipv4Addr::new(ip24_a, ip24_b, 0, 0),
                Ipv4Addr::new(ip24_a, ip24_b, 255, 255),
                port.as_int().ok_or(anyhow!("port not int somehow"))? as u16,
            ));
        }
    }

    Ok(ranges)
}

#[inline(always)]
async fn slash16_all_ports(collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    let mut cursor = collection
        .aggregate([
            doc! {
                "$group": {
                    "_id": { "$floor": { "$divide": ["$ip", 65536] } },
                }
            },
            doc! {
                "$project": {
                    "_id": 0,
                    "ip": "$_id"
                }
            },
        ])
        .await
        .context("aggregating data")?;

    let mut ranges = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        let ip24 = doc.get("ip").and_then(|r| r.as_int()).unwrap() as u32;
        let ip24_a = ((ip24 >> 8) & 0xFF) as u8;
        let ip24_b = (ip24 & 0xFF) as u8;

        ranges.push(ScanRange {
            addr_start: Ipv4Addr::new(ip24_a, ip24_b, 0, 0),
            addr_end: Ipv4Addr::new(ip24_a, ip24_b, 255, 255),
            port_start: 1024,
            port_end: 65535,
        });
    }

    Ok(ranges)
}

#[inline(always)]
async fn slash16_range(_collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

#[inline(always)]
async fn slash32_range(_collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

#[inline(always)]
async fn slash32_all(_collection: &Collection<Document>) -> anyhow::Result<Vec<ScanRange>> {
    bail!("unimplemented")
}

pub async fn pick(confidence: f64, collection: &Collection<Document>) -> anyhow::Result<ScanMode> {
    let mut cursor = collection.find(doc! {}).await.context("aggregating data")?;

    let mut modes = HashMap::new();
    for mode in MODES {
        modes.insert(mode.clone(), (1, 1));
    }

    while let Some(document) = cursor.try_next().await? {
        let Ok(mode) = ScanMode::from_str(document.get_str("mode")?) else {
            continue;
        };
        let Some(alpha) = document.get("alpha").and_then(|r| r.as_int()) else {
            continue;
        };
        let Some(beta) = document.get("beta").and_then(|r| r.as_int()) else {
            continue;
        };

        modes.insert(mode, (alpha + 1, beta + 1));
    }

    if modes
        .iter()
        .all(|(_, (alpha, beta))| *alpha == 1 && *beta == 1)
    {
        return Ok(ScanMode::Slash0);
    }

    Ok(modes
        .iter()
        .max_by(|(_, (alpha_a, beta_a)), (_, (alpha_b, beta_b))| {
            Beta::new(*alpha_a as f64, *beta_a as f64)
                .unwrap()
                .inverse_cdf(confidence)
                .partial_cmp(
                    &Beta::new(*alpha_b as f64, *beta_b as f64)
                        .unwrap()
                        .inverse_cdf(confidence),
                )
                .unwrap()
        })
        .unwrap()
        .0
        .clone())
}
