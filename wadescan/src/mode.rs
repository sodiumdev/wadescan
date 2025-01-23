// thanks mat

use std::{net::Ipv4Addr, str::FromStr};

use mongodb::{
    bson::{Bson, Document},
    Collection,
};
use serde::{Deserialize, Serialize};

use crate::range::ScanRange;

macro_rules! scan_mode {
    ($($variant:ident),*) => {
        #[repr(u8)]
        #[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
        pub enum ScanMode {
            $($variant),*
        }

        impl ScanMode {
            #[inline]
            pub const fn name(&self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant)),*
                }
            }
        }

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
    Slash0FewPorts,
    Slash0FilteredByAsn,
    Slash0SomeFilteredByAsn,
    Slash0FilteredBySlash24,
    Slash0FilteredBySlash2430d,
    Slash0FilteredBySlash24New,
    Slash0FilteredBySlash24Top128PortsUniform,
    Slash0FilteredBySlash24Top1024PortsUniform,
    Slash0FilteredBySlash24TopPortsWeighted,
    Slash0,
    Slash24SomePorts,
    Slash24AllPortsNew,
    Slash24AllPorts,
    Slash24,
    Slash24FewPorts,
    Slash24FewPortsNew,
    Slash24New,
    Slash32AllPorts,
    Slash32AllPorts365d,
    Slash32AllPortsNew,
    Slash32RangePorts,
    Slash32RangePortsNew
);

impl Into<Bson> for ScanMode {
    fn into(self) -> Bson {
        Bson::String(self.name().to_string())
    }
}

impl ScanMode {
    #[inline]
    pub fn ranges(&self, collection: &Collection<Document>) -> Vec<ScanRange> {
        match self {
            ScanMode::Slash0FewPorts => slash0_few_ports(collection),
            ScanMode::Slash0FilteredByAsn => slash0_asn(collection),
            ScanMode::Slash0SomeFilteredByAsn => slash0_some_asn(collection),
            ScanMode::Slash0FilteredBySlash24 => slash0_slash24(collection),
            ScanMode::Slash0FilteredBySlash2430d => slash0_slash24_30d(collection),
            ScanMode::Slash0FilteredBySlash24New => slash0_slash24_new(collection),
            ScanMode::Slash0FilteredBySlash24Top128PortsUniform => {
                slash0_slash24_top128(collection)
            }
            ScanMode::Slash0FilteredBySlash24Top1024PortsUniform => {
                slash0_slash24_top1024(collection)
            }
            ScanMode::Slash0FilteredBySlash24TopPortsWeighted => {
                slash0_slash24_top_weighted(collection)
            }
            ScanMode::Slash0 => slash0(collection),
            ScanMode::Slash24SomePorts => slash24_some_ports(collection),
            ScanMode::Slash24AllPortsNew => slash24_all_ports_new(collection),
            ScanMode::Slash24AllPorts => slash24_all_ports(collection),
            ScanMode::Slash24 => slash24(collection),
            ScanMode::Slash24FewPorts => slash24_few_ports(collection),
            ScanMode::Slash24FewPortsNew => slash24_few_ports_new(collection),
            ScanMode::Slash24New => slash24_new(collection),
            ScanMode::Slash32AllPorts => slash32_all_ports(collection),
            ScanMode::Slash32AllPorts365d => slash32_all_ports_365d(collection),
            ScanMode::Slash32AllPortsNew => slash32_all_ports_new(collection),
            ScanMode::Slash32RangePorts => slash32_range_ports(collection),
            ScanMode::Slash32RangePortsNew => slash32_range_ports_new(collection),
        }
    }
}

#[inline(always)]
fn slash0_few_ports(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0_asn(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0_some_asn(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0_slash24(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0_slash24_30d(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0_slash24_new(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0_slash24_top128(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0_slash24_top1024(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0_ranges(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0_slash24_top_weighted(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash0(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash24_some_ports(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash24_all_ports_new(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash24_all_ports(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash24(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash24_few_ports(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash24_few_ports_new(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash24_new(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash32_all_ports(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash32_all_ports_365d(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash32_all_ports_new(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash32_range_ports(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline(always)]
fn slash32_range_ports_new(_collection: &Collection<Document>) -> Vec<ScanRange> {
    vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]
}

#[inline]
pub fn pick(collection: &Collection<Document>) -> ScanMode {
    ScanMode::Slash0
}
