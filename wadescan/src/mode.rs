// thanks mat

use std::net::Ipv4Addr;
use std::str::FromStr;
use mongodb::bson::Document;
use mongodb::Collection;
use rand::distr::{Distribution, WeightedIndex};
use rayon::prelude::*;
use rustc_hash::{FxHashMap};
use serde::{Deserialize, Serialize};
use crate::range::ScanRange;

macro_rules! scan_mode {
    ($($variant:ident),*) => {
        #[repr(u8)]
        #[derive(Hash, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
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
    Slash0FilteredByAsnButLess,
    Slash0FilteredBySlash24,
    Slash0FilteredBySlash2430d,
    Slash0FilteredBySlash24New,
    Slash0FilteredBySlash24Top128PortsUniform,
    Slash0FilteredBySlash24Top1024PortsUniform,
    Slash0FilteredBySlash24TopPortsWeighted,
    Slash0,
    Slash24AllPortsButLess,
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

impl ScanMode {
    #[inline]
    pub fn ranges(&self, collection: &Collection<Document>) -> Vec<ScanRange> {
        match self {
            ScanMode::Slash0FewPorts => unimplemented!(),
            ScanMode::Slash0FilteredByAsn => unimplemented!(),
            ScanMode::Slash0FilteredByAsnButLess => unimplemented!(),
            ScanMode::Slash0FilteredBySlash24 => unimplemented!(),
            ScanMode::Slash0FilteredBySlash2430d => unimplemented!(),
            ScanMode::Slash0FilteredBySlash24New => unimplemented!(),
            ScanMode::Slash0FilteredBySlash24Top128PortsUniform => unimplemented!(),
            ScanMode::Slash0FilteredBySlash24Top1024PortsUniform => unimplemented!(),
            ScanMode::Slash0FilteredBySlash24TopPortsWeighted => unimplemented!(),
            ScanMode::Slash0 => vec![ScanRange::single_port(
                Ipv4Addr::new(0, 0, 0, 0),
                Ipv4Addr::new(255, 255, 255, 255),
                25565,
            )],
            ScanMode::Slash24AllPortsButLess => unimplemented!(),
            ScanMode::Slash24AllPortsNew => unimplemented!(),
            ScanMode::Slash24AllPorts => unimplemented!(),
            ScanMode::Slash24 => unimplemented!(),
            ScanMode::Slash24FewPorts => unimplemented!(),
            ScanMode::Slash24FewPortsNew => unimplemented!(),
            ScanMode::Slash24New => unimplemented!(),
            ScanMode::Slash32AllPorts => unimplemented!(),
            ScanMode::Slash32AllPorts365d => unimplemented!(),
            ScanMode::Slash32AllPortsNew => unimplemented!(),
            ScanMode::Slash32RangePorts => unimplemented!(),
            ScanMode::Slash32RangePortsNew => unimplemented!()
        }
    }
}

pub const DEFAULT_FOUND: usize = 1_000_000;

#[derive(Default, Serialize, Deserialize)]
pub struct ModePicker {
    modes: FxHashMap<ScanMode, usize>,
}

impl ModePicker {
    #[inline]
    pub fn pick(&self) -> ScanMode {
        if self.modes.values().all(|&count| count == 0 || count == DEFAULT_FOUND) {
            return ScanMode::Slash0;
        }

        let modes: Vec<_> = self.modes.iter().collect();
        let dist = WeightedIndex::new(
            modes
                .par_iter()
                .map(|(_, &count)| (count * count) + 1)
                .collect::<Vec<_>>(),
        ).unwrap();

        *modes[dist.sample(&mut rand::rng())].0
    }

    #[inline]
    pub fn increment(&mut self, mode: ScanMode, score: usize) {
        self.modes.insert(mode, score);
    }
}
