use log::info;
use mongodb::{bson::Document, Collection};
use perfect_rand::PerfectRng;

use crate::{
    mode,
    range::{Ipv4Ranges, StaticScanRanges},
    sender::SynSender,
    shared::SharedData,
};

pub struct Scanner<'a> {
    shared_data: SharedData,

    seed: u64,
    excludes: Ipv4Ranges,

    sender: SynSender<'a>,

    collection: Collection<Document>,

    packet_count: u64,
}

impl<'a> Scanner<'a> {
    #[inline]
    pub fn new(
        collection: Collection<Document>,
        seed: u64,
        excludes: Ipv4Ranges,
        sender: SynSender<'a>,
        shared_data: SharedData,
        packet_count: u64,
    ) -> Self {
        Self {
            shared_data,

            seed,
            excludes,

            sender,

            collection,

            packet_count,
        }
    }

    #[inline]
    pub async fn tick(&mut self) {
        let mode = mode::pick(&self.collection);
        info!("scanning with mode {:?}", mode);

        let ranges =
            StaticScanRanges::from_excluding(mode.ranges(&self.collection), &self.excludes);
        let packet_count = u64::min(ranges.count as u64, self.packet_count);

        self.shared_data.set_mode(mode);

        info!("spewing {packet_count} packets");

        let rng = PerfectRng::new(ranges.count as u64, self.seed, 3);
        for n in 0..packet_count {
            let index = rng.shuffle(n) as usize;
            let (ip, port) = ranges.index(index);

            self.sender.send_syn(&ip, port, self.seed);
        }

        info!("done spewing");
    }
}
