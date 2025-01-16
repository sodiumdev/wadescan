use std::sync::Arc;
use mongodb::bson::Document;
use mongodb::Collection;
use rayon::iter::ParallelIterator;
use perfect_rand::PerfectRng;
use pnet_packet::tcp::TcpFlags;
use rayon::iter::IntoParallelIterator;
use crate::mode::{ModePicker, ScanMode};
use crate::{checksum, Packet};
use crate::range::{Ipv4Ranges, ScanRanges};
use crate::sender::PacketSender;

pub struct Scanner<'a> {
    seed: u64,
    excludes: Ipv4Ranges,

    mode_picker: ModePicker,
    mode: ScanMode,

    sender: Arc<PacketSender<'a>>,

    collection: Collection<Document>
}

impl<'a> Scanner<'a> {
    #[inline]
    pub fn new(collection: Collection<Document>, seed: u64, excludes: Ipv4Ranges, sender: Arc<PacketSender<'a>>) -> Self {
        let mode_picker = ModePicker::default();
        let mode = mode_picker.pick();

        Self {
            seed,
            excludes,

            mode_picker,
            mode,

            sender,
            
            collection
        }
    }

    #[inline]
    pub fn tick(&mut self) {
        let ranges = ScanRanges::from_except(
            self.mode.ranges(&self.collection),
            &self.excludes,
        ).into_static();

        let rng = PerfectRng::new(ranges.count as u64, self.seed, 3);
        let packet_count = u64::min(
            ranges.count as u64,
            1_000_000 * 60 /* 1000 KPPS for 60 seconds */
        );

        (0..packet_count).into_par_iter().for_each(|n| {
            let shuffled_index = rng.shuffle(n);
            let dest = ranges.index(shuffled_index as usize);

            let ip = dest.0;
            let port = dest.1;

            _ = self.sender.send(Packet {
                ty: TcpFlags::SYN,
                ip,
                port,
                seq: checksum::cookie(ip, port, self.seed),
                ack: 0,
                ping: false
            });
        });

        self.mode = self.mode_picker.pick();
    }
}
