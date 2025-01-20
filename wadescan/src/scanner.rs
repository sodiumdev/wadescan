use mongodb::{bson::Document, Collection};
use perfect_rand::PerfectRng;

use crate::{
    mode::{ModePicker, ScanMode},
    range::{Ipv4Ranges, ScanRanges},
    sender::PacketSender,
};

pub struct Scanner<'a> {
    seed: u64,
    excludes: Ipv4Ranges,

    mode_picker: ModePicker,
    mode: ScanMode,

    sender: PacketSender<'a>,

    collection: Collection<Document>,
}

impl<'a> Scanner<'a> {
    #[inline]
    pub fn new(
        collection: Collection<Document>,
        seed: u64,
        excludes: Ipv4Ranges,
        sender: PacketSender<'a>,
    ) -> Self {
        let mode_picker = ModePicker::default();
        let mode = mode_picker.pick();

        Self {
            seed,
            excludes,

            mode_picker,
            mode,

            sender,

            collection,
        }
    }

    #[inline]
    pub fn tick(&mut self) {
        let ranges = ScanRanges::from_excluding(self.mode.ranges(&self.collection), &self.excludes)
            .into_static();

        let rng = PerfectRng::new(ranges.count as u64, self.seed, 3);
        for n in 0..ranges.count {
            let index = rng.shuffle(n as u64) as usize;
            let (ip, port) = ranges.index(index);

            self.sender.send_syn(&ip, port, self.seed);
        }

        self.mode = self.mode_picker.pick();
    }
}
