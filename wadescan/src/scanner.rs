use std::time::Duration;

use flume::Receiver;
use mongodb::{bson::Document, Collection};
use perfect_rand::PerfectRng;

use crate::{
    mode::{ModePicker, ScanMode},
    range::{Ipv4Ranges, StaticScanRanges},
    sender::PacketSender,
    shared::ServerInfo,
};

pub struct Scanner<'a> {
    seed: u64,
    excludes: Ipv4Ranges,

    mode_picker: ModePicker,
    mode: ScanMode,

    sender: PacketSender<'a>,

    collection: Collection<Document>,
    server_receiver: Receiver<ServerInfo>,

    tick_interval: Duration,
}

impl<'a> Scanner<'a> {
    #[inline]
    pub fn new(
        collection: Collection<Document>,
        seed: u64,
        excludes: Ipv4Ranges,
        sender: PacketSender<'a>,
        server_receiver: Receiver<ServerInfo>,
        tick_interval: Duration,
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
            server_receiver,

            tick_interval,
        }
    }

    #[inline]
    pub async fn tick(&mut self) {
        let ranges =
            StaticScanRanges::from_excluding(self.mode.ranges(&self.collection), &self.excludes);

        let packet_count = u64::min(
            ranges.count as u64,
            1_000_000 * 60, // 1000 KPPS for 60 seconds
        );

        let rng = PerfectRng::new(ranges.count as u64, self.seed, 3);
        for n in 0..packet_count {
            let index = rng.shuffle(n) as usize;
            let (ip, port) = ranges.index(index);

            self.sender.send_syn(&ip, port, self.seed);
        }

        tokio::time::sleep(self.tick_interval).await;

        let found = self.server_receiver.len(); // TODO: store this to the database alongside the server info
        while let Ok(server_info) = self.server_receiver.try_recv() {
            // all this mpsc channel stuff is to get the found servers from the receiver thread to the main (sender) thread
            // TODO: store the server info to the database from here and update the mode count (perhaps also store which mode the server was found in with all the info, we can aggregate that info later to find which mode with which port finds more servers)
            println!("{server_info:?}");
        }

        self.mode = self.mode_picker.pick();
    }
}
