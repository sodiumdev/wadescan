use std::{net::Ipv4Addr, time::Duration};

use flume::Receiver;
use log::{debug, info, trace};
use mongodb::{bson::Document, Collection};
use perfect_rand::PerfectRng;

use crate::{
    configfile::ScannerConfig,
    mode::{ModePicker, ScanMode},
    range::{Ipv4Ranges, StaticScanRanges},
    sender::SynSender,
    shared::ServerInfo,
};

pub struct Scanner<'a> {
    seed: u64,
    excludes: Ipv4Ranges,

    mode_picker: ModePicker,
    mode: ScanMode,

    sender: SynSender<'a>,

    collection: Collection<Document>,
    server_receiver: Receiver<ServerInfo>,

    settling_delay: Duration,
    packet_count: u64,
}

impl<'a> Scanner<'a> {
    #[inline]
    pub fn new(
        collection: Collection<Document>,
        seed: u64,
        excludes: Ipv4Ranges,
        sender: SynSender<'a>,
        server_receiver: Receiver<ServerInfo>,
        config: &ScannerConfig,
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

            settling_delay: config.settling_delay,
            packet_count: config.target.pps * config.target.r#for,
        }
    }

    #[inline]
    pub async fn tick(&mut self) {
        info!("scanning with mode {:?}", self.mode);

        let ranges =
            StaticScanRanges::from_excluding(self.mode.ranges(&self.collection), &self.excludes);

        let packet_count = u64::min(ranges.count as u64, self.packet_count);

        info!("spewing {packet_count} packets");

        let rng = PerfectRng::new(ranges.count as u64, self.seed, 3);
        for n in 0..packet_count {
            let index = rng.shuffle(n) as usize;
            let (ip, port) = ranges.index(index);

            self.sender.send_syn(&ip, port, self.seed);
        }

        info!(
            "finished spewing, waiting {} seconds to settle down connections",
            self.settling_delay.as_secs()
        );

        tokio::time::sleep(self.settling_delay).await;

        let found = self.server_receiver.len(); // TODO: store this to the database alongside the server info
        info!("found {found} servers in this scan");

        while let Ok(server_info) = self.server_receiver.try_recv() {
            // all this mpsc channel stuff is to get the found servers from the receiver thread to the main (scanner) thread
            // TODO: store the server info to the database from here and update the mode count (perhaps also store which mode the server was found in with all the info, we can aggregate that info later to find which mode with which port finds more servers)
            debug!("{server_info:?}");
        }

        self.mode = self.mode_picker.pick();
    }
}
