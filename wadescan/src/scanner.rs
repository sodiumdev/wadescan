use std::net::Ipv4Addr;

use flume::Receiver;
use perfect_rand::PerfectRng;

use crate::{
    range::{Ipv4Ranges, ScanRange, StaticScanRanges},
    sender::SynSender,
    shared::ServerInfo,
};

pub struct Scanner<'a> {
    seed: u64,
    excludes: Ipv4Ranges,

    sender: SynSender<'a>,
    receiver: Receiver<ServerInfo>,
}

impl<'a> Scanner<'a> {
    #[inline]
    pub fn new(
        seed: u64,
        excludes: Ipv4Ranges,
        sender: SynSender<'a>,
        receiver: Receiver<ServerInfo>,
    ) -> Self {
        Self {
            seed,
            excludes,

            sender,

            receiver,
        }
    }

    #[inline]
    pub async fn tick(&mut self) -> anyhow::Result<()> {
        /*
        So, the strategy here is that the scanner always scans 0.0.0.0/0, but when it finds a server it automatically scans the adjacent ips with ALL strategies.
        The term "adjacent" can change based on the strategy used, i.e. when a slash 32 strategy is used it just scans all ports on the same ip,
        and when a slash 24 strategy is used it just scans all ports (maybe only 25565, thinking of changing that in the future) on a.b.c.0/24

        There also should be a rescan feature which just scans everything in the database again, maybe the adjacent ips too

        Also!!! masscan gets me about 700 kpps, while my scanner gets 550 kpps. my scanner uses af_xdp but in my tests matscan (which uses raw sockets) gets about 300 kpps
        */

        let ranges = StaticScanRanges::from_excluding(
            vec![ScanRange {
                addr_start: Ipv4Addr::new(0, 0, 0, 0),
                addr_end: Ipv4Addr::new(255, 255, 255, 255),
                port_start: 25565,
                port_end: 25565,
            }],
            &self.excludes,
        );

        let rng = PerfectRng::new(ranges.count as u64, self.seed, 3);
        for n in 0..(ranges.count as u64) {
            let index = rng.shuffle(n) as usize;
            let (ip, port) = ranges.index(index);

            self.sender.send_syn(&ip, port, self.seed);
        }

        Ok(())
    }
}
