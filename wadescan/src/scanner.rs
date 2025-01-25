use std::time::Duration;

use anyhow::Context;
use flume::Receiver;
use log::info;
use mongodb::{
    Collection,
    bson::{DateTime, Document, doc},
    options::{UpdateOneModel, WriteModel},
};
use perfect_rand::PerfectRng;

use crate::{
    mode,
    range::{Ipv4Ranges, StaticScanRanges},
    sender::SynSender,
    shared::{ServerInfo, SharedData},
};

pub struct Scanner<'a> {
    shared_data: SharedData,

    seed: u64,
    excludes: Ipv4Ranges,

    sender: SynSender<'a>,

    servers_collection: Collection<Document>,
    modes_collection: Collection<Document>,

    confidence: f64,
    settling_delay: Duration,
    receiver: Receiver<ServerInfo>,

    packet_count: u64,
}

impl<'a> Scanner<'a> {
    #[inline]
    pub fn new(
        servers_collection: Collection<Document>,
        modes_collection: Collection<Document>,
        seed: u64,
        excludes: Ipv4Ranges,
        sender: SynSender<'a>,
        shared_data: SharedData,
        settling_delay: Duration,
        receiver: Receiver<ServerInfo>,
        packet_count: u64,
        confidence: f64,
    ) -> Self {
        Self {
            shared_data,

            seed,
            excludes,

            sender,

            servers_collection,
            modes_collection,

            confidence,
            settling_delay,
            receiver,

            packet_count,
        }
    }

    #[inline]
    pub async fn tick(&mut self) -> anyhow::Result<()> {
        let mode = mode::pick(self.confidence, &self.modes_collection).await?;
        let current_mode = mode.clone();

        let ranges = StaticScanRanges::from_excluding(
            mode.ranges(&self.servers_collection).await?,
            &self.excludes,
        );
        let packet_count = u64::min(ranges.count as u64, self.packet_count);
        info!("spewing {packet_count} packets with mode {mode:?}");

        self.shared_data.set_mode(mode);

        let rng = PerfectRng::new(ranges.count as u64, self.seed, 3);
        for n in 0..packet_count {
            let index = rng.shuffle(n) as usize;
            let (ip, port) = ranges.index(index);

            self.sender.send_syn(&ip, port, self.seed);
        }

        info!(
            "done spewing, waiting {} seconds to settle down connections",
            self.settling_delay.as_secs()
        );

        tokio::time::sleep(self.settling_delay).await;

        info!("done waiting, adapting to and processing results");
        let found = self.receiver.len();
        let mut models = Vec::with_capacity(found);
        while let Ok(server) = self.receiver.try_recv() {
            models.push(
                WriteModel::UpdateOne(
                    UpdateOneModel::builder()
                        .namespace(self.servers_collection.namespace())
                        .filter(doc! { "ip": server.ip.to_bits() as i64, "port": server.port as i32 })
                        .update(doc! { "$push": {
                            "pings": { "at": DateTime::now(), "by": &current_mode, "response": server.response }
                        } })
                        .upsert(true)
                        .build()
                )
            );
        }

        let not_found = packet_count as i64 - found as i64;

        self.modes_collection
            .update_one(
                doc! {
                    "mode": current_mode
                },
                doc! {
                    "$set": {
                        "timestamp": DateTime::now(),
                    },
                    "$inc": {
                        "alpha": found as i64,
                        "beta": not_found
                    }
                },
            )
            .upsert(true)
            .await?;

        self.servers_collection
            .client()
            .bulk_write(models)
            .await
            .context("bulk-writing data")?;

        Ok(())
    }
}
