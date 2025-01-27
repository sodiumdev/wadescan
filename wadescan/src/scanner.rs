use std::time::Duration;

use anyhow::Context;
use flume::Receiver;
use log::{info, trace};
use mongodb::{
    Collection,
    bson::{DateTime, Document, doc},
    options::{UpdateOneModel, WriteModel},
};
use perfect_rand::PerfectRng;

use crate::{
    mode::ModePicker,
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

    mode_picker: ModePicker,

    settling_delay: Duration,
    receiver: Receiver<ServerInfo>,

    packet_count: u64,
}

impl<'a> Scanner<'a> {
    #[inline]
    pub fn new(
        servers_collection: Collection<Document>,
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

            mode_picker: ModePicker::load("modes.json", confidence),
            settling_delay,
            receiver,

            packet_count,
        }
    }

    #[inline]
    pub async fn tick(&mut self) -> anyhow::Result<()> {
        trace!("picking mode...");

        let mode = self.mode_picker.pick()?;

        trace!("picked mode {mode:?}, calculating ranges");

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

        info!("done waiting, processing and adapting to results");

        let found = self.receiver.len();
        self.mode_picker
            .found(self.shared_data.get_mode().clone().unwrap(), found);

        self.mode_picker
            .save("modes.json")
            .context("saving modes")?;

        let mut models = Vec::with_capacity(found);
        while let Ok(server) = self.receiver.try_recv() {
            models.push(
                WriteModel::UpdateOne(
                    UpdateOneModel::builder()
                        .namespace(self.servers_collection.namespace())
                        .filter(doc! { "ip": server.ip.to_bits() as i64, "port": server.port as i32 })
                        .update(doc! { "$push": {
                            "pings": { "at": DateTime::now(), "by": self.shared_data.get_mode().clone().unwrap(), "response": server.response }
                        } })
                        .upsert(true)
                        .build()
                )
            );
        }

        self.servers_collection
            .client()
            .bulk_write(models)
            .await
            .context("bulk-writing data")?;

        Ok(())
    }
}
