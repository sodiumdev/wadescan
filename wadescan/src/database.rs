use anyhow::{bail, Context};
use flume::Receiver;
use log::debug;
use mongodb::{bson::Document, Collection};

use crate::shared::ServerInfo;

pub struct Database {
    collection: Collection<Document>,
    receiver: Receiver<ServerInfo>,
}

impl Database {
    #[inline]
    pub fn new(collection: Collection<Document>, receiver: Receiver<ServerInfo>) -> Database {
        Self {
            collection,
            receiver,
        }
    }

    #[inline]
    pub async fn tick(&self) -> anyhow::Result<()> {
        let Ok(server_info) = self.receiver.recv_async().await else {
            bail!("channel is dropped, scanner panicked?")
        };

        let ip = server_info.ip;
        let port = server_info.port;

        self.collection
            .insert_one(Document::from(server_info))
            .await
            .context("failed to store response in database")?;

        debug!("inserting {}:{} into database", ip, port);

        Ok(())
    }
}
