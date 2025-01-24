use anyhow::{bail, Context};
use flume::Receiver;
use log::{debug, error, info};
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

        match self
            .collection
            .insert_one(server_info.into_document())
            .await
        {
            Ok(_) => info!("inserted {}:{} into database", ip, port),
            Err(err) => error!("error while inserting into database: {}", err),
        }

        Ok(())
    }
}
