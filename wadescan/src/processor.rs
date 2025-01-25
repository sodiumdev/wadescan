use anyhow::bail;
use flume::Receiver;
use log::{debug, error, info};
use mongodb::{
    Collection,
    bson::{Document, doc},
};

use crate::shared::ServerInfo;

pub struct Processor {
    collection: Collection<Document>,
    receiver: Receiver<ServerInfo>,
}

impl Processor {
    #[inline]
    pub fn new(collection: Collection<Document>, receiver: Receiver<ServerInfo>) -> Processor {
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

        debug!("trying to insert {}:{}", ip, port);

        match self
            .collection
            .update_one(
                doc! { "ip": ip.to_bits() as i64, "port": port as i32 },
                doc! {
                    "$push": {
                        "pings": {
                            "at": server_info.found_at,
                            "by": server_info.found_by,
                            "response": server_info.response
                        }
                    }
                },
            )
            .upsert(true)
            .await
        {
            Ok(_) => info!("inserted {}:{} into database", ip, port),
            Err(err) => error!("error while inserting into database: {}", err),
        }

        Ok(())
    }
}
