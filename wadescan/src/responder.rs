use std::{
    net::Ipv4Addr,
    ptr,
    slice::from_raw_parts,
    sync::Arc,
    time::{Duration, Instant},
};

use aya::maps::{MapData, RingBuf};
use dashmap::DashMap;
use flume::Sender;
use log::{debug, info, trace};
use mongodb::{bson::Document, Collection};
use rustc_hash::FxBuildHasher;
use tokio::io::unix::AsyncFd;
use wadescan_common::{PacketHeader, PacketType};

use crate::{
    checksum, ping,
    ping::{PingParseError, RawLatest},
    sender::ResponseSender,
    shared::{ServerInfo, SharedState},
};

pub struct ConnectionState {
    data: Vec<u8>,
    started: Instant,

    remote_seq: u32,
    local_seq: u32,

    fin_sent: bool,
}

pub type ConnectionMap = Arc<DashMap<(Ipv4Addr, u16), ConnectionState, FxBuildHasher>>;

pub struct Responder<'a> {
    collection: Collection<Document>,

    connections: ConnectionMap,
    sender: ResponseSender<'a>,

    fd: AsyncFd<RingBuf<MapData>>,
    seed: u64,

    server_sender: Sender<ServerInfo>,
    ping_data: &'static [u8],
}

#[repr(u8)]
pub enum TickResult {
    Continue,
    Stop,
}

impl<'a> Responder<'a> {
    #[inline]
    pub fn new(
        collection: Collection<Document>,
        connections: ConnectionMap,
        seed: u64,
        ring_buf: RingBuf<MapData>,
        sender: ResponseSender<'a>,
        server_sender: Sender<ServerInfo>,
        ping_data: &'static [u8],
    ) -> Option<Self> {
        let fd = AsyncFd::new(ring_buf).ok()?;

        Some(Self {
            collection,

            connections,
            sender,

            fd,
            seed,

            server_sender,
            ping_data,
        })
    }

    #[inline]
    pub async fn tick(&mut self) -> TickResult {
        let Ok(mut guard) = self.fd.readable_mut().await else {
            return TickResult::Stop;
        };

        let ring_buf = guard.get_inner_mut();

        while let Some(read) = ring_buf.next() {
            let read = read.as_ptr();
            let hdr: *const PacketHeader = read as *const PacketHeader;

            let ip = Ipv4Addr::from(unsafe { (*hdr).ip });
            let ty = unsafe { (*hdr).ty };
            let port = unsafe { (*hdr).port };
            let seq = unsafe { (*hdr).seq };
            let ack = unsafe { (*hdr).ack };

            trace!("received {ty:?} packet from {ip}:{port} with seq:{seq}/ack:{ack}");

            match ty {
                PacketType::SynAck => {
                    let expected = checksum::cookie(&ip, port, self.seed) + 1;
                    if ack != expected {
                        debug!("cookie mismatch for {ip}:{port} at SYN+ACK (expected {expected}, got {ack})");

                        continue;
                    }

                    self.sender.send_ack(&ip, port, ack, seq + 1);
                    self.sender.send_psh(&ip, port, ack, seq + 1);
                }

                PacketType::Ack => {
                    let read = unsafe { read.add(PacketHeader::LEN) };

                    let len = unsafe { ptr::read_unaligned(read.cast::<u16>()) };
                    if len == 0 {
                        debug!("received ACK without data from {ip}:{port}");

                        continue;
                    }

                    debug!("received ACK with {len} bytes from {ip}:{port}");

                    let data = unsafe { from_raw_parts(read.add(size_of::<u16>()), len as usize) };

                    let remote_seq = seq.wrapping_add(len as u32);
                    let ping_response = if let Some(mut conn) =
                        self.connections.get_mut(&(ip, port))
                    {
                        if seq != conn.remote_seq {
                            debug!("got wrong seq number! this is probably because of a retransmission");

                            self.sender.send_ack(&ip, port, ack, conn.remote_seq);

                            continue;
                        }

                        conn.remote_seq = remote_seq;
                        conn.data.extend(data);

                        ping::parse_response(&conn.data)
                    } else {
                        let expected = checksum::cookie(&ip, port, self.seed)
                            .wrapping_add((self.ping_data.len() + 1) as u32);
                        if ack != expected {
                            debug!("cookie mismatch for {ip}:{port} at ACK (expected {expected}, got {ack})");

                            continue;
                        }

                        let response = ping::parse_response(data);
                        match &response {
                            Err(PingParseError::Invalid) => {}

                            _ => {
                                self.connections.insert(
                                    (ip, port),
                                    ConnectionState {
                                        data: data.to_vec(),
                                        remote_seq,
                                        local_seq: ack,
                                        started: Instant::now(),
                                        fin_sent: false,
                                    },
                                );
                            }
                        };

                        response
                    };

                    match ping_response {
                        Ok(data) => {
                            info!("found 1 ({ip}:{port})");

                            if let Ok(mut raw) = serde_json::from_slice::<RawLatest>(&data) {
                                raw.raw_json = data;

                                if let Ok(response) = raw.try_into() {
                                    _ = self.server_sender.try_send(ServerInfo {
                                        ip,
                                        port,
                                        response,
                                    });
                                }
                            }

                            self.sender.send_ack(&ip, port, ack, remote_seq);
                            self.sender.send_fin(&ip, port, ack, remote_seq);
                        }

                        Err(PingParseError::Invalid) => {
                            debug!("invalid response from {ip}:{port}");
                        }

                        Err(PingParseError::Incomplete) => {
                            self.sender.send_ack(&ip, port, ack, remote_seq);
                        }
                    }
                }

                PacketType::Fin => {
                    if let Some(mut conn) = self.connections.get_mut(&(ip, port)) {
                        self.sender.send_ack(&ip, port, conn.local_seq, seq + 1);

                        if !conn.fin_sent {
                            self.sender.send_fin(&ip, port, conn.local_seq, seq + 1);

                            conn.fin_sent = true;
                        }

                        if !conn.data.is_empty() {
                            drop(conn);

                            self.connections.remove(&(ip, port));
                        }
                    } else {
                        self.sender.send_ack(&ip, port, ack, seq + 1);
                    }
                }

                _ => unreachable!(),
            };
        }

        guard.clear_ready();

        TickResult::Continue
    }
}

pub struct Purger {
    connections: ConnectionMap,
    purge_interval: Duration,
    ping_timeout: Duration,
}

impl Purger {
    #[inline]
    pub fn new(
        connections: ConnectionMap,
        purge_interval: Duration,
        ping_timeout: Duration,
    ) -> Self {
        Self {
            connections,
            purge_interval,
            ping_timeout,
        }
    }

    #[inline]
    pub async fn tick(&self) {
        self.connections
            .retain(|_, conn| conn.started.elapsed() <= self.ping_timeout);

        tokio::time::sleep(self.purge_interval).await;
    }
}
