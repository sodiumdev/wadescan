use std::net::Ipv4Addr;
use std::ptr;
use std::slice::from_raw_parts;
use std::sync::Arc;
use std::time::{Duration, Instant};
use aya::maps::{MapData, RingBuf};
use dashmap::DashMap;
use log::debug;
use mongodb::bson::Document;
use mongodb::Collection;
use rustc_hash::FxBuildHasher;
use tokio::io::unix::AsyncFd;
use wadescan_common::{PacketHeader, PacketType};
use crate::{checksum, ping};
use crate::ping::{PingParseError, RawLatest, Response};
use crate::sender::PacketSender;

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
    sender: PacketSender<'a>,

    fd: AsyncFd<RingBuf<MapData>>,
    seed: u64,

    ping_data: &'static [u8],
}

impl<'a> Responder<'a> {
    #[inline]
    pub fn new(collection: Collection<Document>, connections: ConnectionMap, seed: u64, ring_buf: RingBuf<MapData>, sender: PacketSender<'a>, ping_data: &'static [u8]) -> Option<Self> {
        let fd = AsyncFd::new(ring_buf).ok()?;

        Some(Self {
            collection,

            connections,
            sender,

            fd,
            seed,

            ping_data,
        })
    }

    #[inline]
    pub async fn tick(&mut self) -> Option<()> {
        let mut guard = self.fd.readable_mut().await.ok()?;
        let ring_buf = guard.get_inner_mut();

        while let Some(read) = ring_buf.next() {
            let read = read.as_ptr();
            let hdr: *const PacketHeader = read as *const PacketHeader;

            let ip = Ipv4Addr::from(unsafe { (*hdr).ip });

            let port = unsafe { (*hdr).port };
            let seq = unsafe { (*hdr).seq };
            let ack = unsafe { (*hdr).ack };

            match unsafe { (*hdr).ty } {
                PacketType::SynAck => {
                    if ack != checksum::cookie(&ip, port, self.seed) + 1 {
                        debug!("invalid cookie at SYN+ACK");

                        continue
                    }

                    self.sender.send_ack(
                        &ip,
                        port,
                        ack,
                        seq + 1
                    );

                    self.sender.send_psh(
                        &ip,
                        port,
                        ack,
                        seq + 1
                    );
                }

                PacketType::Ack => {
                    let read = unsafe { read.add(PacketHeader::LEN) };

                    let len = unsafe { ptr::read_unaligned(read.cast::<u16>()) };
                    if len == 0 {
                        debug!("received ACK without data");

                        continue
                    }
                    
                    debug!("received ACK with {} bytes", len);

                    let data = unsafe { from_raw_parts(read.add(size_of::<u16>()), len as usize) };

                    let remote_seq = seq.wrapping_add(len as u32);
                    let ping_response = if let Some(mut conn) = self.connections.get_mut(&(ip, port)) {
                        if seq != conn.remote_seq {
                            debug!("got wrong seq number! this is probably because of a retransmission");

                            self.sender.send_ack(
                                &ip,
                                port,
                                ack,
                                conn.remote_seq
                            );

                            continue
                        }

                        conn.remote_seq = remote_seq;
                        conn.data.extend(data);

                        ping::parse_response(&conn.data)
                    } else {
                        if ack != checksum::cookie(&ip, port, self.seed).wrapping_add((self.ping_data.len() + 1) as u32) {
                            debug!("cookie mismatch when reading data from: {}", ip);

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
                            if let Ok(mut response) = serde_json::from_slice::<RawLatest>(&data) {
                                response.raw_json = data;

                                if let Ok(response) = TryInto::<Response>::try_into(response) {
                                    println!("{response:?}");
                                }
                            }

                            self.sender.send_ack(
                                &ip,
                                port,
                                ack,
                                remote_seq
                            );

                            self.sender.send_fin(
                                &ip,
                                port,
                                ack,
                                remote_seq
                            );
                        }
                        
                        Err(PingParseError::Invalid) => {},
                        Err(PingParseError::Incomplete) => {
                            self.sender.send_ack(
                                &ip,
                                port,
                                ack,
                                remote_seq
                            );
                        },
                    }
                }

                PacketType::Fin => {
                    if let Some(mut conn) = self.connections.get_mut(&(ip, port)) {
                        self.sender.send_ack(
                            &ip,
                            port,
                            conn.local_seq,
                            seq + 1
                        );

                        if !conn.fin_sent {
                            self.sender.send_fin(
                                &ip,
                                port,
                                conn.local_seq,
                                seq + 1
                            );

                            conn.fin_sent = true;
                        }

                        if !conn.data.is_empty() {
                            self.connections.remove(&(ip, port));
                        }
                    }

                    self.sender.send_ack(
                        &ip,
                        port,
                        ack,
                        seq + 1
                    );
                }

                _ => unreachable!()
            };
        }

        guard.clear_ready();

        Some(())
    }
}

pub struct Purger {
    connections: ConnectionMap,
    purge_interval: Duration,
    ping_timeout: Duration,
}

impl Purger {
    #[inline]
    pub fn new(connections: ConnectionMap, purge_interval: Duration, ping_timeout: Duration) -> Self {
        Self {
            connections,
            purge_interval,
            ping_timeout
        }
    }

    #[inline]
    pub async fn tick(&self) {
        self.connections.retain(|_, conn| conn.started.elapsed() <= self.ping_timeout);

        tokio::time::sleep(self.purge_interval).await;
    }
}
