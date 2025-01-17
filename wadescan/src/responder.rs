use std::net::Ipv4Addr;
use std::slice::from_raw_parts;
use std::sync::Arc;
use std::time::{Duration, Instant};
use aya::maps::{MapData, RingBuf};
use dashmap::DashMap;
use log::debug;
use mongodb::bson::Document;
use mongodb::Collection;
use pnet_packet::tcp::TcpFlags;
use rustc_hash::FxBuildHasher;
use tokio::io::unix::AsyncFd;
use wadescan_common::{PacketHeader, PacketType};
use crate::{checksum, ping, Packet};
use crate::ping::{RawLatest, Response};
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
                    if ack != checksum::cookie(ip, port, self.seed) + 1 {
                        debug!("invalid cookie at SYN+ACK");

                        continue
                    }

                    self.sender.send(Packet {
                        ty: TcpFlags::ACK,
                        ip,
                        port,
                        seq: ack,
                        ack: seq + 1,
                        ping: false
                    });

                    self.sender.send(Packet {
                        ty: TcpFlags::PSH | TcpFlags::ACK,
                        ip,
                        port,
                        seq: ack,
                        ack: seq + 1,
                        ping: true
                    });
                }

                PacketType::Ack => {
                    let read = unsafe { read.add(PacketHeader::LEN) };
                    
                    let size = unsafe { read.cast::<u16>().read_unaligned() };
                    if size == 0 {
                        continue
                    }

                    let data = unsafe { from_raw_parts(read.add(2), size as usize) };

                    let remote_seq = seq.wrapping_add(size as u32);
                    let ping_response = if let Some(mut conn) = self.connections.get_mut(&(ip, port)) {
                        if seq != conn.remote_seq {
                            debug!("got wrong seq number! this is probably because of a retransmission");

                            self.sender.send(Packet {
                                ty: TcpFlags::ACK,
                                ip,
                                port,
                                seq: ack,
                                ack: conn.remote_seq,
                                ping: false
                            });

                            continue
                        }

                        conn.remote_seq = remote_seq;
                        conn.data.extend(data);

                        ping::parse_response(&conn.data)
                    } else {
                        if ack != checksum::cookie(ip, port, self.seed).wrapping_add((self.ping_data.len() + 1) as u32) {
                            debug!("cookie mismatch when reading data from: {}", ip);

                            continue;
                        }

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

                        ping::parse_response(data)
                    };

                    self.sender.send(Packet {
                        ty: TcpFlags::ACK,
                        ip,
                        port,
                        seq: ack,
                        ack: remote_seq,
                        ping: false
                    });

                    if let Ok(data) = ping_response {
                        if let Ok(mut response) = serde_json::from_slice::<RawLatest>(&data) {
                            response.raw_json = data;
                            
                            if let Ok(response) = TryInto::<Response>::try_into(response) {
                                println!("{response:?}");
                            }
                        }

                        self.sender.send(Packet {
                            ty: TcpFlags::FIN | TcpFlags::ACK,
                            ip,
                            port,
                            seq: ack,
                            ack: remote_seq,
                            ping: false
                        });
                    }
                }

                PacketType::Fin => {
                    if let Some(mut conn) = self.connections.get_mut(&(ip, port)) {
                        self.sender.send(Packet {
                            ty: TcpFlags::ACK,
                            ip,
                            port,
                            seq: conn.local_seq,
                            ack: seq + 1,
                            ping: false
                        });

                        if !conn.fin_sent {
                            self.sender.send(Packet {
                                ty: TcpFlags::FIN | TcpFlags::ACK,
                                ip,
                                port,
                                seq: conn.local_seq,
                                ack: seq + 1,
                                ping: false
                            });

                            conn.fin_sent = true;
                        }

                        if !conn.data.is_empty() {
                            self.connections.remove(&(ip, port));
                        }
                    }

                    self.sender.send(Packet {
                        ty: TcpFlags::ACK,
                        ip,
                        port,
                        seq: ack,
                        ack: seq + 1,
                        ping: false
                    });
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
