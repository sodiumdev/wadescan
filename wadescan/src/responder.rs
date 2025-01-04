use std::net::Ipv4Addr;
use std::slice::from_raw_parts;
use std::time::Instant;
use aya::maps::{MapData, RingBuf};
use dashmap::DashMap;
use flume::Sender;
use log::debug;
use pnet_packet::tcp::TcpFlags;
use rustc_hash::FxBuildHasher;
use tokio::io::unix::AsyncFd;
use wadescan_common::{PacketHeader, PacketType};
use crate::{checksum, ping, Packet};

struct ConnectionState {
    data: Vec<u8>,
    started: Instant,

    remote_seq: u32,
    local_seq: u32,

    fin_sent: bool,
}

pub struct Responder {
    connections: DashMap<(Ipv4Addr, u16), ConnectionState, FxBuildHasher>,
    sender: Sender<Packet>,
    
    fd: AsyncFd<RingBuf<MapData>>,
    seed: u64,
    
    ping_data: &'static [u8]
}

impl Responder {
    #[inline]
    pub fn new(seed: u64, ring_buf: RingBuf<MapData>, sender: Sender<Packet>, ping_data: &'static [u8]) -> Option<Self> {
        let fd = AsyncFd::new(ring_buf).ok()?;

        Some(Self {
            connections: DashMap::with_hasher(FxBuildHasher),
            sender,
            
            fd,
            seed,

            ping_data
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

                    _ = self.sender.send_async(Packet {
                        ty: TcpFlags::ACK,
                        ip,
                        port,
                        seq: ack,
                        ack: seq + 1,
                        ping: false
                    }).await;

                    _ = self.sender.send_async(Packet {
                        ty: TcpFlags::PSH | TcpFlags::ACK,
                        ip,
                        port,
                        seq: ack,
                        ack: seq + 1,
                        ping: true
                    }).await;
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

                            _ = self.sender.send_async(Packet {
                                ty: TcpFlags::ACK,
                                ip,
                                port,
                                seq: ack,
                                ack: conn.remote_seq,
                                ping: false
                            }).await;

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

                    _ = self.sender.send_async(Packet {
                        ty: TcpFlags::ACK,
                        ip,
                        port,
                        seq: ack,
                        ack: remote_seq,
                        ping: false
                    }).await;

                    if let Ok(data) = ping_response {
                        let data_string = String::from_utf8_lossy(&data);
                        println!("{}", data_string);

                        _ = self.sender.send_async(Packet {
                            ty: TcpFlags::FIN | TcpFlags::ACK,
                            ip,
                            port,
                            seq: ack,
                            ack: remote_seq,
                            ping: false
                        }).await;
                    }
                }

                PacketType::Fin => {
                    if let Some(mut conn) = self.connections.get_mut(&(ip, port)) {
                        _ = self.sender.send_async(Packet {
                            ty: TcpFlags::ACK,
                            ip,
                            port,
                            seq: conn.local_seq,
                            ack: seq + 1,
                            ping: false
                        }).await;

                        if !conn.fin_sent {
                            _ = self.sender.send_async(Packet {
                                ty: TcpFlags::FIN | TcpFlags::ACK,
                                ip,
                                port,
                                seq: conn.local_seq,
                                ack: seq + 1,
                                ping: false
                            }).await;

                            conn.fin_sent = true;
                        }

                        if !conn.data.is_empty() {
                            self.connections.remove(&(ip, port));
                        }
                    }

                    _ = self.sender.send_async(Packet {
                        ty: TcpFlags::ACK,
                        ip,
                        port,
                        seq: ack,
                        ack: seq + 1,
                        ping: false
                    }).await;
                }
                
                _ => unreachable!()
            };
        }

        guard.clear_ready();
        
        Some(())
    }
}
