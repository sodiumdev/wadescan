#![feature(const_vec_string_slice)]

mod range;
mod excludefile;
mod checksum;
mod ping;

use crate::range::{ScanRange, ScanRanges};
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use dashmap::DashMap;
use default_net::get_interfaces;
use perfect_rand::PerfectRng;
use std::alloc::{alloc, Layout};
use std::io::{Cursor, Read};
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::ptr;
use std::ptr::NonNull;
use std::slice::from_raw_parts;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use wadescan_common::{PacketHeader, PacketType};
use xdpilone::xdp::XdpDesc;
use xdpilone::{BufIdx, Errno, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use log::debug;
use pnet_base::MacAddr;
use rustc_hash::FxBuildHasher;
use pnet_packet::{ethernet::{EtherTypes, MutableEthernetPacket}, ip::IpNextHeaderProtocols, ipv4::{MutableIpv4Packet}, tcp::{MutableTcpPacket, TcpFlags, TcpOption}, util, Packet as OtherPacket};

#[repr(C, packed)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
struct Packet {
    ty: u8,
    ip: Ipv4Addr,
    port: u16,
    seq: u32,
    ack: u32,
    ping: bool
}

struct ConnectionState {
    data: Vec<u8>,
    started: Instant,

    remote_seq: u32,
    local_seq: u32,

    fin_sent: bool,
}

#[inline(always)]
fn read_varint(reader: &mut (dyn Read + Unpin + Send)) -> Option<i32> {
    let mut buffer = [0];
    let mut ans = 0;
    for i in 0..5 {
        if reader.read_exact(&mut buffer).is_err() { return None };

        ans |= ((buffer[0] & 0b0111_1111) as i32) << (7 * i);
        if buffer[0] & 0b1000_0000 == 0 {
            return Some(ans);
        }
    }

    Some(ans)
}

#[inline(always)]
fn parse_response(response: &[u8]) -> Option<Vec<u8>> {
    let mut stream = Cursor::new(response);
    read_varint(&mut stream)?;

    let packet_id = read_varint(&mut stream)?;
    let response_length = read_varint(&mut stream)?;
    if packet_id != 0x00 || response_length < 0 {
        return None
    }

    let position = stream.position() as usize;
    let status_buffer = &response[position..];
    if status_buffer.len() < response_length as usize {
        return None
    }

    Some(status_buffer.to_vec())
}



#[tokio::main(flavor = "multi_thread", worker_threads = 20)]
async fn main() -> Result<(), Errno> {
    env_logger::init();

    unsafe {
        libc::setrlimit(
            libc::RLIMIT_MEMLOCK,
            &libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            }
        )
    };

    let ping_data = Arc::new(ping::build_latest_request(767, "wadescan", 25565));
    let ping_data_len = ping_data.len();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/wadescan"
    ))).unwrap();

    let ring_buf = ebpf.take_map("RING_BUF").unwrap();
    let ring_buf = RingBuf::try_from(ring_buf).unwrap();

    _ = aya_log::EbpfLogger::init(&mut ebpf);

    let program: &mut Xdp = ebpf.program_mut("wadescan").unwrap().try_into().unwrap();
    program.load().unwrap();
    program.attach("eth0", XdpFlags::SKB_MODE).unwrap();

    let mut ranges = ScanRanges::new();
    ranges.extend(vec![ScanRange::single_port(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
        25565,
    )]);

    {
        let excludes = excludefile::parse_file("exclude.conf").expect("Error parsing excludefile");
        ranges.apply_exclude(&excludes);
    }

    let seed = rand::random();

    let rng = Arc::new(PerfectRng::new(ranges.count() as u64, seed, 3));
    let ranges = Arc::new(ranges.into_static());

    const UMEM_SIZE: usize = 1 << 21;
    let layout = Layout::from_size_align(UMEM_SIZE, 16384).unwrap();
    let ptr = unsafe { NonNull::slice_from_raw_parts(NonNull::new_unchecked(alloc(layout)), UMEM_SIZE) };

    let umem: Umem = {
        unsafe { Umem::new(UmemConfig {
            fill_size: 1,
            complete_size: 1 << 20,
            frame_size: 1 << 12,
            headroom: 0,
            flags: 0,
        }, ptr).expect("umem creation error") }
    };

    let mut iface = IfInfo::invalid();
    iface.from_name(c"eth0")?;

    let sock = Socket::with_shared(&iface, &umem)?;
    let mut device = umem.fq_cq(&sock)?;

    let rxtx = umem.rx_tx(&sock, &SocketConfig {
        rx_size: None,
        tx_size: NonZeroU32::new(1 << 20),
        bind_flags: SocketConfig::XDP_BIND_ZEROCOPY  | SocketConfig::XDP_BIND_NEED_WAKEUP,
    })?;

    umem.bind(&rxtx)?;

    let (sender, receiver) = flume::bounded::<Packet>(u16::MAX as usize);
    let sender_b = sender.clone();

    let iface = get_interfaces().into_iter()
        .find(|i| i.name == "eth0").unwrap();
    let gateway_mac = iface.gateway.unwrap().mac_addr.octets();
    let iface_mac = iface.mac_addr.unwrap().octets();
    let source_ip = iface.ipv4.first().unwrap().addr;

    let sender_count = 4;
    let frame_count = 512 / sender_count;

    let connections = Arc::new(DashMap::<(Ipv4Addr, u16), ConnectionState, FxBuildHasher>::with_hasher(FxBuildHasher));
    tokio::spawn(async move {
        let mut ring_buf = AsyncFd::new(ring_buf).unwrap();
        
        loop {
            let mut guard = ring_buf.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();

            while let Some(read) = ring_buf.next() {
                let read = read.as_ptr();
                let hdr: *const PacketHeader = read as *const PacketHeader;

                let ip = Ipv4Addr::from(unsafe { (*hdr).ip });
                
                let port = unsafe { (*hdr).port };
                let addr = (ip, port);

                let seq = unsafe { (*hdr).seq };
                let ack = unsafe { (*hdr).ack };

                match unsafe { (*hdr).ty } {
                    PacketType::SynAck => {
                        if ack != checksum::cookie(ip, port, seed) + 1 {
                            debug!("invalid cookie at SYN+ACK");

                            continue
                        }
                        
                        _ = sender_b.send_async(Packet {
                            ty: TcpFlags::ACK,
                            ip,
                            port,
                            seq: ack,
                            ack: seq + 1,
                            ping: false
                        }).await;

                        _ = sender_b.send_async(Packet {
                            ty: TcpFlags::PSH | TcpFlags::ACK,
                            ip,
                            port,
                            seq: ack,
                            ack: seq + 1,
                            ping: true
                        }).await;
                    }

                    PacketType::Ack => {
                        let size = unsafe { ptr::read_unaligned(read.byte_add(PacketHeader::LEN) as *const u16) };
                        let data = if size == 0 {
                            continue
                        } else {
                            unsafe { from_raw_parts(read.byte_add(PacketHeader::LEN + 2), size as usize) }
                        };

                        let (ping_response, remote_seq) = if let Some(mut conn) = connections.get_mut(&addr) {
                            if seq != conn.remote_seq {
                                debug!("Got wrong seq number! This is probably because of a re-transmission");

                                sender_b.send_async(Packet {
                                    ty: TcpFlags::ACK,
                                    ip,
                                    port,
                                    seq: ack,
                                    ack: conn.remote_seq,
                                    ping: false
                                }).await;

                                continue;
                            }

                            let remote_seq = seq + size as u32;
                            conn.data.extend(data.to_vec());
                            conn.remote_seq = remote_seq;

                            (parse_response(&conn.data), remote_seq)
                        } else {
                            if ack != checksum::cookie(ip, port, seed).wrapping_add((ping_data_len + 1) as u32) {
                                debug!("cookie mismatch when reading data from: {}", ip);

                                continue;
                            }

                            let remote_seq = seq.wrapping_add(size as u32);
                            connections.insert(
                                addr,
                                ConnectionState {
                                    data: data.to_vec(),
                                    remote_seq,
                                    local_seq: ack,
                                    started: Instant::now(),
                                    fin_sent: false,
                                },
                            );
                            
                            (parse_response(data), remote_seq)
                        };

                        _ = sender_b.send_async(Packet {
                            ty: TcpFlags::ACK,
                            ip,
                            port,
                            seq: ack,
                            ack: remote_seq,
                            ping: false
                        }).await;

                        if let Some(data) = ping_response {
                            let data_string = String::from_utf8_lossy(&data);
                            println!("{}", data_string);

                            _ = sender_b.send_async(Packet {
                                ty: TcpFlags::FIN,
                                ip,
                                port,
                                seq: ack,
                                ack: remote_seq,
                                ping: false
                            }).await;
                        }
                    }

                    PacketType::Fin => {
                        if let Some(mut conn) = connections.get_mut(&addr) {
                            _ = sender_b.send_async(Packet {
                                ty: TcpFlags::ACK,
                                ip,
                                port,
                                seq: conn.local_seq,
                                ack: seq + 1,
                                ping: false
                            }).await;

                            if !conn.fin_sent {
                                _ = sender_b.send_async(Packet {
                                    ty: TcpFlags::FIN,
                                    ip,
                                    port,
                                    seq: conn.local_seq,
                                    ack: seq + 1,
                                    ping: false
                                }).await;

                                conn.fin_sent = true;
                            }

                            if !conn.data.is_empty() {
                                connections.remove(&addr);
                            }
                        } else {
                            _ = sender_b.send_async(Packet {
                                ty: TcpFlags::ACK,
                                ip,
                                port,
                                seq: ack,
                                ack: seq + 1,
                                ping: false
                            }).await;
                        }
                    }

                    _ => {}
                };
            }

            guard.clear_ready();
        }
    });

    tokio::spawn(async move {
        let mut completed = 0u32;
        let mut completed_last = 0;
        let mut last_print = Instant::now();

        let threshold = Duration::from_secs(5);

        loop {
            {
                let elapsed = last_print.elapsed();
                if completed != 0 && elapsed > threshold {
                    let packets_per_second = (completed - completed_last) as f64 / elapsed.as_secs_f64();

                    if packets_per_second > 10_000_000. {
                        eprintln!("{} mpps", (packets_per_second / 1_000_000.).round() as u64);
                    } else if packets_per_second > 10_000. {
                        eprintln!("{} kpps", (packets_per_second / 1_000.).round() as u64);
                    } else {
                        eprintln!("{} pps", packets_per_second.round() as u64);
                    }

                    completed_last = completed;
                    last_print = Instant::now();
                }
            }

            {
                let mut reader = device.complete(device.available());
                while reader.read().is_some() {
                    completed += 1;
                }

                reader.release();
            }
        }
    });

    for n in 0..sender_count {
        let mut tx = rxtx.map_tx()?;
        
        let offset = n * frame_count;
        let mut frames = (0..frame_count)
            .map(|i| {
                let mut frame = umem.frame(BufIdx((offset + i) as u32)).unwrap();
                let base = unsafe { frame.addr.as_mut() };

                let (ether_base, base) = base.split_at_mut(14);
                {
                    let mut ethernet_packet = MutableEthernetPacket::new(ether_base).unwrap();
                    ethernet_packet.set_destination(MacAddr::from(gateway_mac));
                    ethernet_packet.set_source(MacAddr::from(iface_mac));
                    ethernet_packet.set_ethertype(EtherTypes::Ipv4);
                }

                let (ipv4_base, base) = base.split_at_mut(20);
                let mut ipv4_packet = MutableIpv4Packet::new(ipv4_base).unwrap();
                ipv4_packet.set_version(4);
                ipv4_packet.set_header_length(5);
                ipv4_packet.set_dscp(0);
                ipv4_packet.set_ecn(0);
                ipv4_packet.set_identification(1);
                ipv4_packet.set_flags(0b010);
                ipv4_packet.set_fragment_offset(0);
                ipv4_packet.set_ttl(64);
                ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                ipv4_packet.set_source(source_ip);
                ipv4_packet.set_options(&[]);

                let mut tcp_packet = MutableTcpPacket::new(base).unwrap();
                tcp_packet.set_source(61000);
                tcp_packet.set_reserved(0);
                tcp_packet.set_window(32768);
                tcp_packet.set_urgent_ptr(0);

                (frame.offset, ipv4_packet, tcp_packet)
            })
            .collect::<Vec<_>>();

        let ping_data = ping_data.clone();
        let receiver = receiver.clone();
        tokio::spawn(async move {
            let mut frame = 0;

            while let Ok(Packet { ty, ip, port, seq, ack, ping }) = receiver.recv_async().await {
                let (offset, ipv4_packet, tcp_packet) = frames.get_mut(frame).unwrap();

                frame += 1;
                if frame >= frame_count {
                    frame = 0;
                }

                let len;
                {
                    let tcp_packet_len = if ty == TcpFlags::SYN {
                        tcp_packet.set_data_offset(7);
                        tcp_packet.set_options(&[TcpOption::mss(1340), TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()]);

                        28
                    } else {
                        tcp_packet.set_data_offset(5);
                        tcp_packet.set_options(&[]);

                        20
                    } + if ping { ping_data_len } else { 0 };

                    let total_len = 20 + tcp_packet_len;
                    len = 14 + total_len;

                    ipv4_packet.set_destination(ip);
                    ipv4_packet.set_total_length(total_len as u16);
                    ipv4_packet.set_checksum(
                        checksum::ipv4(ipv4_packet.packet())
                    );

                    tcp_packet.set_checksum(0);
                    tcp_packet.set_destination(port);
                    tcp_packet.set_sequence(seq);
                    tcp_packet.set_acknowledgement(ack);
                    tcp_packet.set_flags(ty);

                    if ping {
                        tcp_packet.set_payload(&ping_data);
                    }

                    tcp_packet.set_checksum(checksum::tcp(tcp_packet.packet().as_ptr(), tcp_packet_len, &source_ip, &ip));
                };

                {
                    let mut writer = tx.transmit(1);
                    writer.insert_once(XdpDesc {
                        addr: *offset,
                        len: len as u32,
                        options: 0
                    });
                    
                    writer.commit();
                }

                if tx.needs_wakeup() {
                    tx.wake();
                }
            }
        });
    }

    let packet_calculator_count = 8;
    let packets_per_calculator = ranges.count / packet_calculator_count;

    for i in 0..packet_calculator_count {
        let rng = rng.clone();
        let ranges = ranges.clone();
        let sender_a = sender.clone();

        let offset = i * packets_per_calculator;
        tokio::spawn(async move {
            for n in 0..packets_per_calculator {
                let shuffled_index = rng.shuffle((offset + n) as u64);
                let dest = ranges.index(shuffled_index as usize);

                let ip = dest.0;
                let port = dest.1;

                _ = sender_a.send_async(Packet {
                    ty: TcpFlags::SYN,
                    ip,
                    port,
                    seq: checksum::cookie(ip, port, seed),
                    ack: 0,
                    ping: false
                }).await;
            }
        });
    }

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
