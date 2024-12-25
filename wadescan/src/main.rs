mod range;
mod excludefile;

use crate::range::{ScanRange, ScanRanges};
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use dashmap::DashMap;
use default_net::get_interfaces;
use perfect_rand::PerfectRng;
use std::alloc::{alloc, Layout};
use std::hash::Hasher;
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
use log::trace;
use pnet_base::MacAddr;
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{checksum, MutableIpv4Packet};
use pnet_packet::MutablePacket;
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpOptionPacket};
use rustc_hash::{FxBuildHasher, FxHasher};

#[repr(C, packed)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
struct Packet {
    ty: PacketType,
    ip: Ipv4Addr,
    port: u16,
    seq: u32,
    ack: u32,
    ping: bool
}

static PING_DATA: [u8; 22] = [19, 0, 128, 6, 12, 77, 121, 73, 115, 112, 72, 97, 116, 101, 115, 77, 101, 5, 57, 1, 1, 0];

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
        reader.read_exact(&mut buffer).ok()?;
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
    let status_buffer = &stream.into_inner()[position..];
    if status_buffer.len() < response_length as usize {
        return None
    }

    Some(status_buffer.to_vec())
}

#[inline(always)]
fn cookie(ip: Ipv4Addr, port: u16, seed: u64) -> u32 {
    let mut hasher = FxHasher::default();
    hasher.write_u64(seed);
    hasher.write_u32(ip.to_bits());
    hasher.write_u16(port);

    hasher.finish() as u32
}

#[tokio::main(flavor = "multi_thread", worker_threads = 18)]
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

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/wadescan"
    ))).unwrap();

    let ring_buf = ebpf.take_map("RING_BUF").unwrap();
    let ring_buf = RingBuf::try_from(ring_buf).unwrap();

    _ = aya_log::EbpfLogger::init(&mut ebpf);

    let program: &mut Xdp = ebpf.program_mut("wadescan").unwrap().try_into().unwrap();
    program.load().unwrap();
    program.attach("eth0", XdpFlags::default()).unwrap();

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

    let rng = PerfectRng::new(ranges.count() as u64, seed, 3);
    let ranges = ranges.into_static();

    const UMEM_SIZE: usize = 1 << 20;
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

    let mut tx = rxtx.map_tx()?;

    umem.bind(&rxtx)?;

    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<Packet>();

    let sender_a = Arc::new(sender);
    let sender_b = sender_a.clone();

    let mut base_frame = umem.frame(BufIdx(0)).unwrap();
    let base = unsafe { base_frame.addr.as_mut() };

    let iface = get_interfaces().into_iter()
        .find(|i| i.name == "eth0").unwrap();
    let gateway = iface.gateway.unwrap();
    let source_ip = iface.ipv4.first().unwrap().addr;

    let (ether_base, base) = base.split_at_mut(14);
    let mut mutable_ethernet_packet = MutableEthernetPacket::new(ether_base).unwrap();
    mutable_ethernet_packet.set_destination(MacAddr::from(gateway.mac_addr.octets()));
    mutable_ethernet_packet.set_source(MacAddr::from(iface.mac_addr.unwrap().octets()));
    mutable_ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let (ipv4_base, tcp_base) = base.split_at_mut(20);
    let mut mutable_ipv4_packet = MutableIpv4Packet::new(ipv4_base).unwrap();
    mutable_ipv4_packet.set_version(4);
    mutable_ipv4_packet.set_header_length(5);
    mutable_ipv4_packet.set_dscp(0);
    mutable_ipv4_packet.set_ecn(0);
    mutable_ipv4_packet.set_identification(1);
    mutable_ipv4_packet.set_flags(0b010);
    mutable_ipv4_packet.set_fragment_offset(0);
    mutable_ipv4_packet.set_ttl(64);
    mutable_ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    mutable_ipv4_packet.set_source(source_ip);
    mutable_ipv4_packet.set_options(&[]);

    let options = [TcpOption::mss(1360), TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()];
    let other_options = [TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()];

    let tcp_options_length_as_bytes = options.iter().map(TcpOptionPacket::packet_size).sum::<usize>();
    let syn_doff = 5 + (tcp_options_length_as_bytes + 3) / 4;

    let tcp_options_length_as_bytes = other_options.iter().map(TcpOptionPacket::packet_size).sum::<usize>();
    let other_doff = 5 + (tcp_options_length_as_bytes + 3) / 4;

    let tcp_header_len = syn_doff * 4;
    let mut mutable_tcp_packet = MutableTcpPacket::new(tcp_base).unwrap();
    mutable_tcp_packet.set_source(1337);
    mutable_tcp_packet.set_data_offset(syn_doff as u8);
    mutable_tcp_packet.set_reserved(0);
    mutable_tcp_packet.set_window(32768);
    mutable_tcp_packet.set_urgent_ptr(0);
    mutable_tcp_packet.set_options(&options);
    
    let connections = Arc::new(DashMap::<(Ipv4Addr, u16), ConnectionState, FxBuildHasher>::with_hasher(FxBuildHasher));
    let reader = tokio::spawn(async move {
        let mut ring_buf = AsyncFd::new(ring_buf).unwrap();
        
        loop {
            let mut guard = ring_buf.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();

            while let Some(read) = ring_buf.next() {
                let read = read.as_ptr();
                let hdr: *const PacketHeader = read as *const PacketHeader;

                let ip = unsafe { (*hdr).ip };
                let ip = Ipv4Addr::from(ip);
                
                let port = unsafe { (*hdr).port };
                let addr = (ip, port);

                let seq = unsafe { (*hdr).seq };
                let ack = unsafe { (*hdr).ack };

                match unsafe { (*hdr).ty } {
                    PacketType::SynAck => {
                        if ack != cookie(ip, port, seed) + 1 {
                            trace!("invalid cookie at SYN+ACK");

                            continue
                        }
                        
                        sender_b.send(Packet {
                            ty: PacketType::Ack,
                            ip,
                            port,
                            seq: ack,
                            ack: seq + 1,
                            ping: false
                        }).unwrap();

                        sender_b.send(Packet {
                            ty: PacketType::PshAck,
                            ip,
                            port,
                            seq: ack,
                            ack: seq + 1,
                            ping: true
                        }).unwrap();
                    }

                    PacketType::Ack => {
                        let size = unsafe { ptr::read_unaligned(read.byte_add(PacketHeader::LEN) as *const u16) };
                        let data = if size == 0 {
                            continue
                        } else {
                            unsafe { from_raw_parts(read.byte_add(PacketHeader::LEN + 2), size as usize) }
                        };

                        trace!("received ACK with data from ip {}:{port}", ip);

                        let (ping_response, remote_seq) = if let Some(mut conn) = connections.get_mut(&addr) {
                            if seq != conn.remote_seq {
                                trace!("Got wrong seq number! This is probably because of a re-transmission");

                                sender_b.send(Packet {
                                    ty: PacketType::Ack,
                                    ip,
                                    port,
                                    seq: ack,
                                    ack: conn.remote_seq,
                                    ping: false
                                }).unwrap();

                                continue;
                            }

                            let remote_seq = seq + size as u32;
                            conn.data.extend(data.to_vec());
                            conn.remote_seq = remote_seq;

                            (parse_response(&conn.data), remote_seq)
                        } else {
                            if ack != cookie(ip, port, seed).wrapping_add(23) {
                                trace!("cookie mismatch when reading data from: {}", ip);

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

                        sender_b.send(Packet {
                            ty: PacketType::Ack,
                            ip,
                            port,
                            seq: ack,
                            ack: remote_seq,
                            ping: false
                        }).unwrap();

                        if let Some(data) = ping_response {
                            let data_string = String::from_utf8_lossy(&data);
                            println!("{}", data_string);

                            sender_b.send(Packet {
                                ty: PacketType::Fin,
                                ip,
                                port,
                                seq: ack,
                                ack: remote_seq,
                                ping: false
                            }).unwrap();
                        }
                    }

                    PacketType::Fin => {
                        trace!("received FIN with data from ip {}:{port}", ip);

                        if let Some(mut conn) = connections.get_mut(&addr) {
                            sender_b.send(Packet {
                                ty: PacketType::Ack,
                                ip,
                                port,
                                seq: conn.local_seq,
                                ack: seq + 1,
                                ping: false
                            }).unwrap();

                            if !conn.fin_sent {
                                sender_b.send(Packet {
                                    ty: PacketType::Fin,
                                    ip,
                                    port,
                                    seq: conn.local_seq,
                                    ack: seq + 1,
                                    ping: false
                                }).unwrap();

                                conn.fin_sent = true;
                            }

                            if !conn.data.is_empty() {
                                connections.remove(&addr);
                            }
                        } else {
                            sender_b.send(Packet {
                                ty: PacketType::Ack,
                                ip,
                                port,
                                seq: ack,
                                ack: seq + 1,
                                ping: false
                            }).unwrap();
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
                let mut reader = device.complete(1);
                if reader.read().is_some() {
                    completed += 1;
                }

                reader.release();
            }
        }
    });

    tokio::spawn(async move {
        while let Some(Packet { ty, ip, port, seq, ack, ping }) = receiver.recv().await {
            let len = if ping {
                mutable_tcp_packet.payload_mut()[..PING_DATA.len()].copy_from_slice(&PING_DATA[..]);

                20 + tcp_header_len + PING_DATA.len()
            } else { 20 + tcp_header_len } as u16;

            {
                mutable_ipv4_packet.set_destination(ip);
                mutable_ipv4_packet.set_total_length(len);
                mutable_ipv4_packet.set_checksum(checksum(
                    &mutable_ipv4_packet.to_immutable()
                ));
                
                if ty == PacketType::Syn {
                    mutable_tcp_packet.set_data_offset(syn_doff as u8);
                    mutable_tcp_packet.set_options(&options)
                } else {
                    mutable_tcp_packet.set_data_offset(other_doff as u8);
                    mutable_tcp_packet.set_options(&other_options)
                }

                mutable_tcp_packet.set_flags(match ty {
                    PacketType::SynAck => TcpFlags::SYN | TcpFlags::ACK,
                    PacketType::Syn => TcpFlags::SYN,
                    PacketType::Ack => TcpFlags::ACK,
                    PacketType::Rst => TcpFlags::RST | TcpFlags::ACK,
                    PacketType::Fin => TcpFlags::FIN | TcpFlags::ACK,
                    PacketType::PshAck => TcpFlags::PSH | TcpFlags::ACK,
                });

                mutable_tcp_packet.set_destination(port);
                mutable_tcp_packet.set_sequence(seq);
                mutable_tcp_packet.set_acknowledgement(ack);

                mutable_tcp_packet.set_checksum(ipv4_checksum(
                    &mutable_tcp_packet.to_immutable(),
                    &ip,
                    &source_ip,
                ));
            }

            {
                let mut writer = tx.transmit(1);
                writer.insert_once(XdpDesc {
                    addr: 0,
                    len: (len + 14) as u32,
                    options: 0
                });

                writer.commit();
            }

            if tx.needs_wakeup() {
                tx.wake();
            }
        }
    });

    for n in 0..ranges.count {
        let shuffled_index = rng.shuffle(n as u64);
        let dest = ranges.index(shuffled_index as usize);

        let ip = *dest.ip();
        let port = dest.port();

        sender_a.send(Packet {
            ty: PacketType::Syn,
            ip,
            port,
            seq: cookie(ip, port, seed),
            ack: 0,
            ping: false
        }).unwrap();
    }

    println!("Finished scanning...");
    reader.await.unwrap();

    Ok(())
}
