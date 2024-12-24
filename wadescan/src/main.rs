mod range;
mod excludefile;

use crate::range::{ScanRange, ScanRanges};
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use dashmap::DashMap;
use default_net::get_interfaces;
use perfect_rand::PerfectRng;
use std::alloc::{alloc, Layout};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU32;
use std::ptr;
use std::ptr::NonNull;
use std::slice::from_raw_parts;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use wadescan_common::{PacketHeader, PacketType};
use xdpilone::xdp::XdpDesc;
use xdpilone::{BufIdx, Errno, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use log::trace;

#[repr(C, packed)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
struct Packet {
    ty: PacketType,
    ip: u32,
    port: u16,
    seq: u32,
    ack: u32,
    ping: bool
}

#[inline(always)]
fn set_ip_chksum(header: &mut [u8]) {
    assert!(header.len() >= 20);

    let mut sum = 0u32;
    for i in 0..5 {
        sum += u16::from_le_bytes([header[2 * i], header[2 * i + 1]]) as u32;
    }

    for i in 6..10 {
        sum += u16::from_le_bytes([header[2 * i], header[2 * i + 1]]) as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let sum = !(sum as u16);
    header[10..12].copy_from_slice(&sum.to_le_bytes());
}

#[inline(always)]
fn set_tcp_chksum(header: &mut [u8]) {
    assert!(header.len() >= 40);

    let mut ps_header: [u8; 12] = [0; 12];
    ps_header[0..8].copy_from_slice(&header[12..20]);
    ps_header[9] = 0x06;
    ps_header[11] = 20;

    let mut sum = 0u32;
    for i in 0..6 {
        sum += u16::from_le_bytes([ps_header[2 * i], ps_header[2 * i + 1]]) as u32;
    }

    for i in 0..8 {
        sum += u16::from_le_bytes([header[20 + 2 * i], header[21 + 2 * i]]) as u32;
    }

    for i in 9..10 {
        sum += u16::from_le_bytes([header[20 + 2 * i], header[21 + 2 * i]]) as u32;
    }


    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let sum = !(sum as u16);
    header[36..38].copy_from_slice(&sum.to_le_bytes());
}

const BASE_PACKET: [u8; 54] = [
    // ETHER
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // (dst mac) : [0..6]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (src mac) : [6..12]
    0x08, 0x00, // proto

    // IP : [14..34]
    0x45, 0x00, 0x00, 0x28, // version etc
    0x00, 0x01, 0x00, 0x00, // more irrelevant stuff
    0xFF, 0x06, // ttl, protocol
    0x00, 0x00, // [checksum] : [24..26]
    0, 0, 0, 0, // (src ip) : [26..30]
    0, 0, 0, 0, // [dst ip] : [30..34]

    // TCP [34..54]
    0x05, 0x39, // source port known statically as 1337 (this is required for the ebpf program to know which packets are to be directed to the scanner)
    0x00, 0x00, // [dst port] : [36..38]
    0x00, 0x00, 0x00, 0x00, // sequence number : [38..42]
    0x00, 0x00, 0x00, 0x00, // acknowledgment number : [42..46]
    0x50, // data offset [46]
    0b00000000, // flags [47]
    0x80, 0x00, // window size
    0x00, 0x00, // [checksum] : [50..52]
    0x00, 0x00, // urgent pointer
];

struct ConnectionState {
    data: Vec<u8>,
    started: Instant,

    remote_seq: u32,
    local_seq: u32,

    fin_sent: bool,
}

const PING_DATA: [u8; 22] = [19, 0, 128, 6, 12, 77, 121, 73, 115, 112, 72, 97, 116, 101, 115, 77, 101, 5, 57, 1, 1, 0];

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
fn parse_response(response: &[u8]) -> Result<Vec<u8>, u8> {
    let mut stream = Cursor::new(response);
    read_varint(&mut stream).ok_or(1)?;
    let packet_id = read_varint(&mut stream).ok_or(1)?;
    let response_length = read_varint(&mut stream).ok_or(1)?;
    if packet_id != 0x00 || response_length < 0 {
        return Err(1);
    }

    let position = stream.position() as usize;
    let status_buffer = &stream.into_inner()[position..];
    if status_buffer.len() < response_length as usize {
        return Err(0);
    }

    Ok(status_buffer.to_vec())
}

#[inline(always)]
fn cookie(ip: u32, port: u16, seed: u64) -> u32 {
    let mut hasher = DefaultHasher::new();
    (ip, port, seed).hash(&mut hasher);
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

    let mut base = umem.frame(BufIdx(0)).unwrap();
    let base = unsafe { base.addr.as_mut() };
    {
        let iface = get_interfaces().into_iter()
            .find(|i| i.name == "eth0").unwrap();
        let gateway = iface.gateway.unwrap();

        let fr = &mut base[..54];
        fr.copy_from_slice(&BASE_PACKET[..]);
        fr[0..6].copy_from_slice(&gateway.mac_addr.octets());
        fr[6..12].copy_from_slice(&iface.mac_addr.unwrap().octets());
        fr[26..30].copy_from_slice(&iface.ipv4.first().unwrap().addr.octets());

        let fr = &mut base[54..76];
        fr.copy_from_slice(&PING_DATA[..]);
    }

    let connections = Arc::new(DashMap::<(u32, u16), ConnectionState>::new());
    let reader = tokio::spawn(async move {
        let mut ring_buf = AsyncFd::new(ring_buf).unwrap();
        
        loop {
            let mut guard = ring_buf.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();

            while let Some(read) = ring_buf.next() {
                let read = read.as_ptr();
                let hdr: *const PacketHeader = read as *const PacketHeader;

                let ip = unsafe { (*hdr).ip };
                let port = unsafe { (*hdr).port };
                let addr = (ip, port);

                let seq = unsafe { (*hdr).seq };
                let ack = unsafe { (*hdr).ack };

                match unsafe { (*hdr).ty } {
                    PacketType::SynAck => {
                        if ack != cookie(ip, port, seed) + 1 {
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

                        trace!("received SYN+ACK from ip {}:{port}", Ipv4Addr::from(ip));
                    },
                    PacketType::Ack => {
                        let size = unsafe { ptr::read_unaligned(read.byte_add(PacketHeader::LEN) as *const u16) };
                        let data = if size == 0 {
                            trace!("received ACK without data from ip {}:{port}", Ipv4Addr::from(ip));

                            continue
                        } else {
                            unsafe { from_raw_parts(read.byte_add(PacketHeader::LEN + 2), size as usize) }
                        };

                        trace!("received ACK with data from ip {}:{port}", Ipv4Addr::from(ip));

                        let (ping_response, remote_seq) = if let Some(mut conn) = connections.get_mut(&addr) {
                            if seq != conn.remote_seq {
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

                        if let Ok(data) = ping_response {
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
                        trace!("received FIN with data from ip {}:{port}", Ipv4Addr::from(ip));

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

    let completer = tokio::spawn(async move {
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
        while let Some(Packet { ty, ip, port, seq: sequence, ack, ping }) = receiver.recv().await {
            {
                let fr = &mut base[..54];
                fr[47] = match ty {
                    PacketType::Syn => 0b00000010,
                    PacketType::Ack => 0b00010000,
                    PacketType::Fin => 0b00010001,
                    PacketType::PshAck => 0b00011000,

                    _ => unreachable!()
                };

                fr[30..34].copy_from_slice(&ip.to_be_bytes());
                set_ip_chksum(&mut fr[14..34]);
                fr[36..38].copy_from_slice(&port.to_be_bytes());
                fr[38..42].copy_from_slice(&sequence.to_be_bytes());
                fr[42..46].copy_from_slice(&ack.to_be_bytes());
                set_tcp_chksum(&mut fr[14..54]);
            }

            {
                let mut writer = tx.transmit(1);
                writer.insert_once(XdpDesc {
                    addr: 0,
                    len: if ping { 76 } else { 54 },
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

        let ip = dest.ip().to_bits();
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
