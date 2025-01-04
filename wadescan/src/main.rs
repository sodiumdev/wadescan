#![feature(const_vec_string_slice)]

pub mod range;
pub mod excludefile;
pub mod checksum;
pub mod ping;
pub mod responder;
pub mod sender;
pub mod completer;

use crate::completer::{PacketCompleter, Printer};
use crate::range::{ScanRange, ScanRanges};
use crate::responder::Responder;
use crate::sender::{PacketSender, WrappedTx};
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use default_net::get_interfaces;
use perfect_rand::PerfectRng;
use pnet_packet::tcp::{TcpFlags};
use std::alloc::{alloc, Layout};
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::ptr::NonNull;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration};
use tokio::sync::RwLock;
use xdpilone::{Errno, IfInfo, Socket, SocketConfig, Umem, UmemConfig};

#[repr(C, packed)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct Packet {
    ty: u8,
    ip: Ipv4Addr,
    port: u16,
    seq: u32,
    ack: u32,
    ping: bool
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

    let ping_data: &'static [u8] = ping::build_latest_request(767, "wadescan", 25565).leak();

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

    const UMEM_SIZE: usize = 1 << 30;
    let layout = Layout::from_size_align(UMEM_SIZE, 16384).unwrap();
    let ptr = unsafe { NonNull::slice_from_raw_parts(NonNull::new_unchecked(alloc(layout)), UMEM_SIZE) };

    let umem: Umem = {
        unsafe { Umem::new(UmemConfig {
            fill_size: 1,
            complete_size: 1 << 26,
            frame_size: 1 << 12,
            headroom: 0,
            flags: 0,
        }, ptr).expect("umem creation error") }
    };

    let mut iface = IfInfo::invalid();
    iface.from_name(c"eth0")?;

    let sock = Socket::with_shared(&iface, &umem)?;
    let device = umem.fq_cq(&sock)?;

    let rxtx = umem.rx_tx(&sock, &SocketConfig {
        rx_size: None,
        tx_size: NonZeroU32::new(1 << 26),
        bind_flags: SocketConfig::XDP_BIND_ZEROCOPY  | SocketConfig::XDP_BIND_NEED_WAKEUP,
    })?;

    umem.bind(&rxtx)?;

    let (sender, receiver) = flume::bounded::<Packet>(u16::MAX as usize);
    let sender_completer = sender.clone();

    let iface = get_interfaces().into_iter()
        .find(|i| i.name == "eth0").unwrap();
    let gateway_mac = iface.gateway.unwrap().mac_addr.octets();
    let iface_mac = iface.mac_addr.unwrap().octets();
    let source_ip = iface.ipv4.first().unwrap().addr;

    let completed = Arc::new(AtomicUsize::new(0));
    let completed_printer = completed.clone();

    tokio::spawn(async move {
        let mut responder = Responder::new(
            seed,
            ring_buf,
            sender_completer,
            ping_data
        ).unwrap();

        loop {
            if responder.tick().await.is_none() {
                break
            }
        }
    });

    tokio::spawn(async move {
        let mut printer = Printer::new(completed_printer, Duration::from_secs(5));

        loop {
            printer.tick().await;
        }
    });

    tokio::spawn(async move {
        let mut completer = PacketCompleter::new(device, completed);

        loop {
            completer.tick();
        }
    });

    let sender_count = 4;
    let frame_count = 512 / sender_count;

    let tx = Arc::new(RwLock::new(WrappedTx(rxtx.map_tx()?)));
    
    for n in 0..sender_count {
        let receiver = receiver.clone();
        let frames = PacketSender::generate_frames(n, frame_count, &umem, &iface_mac, &gateway_mac, source_ip, ping_data);
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut sender = PacketSender::new(
                frames,
                source_ip,
                tx,
                receiver,
                ping_data
            ).unwrap();

            loop {
                sender.tick().await;
            }
        });
    }

    let packet_calculator_count = 8;
    let packets_per_calculator = ranges.count / packet_calculator_count;

    for i in 0..packet_calculator_count {
        let rng = rng.clone();
        let ranges = ranges.clone();
        let sender = sender.clone();

        let offset = i * packets_per_calculator;
        tokio::spawn(async move {
            for n in 0..packets_per_calculator {
                let shuffled_index = rng.shuffle((offset + n) as u64);
                let dest = ranges.index(shuffled_index as usize);

                let ip = dest.0;
                let port = dest.1;

                sender.send_async(Packet {
                    ty: TcpFlags::SYN,
                    ip,
                    port,
                    seq: checksum::cookie(ip, port, seed),
                    ack: 0,
                    ping: false
                }).await.unwrap();
            }
        });
    }

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await; // to avoid busy-waiting
    }
}
