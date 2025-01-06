#![feature(const_vec_string_slice, variant_count)]

pub mod range;
pub mod excludefile;
pub mod checksum;
pub mod ping;
pub mod responder;
pub mod sender;
pub mod completer;
pub mod mode;
mod scanner;

use crate::completer::{PacketCompleter, Printer};
use crate::responder::{Purger, Responder};
use crate::sender::{PacketSender, WrappedTx};
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use default_net::get_interfaces;
use std::alloc::{alloc, Layout};
use std::env;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::ptr::NonNull;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration};
use dashmap::DashMap;
use diesel::{Connection, PgConnection};
use rustc_hash::FxBuildHasher;
use tokio::sync::RwLock;
use xdpilone::{Errno, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use crate::scanner::Scanner;

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

    let excludefile = excludefile::parse_file("exclude.conf").expect("Error parsing excludefile");
    let ping_data: &[u8] = ping::build_latest_request(767, "wadescan", 25565).leak();

    let seed = rand::random();

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

    let connections = Arc::new(DashMap::with_hasher(FxBuildHasher));
    let connections_purger = connections.clone();

    tokio::spawn(async move {
        let mut responder = Responder::new(
            connections,
            seed,
            ring_buf,
            sender_completer,
            ping_data
        ).expect("Error initiating responder");

        loop {
            if responder.tick().await.is_none() {
                break
            }
        }
    });

    tokio::spawn(async move {
        let purger = Purger::new(
            connections_purger,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );

        loop {
            purger.tick().await;
        }
    });

    let completed = Arc::new(AtomicUsize::new(0));
    let completed_printer = completed.clone();

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

    let tx = Arc::new(RwLock::new(WrappedTx(rxtx.map_tx()?)));
    let iface = get_interfaces().into_iter()
        .find(|i| i.name == "eth0").unwrap();
    let gateway_mac = iface.gateway.unwrap().mac_addr.octets();
    let iface_mac = iface.mac_addr.unwrap().octets();
    let source_ip = iface.ipv4.first().unwrap().addr;

    let sender_count = 4;
    let frame_count = 512 / sender_count;

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
            ).expect("Error initiating packet sender");

            loop {
                sender.tick().await;
            }
        });
    }

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = PgConnection::establish(&database_url).expect("Error connecting to database");

    let mut scanner = Scanner::new(db, seed, excludefile, sender);
    loop {
        scanner.tick();
    }
}
