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
mod configfile;
mod database;

use crate::completer::{PacketCompleter, Printer};
use crate::responder::{Purger, Responder};
use crate::scanner::Scanner;
use crate::sender::PacketSender;
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use dashmap::DashMap;
use default_net::get_interfaces;
use mongodb::Client;
use rustc_hash::FxBuildHasher;
use std::alloc::{alloc, Layout};
use std::env;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::ptr::NonNull;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::sync::RwLock;
use xdpilone::{Errno, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use crate::configfile::Configfile;

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

    let excludefile = excludefile::parse_file("exclude.conf").expect("Error parsing excludefile");
    let configfile = configfile::parse_file("config.toml").expect("Error parsing configfile");

    let program: &mut Xdp = ebpf.program_mut("wadescan").unwrap().try_into().unwrap();
    program.load().unwrap();
    program.attach(&configfile.scanner.interface_name, XdpFlags::SKB_MODE).unwrap();

    let ping_config = configfile.ping;
    let ping_data: &[u8] = ping::build_latest_request(
        ping_config.protocol_version,
        &ping_config.address,
        ping_config.port
    ).leak();

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
    iface.from_name(&CString::new(&*configfile.scanner.interface_name).unwrap())?;

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
    
    let client = Client::with_uri_str(configfile.database.url).await.expect("Error connecting to database");
    let database = client.database(&configfile.database.name);
    let collection = database.collection(&configfile.database.collection_name);
    let collection_responder = collection.clone();
    
    tokio::spawn(async move {
        let mut responder = Responder::new(
            collection_responder,
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
            configfile.purger.interval,
            configfile.purger.timeout
        );

        loop {
            purger.tick().await;
        }
    });

    let completed = Arc::new(AtomicUsize::new(0));
    let completed_printer = completed.clone();

    tokio::spawn(async move {
        let mut printer = Printer::new(completed_printer, configfile.printer.interval);

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

    let iface = get_interfaces().into_iter()
        .find(|i| i.name == configfile.scanner.interface_name).unwrap();
    let gateway_mac = iface.gateway.unwrap().mac_addr.octets();
    let iface_mac = iface.mac_addr.unwrap().octets();
    let source_ip = iface.ipv4.first().unwrap().addr;

    let frame_count = umem.len_frames() as usize;
    let frame_per_sender = frame_count / configfile.sender.threads;

    let tx = Arc::new(RwLock::new(rxtx.map_tx()?.into()));
    for n in 0..configfile.sender.threads {
        let receiver = receiver.clone();
        let frames = PacketSender::generate_frames(n, frame_per_sender, &umem, &iface_mac, &gateway_mac, source_ip, ping_data);
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

    let mut scanner = Scanner::new(collection, seed, excludefile, sender);
    loop {
        scanner.tick();
    }
}
