#![feature(const_vec_string_slice, variant_count)]

pub mod checksum;
pub mod completer;
pub mod configfile;
pub mod database;
pub mod excludefile;
pub mod mode;
pub mod ping;
pub mod range;
pub mod responder;
pub mod scanner;
pub mod sender;

use std::{
    alloc::{alloc, Layout},
    env,
    ffi::CString,
    num::NonZeroU32,
    ptr::NonNull,
    sync::{atomic::AtomicUsize, Arc},
};

use anyhow::Context;
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
};
use dashmap::DashMap;
use default_net::get_interfaces;
use mongodb::Client;
use rustc_hash::FxBuildHasher;
use xdpilone::{Errno, IfInfo, Socket, SocketConfig, Umem, UmemConfig};

use crate::{
    completer::{PacketCompleter, Printer},
    responder::{Purger, Responder},
    scanner::Scanner,
    sender::{PacketSender, SenderKind},
};

const UMEM_SIZE: usize = 1 << 30;

#[tokio::main(flavor = "multi_thread", worker_threads = 20)]
async fn main() -> Result<(), Errno> {
    env_logger::init();

    unsafe {
        libc::setrlimit(
            libc::RLIMIT_MEMLOCK,
            &libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            },
        )
    };

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/wadescan"
    )))
    .unwrap();

    let ring_buf = ebpf.take_map("RING_BUF").unwrap();
    let ring_buf = RingBuf::try_from(ring_buf).unwrap();

    _ = aya_log::EbpfLogger::init(&mut ebpf);

    let excludefile = excludefile::parse_file("exclude.conf")
        .context("parsing excludefile")
        .unwrap();
    let configfile = configfile::parse_file("config.toml")
        .context("parsing configfile")
        .unwrap();

    let program: &mut Xdp = ebpf.program_mut("wadescan").unwrap().try_into().unwrap();

    program.load().context("loading program").unwrap();

    program
        .attach(&configfile.scanner.interface_name, XdpFlags::default())
        .context("attaching program")
        .or_else(|_| {
            program
                .attach(&configfile.scanner.interface_name, XdpFlags::SKB_MODE)
                .context("attaching program via skb")
        })
        .unwrap();

    let ping_config = configfile.ping;
    let ping_data: &[u8] = ping::build_latest_request(
        ping_config.protocol_version,
        &ping_config.address,
        ping_config.port,
    )
    .leak();

    let seed = rand::random();

    let layout = Layout::from_size_align(UMEM_SIZE, 16384).unwrap();
    let ptr =
        NonNull::slice_from_raw_parts(unsafe { NonNull::new_unchecked(alloc(layout)) }, UMEM_SIZE);

    let umem = unsafe {
        Umem::new(
            UmemConfig {
                fill_size: 1,
                complete_size: 1 << 26,
                frame_size: 1 << 12,
                headroom: 0,
                flags: 0,
            },
            ptr,
        )
        .expect("umem creation error")
    };

    let mut iface = IfInfo::invalid();
    iface
        .from_name(&CString::new(&*configfile.scanner.interface_name).unwrap())
        .expect("failed to find interface");

    let sender_sock =
        Socket::with_shared(&iface, &umem).expect("failed to create socket for sender");
    let device = umem
        .fq_cq(&sender_sock)
        .expect("failed to create device queue");

    let sender_rxtx = umem
        .rx_tx(
            &sender_sock,
            &SocketConfig {
                rx_size: None,
                tx_size: NonZeroU32::new(1 << 26),
                bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP,
            },
        )
        .expect("failed to map rxtx for sender");

    umem.bind(&sender_rxtx)
        .expect("failed to bind sender rxtx to umem");

    let responder_sock = Socket::new(&iface).expect("failed to create socket for responder");
    let responder_rxtx = umem
        .rx_tx(
            &responder_sock,
            &SocketConfig {
                rx_size: None,
                tx_size: NonZeroU32::new(1 << 26),
                bind_flags: 0,
            },
        )
        .expect("failed to map rxtx for responder");

    device
        .bind(&responder_rxtx)
        .expect("failed to bind responder to device queue");

    let iface = get_interfaces()
        .into_iter()
        .find(|i| i.name == configfile.scanner.interface_name)
        .unwrap();
    let source_ip = iface.ipv4.first().unwrap().addr;

    let gateway_mac = iface.gateway.unwrap().mac_addr.octets();
    let iface_mac = iface.mac_addr.unwrap().octets();

    let connections = Arc::new(DashMap::with_hasher(FxBuildHasher));
    let connections_purger = connections.clone();

    let client = Client::with_uri_str(configfile.database.url)
        .await
        .expect("Error connecting to database");
    let database = client.database(&configfile.database.name);
    let collection = database.collection(&configfile.database.collection_name);
    let collection_responder = collection.clone();

    let frames = PacketSender::frames(
        SenderKind::Responder,
        &gateway_mac,
        &iface_mac,
        source_ip,
        &umem,
        ping_data,
    );

    let tx = responder_rxtx.map_tx()?;
    tokio::spawn(async move {
        let mut responder = Responder::new(
            collection_responder,
            connections,
            seed,
            ring_buf,
            PacketSender::new(tx, frames).expect("Error initiating packet sender"),
            ping_data,
        )
        .expect("Error initiating responder");

        loop {
            if responder.tick().await.is_none() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let purger = Purger::new(
            connections_purger,
            configfile.purger.interval,
            configfile.purger.timeout,
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

    let frames = PacketSender::frames(
        SenderKind::Scanner,
        &gateway_mac,
        &iface_mac,
        source_ip,
        &umem,
        ping_data,
    );

    // be ready to melt your fucking network!
    let tx = sender_rxtx.map_tx()?;
    let mut scanner = Scanner::new(
        collection,
        seed,
        excludefile,
        PacketSender::new(tx, frames).expect("Error initiating packet sender"),
    );

    loop {
        scanner.tick();
    }
}
