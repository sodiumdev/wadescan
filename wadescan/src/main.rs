#![feature(const_vec_string_slice, variant_count)]
#![feature(generic_arg_infer)]
#![feature(int_roundings)]

pub mod checksum;
pub mod completer;
pub mod configfile;
pub mod excludefile;
pub mod mode;
pub mod ping;
pub mod processor;
pub mod range;
pub mod responder;
pub mod scanner;
pub mod sender;
mod shared;

use std::{
    alloc::{Layout, alloc},
    env,
    ffi::CString,
    ptr::NonNull,
    sync::Arc,
};

use anyhow::Context;
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
};
use dashmap::DashMap;
use default_net::get_interfaces;
use log::{error, info};
use mongodb::Client;
use rustc_hash::FxBuildHasher;
use xdpilone::{IfInfo, Socket, SocketConfig, Umem, UmemConfig};

use crate::{
    completer::PacketCompleter,
    processor::Processor,
    responder::{Purger, Responder},
    scanner::Scanner,
    sender::{ResponseSender, SynSender},
    shared::FRAME_SIZE,
};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    unsafe {
        // set resource limit to infinity
        // oom go brr
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        });
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/wadescan"
    )))
    .expect("failed to load ebpf");

    let ring_buf = ebpf
        .take_map("RING_BUF")
        .expect("somehow the ring buffer doesnt exist");
    let ring_buf =
        RingBuf::try_from(ring_buf).expect("the ring buffer isn't actually a ring buffer");

    _ = aya_log::EbpfLogger::init(&mut ebpf);

    let excludefile = excludefile::parse_file("exclude.conf").expect("failed to parse excludefile");
    let configfile = configfile::parse_file("config.toml").expect("failed to parse configfile");

    let program: &mut Xdp = ebpf
        .program_mut("wadescan")
        .expect("failed to find ebpf program")
        .try_into()
        .expect("failed to convert program to xdp (how the fuck is this possible)");

    program
        .load()
        .expect("failed to load ebpf program to the kernel");
    program
        .attach(&configfile.sender.interface_name, XdpFlags::default())
        .context("attaching program")
        .or_else(|_| {
            program
                .attach(&configfile.sender.interface_name, XdpFlags::SKB_MODE)
                .context("attaching program via skb")
        })?;

    let ping_data: &[u8] = ping::build_latest_request(
        configfile.ping.protocol_version,
        &configfile.ping.address,
        configfile.ping.port,
    )
    .leak();

    let seed = rand::random();

    let umem_size = configfile.sender.umem_size;
    let layout = Layout::from_size_align(umem_size, 16384).context("validating layout")?;
    let ptr =
        NonNull::slice_from_raw_parts(unsafe { NonNull::new_unchecked(alloc(layout)) }, umem_size);

    let umem = unsafe {
        Umem::new(
            UmemConfig {
                fill_size: 1, // 0 won't work for some reason
                complete_size: configfile.sender.complete_size,
                frame_size: FRAME_SIZE, // anything other than 1 << 12 won't work FOR SOME REASON, that's why it's hardcoded
                headroom: 0,
                flags: 0,
            },
            ptr,
        )
        .expect("failed to create umem")
    };

    let mut iface = IfInfo::invalid();
    iface
        .from_name(
            &CString::new(&*configfile.sender.interface_name)
                .expect("error converting interface name to a cstr"),
        )
        .expect("failed to find interface");

    let sender_sock =
        Socket::with_shared(&iface, &umem).expect("failed to create socket for sender");
    let device = umem
        .fq_cq(&sender_sock)
        .expect("failed to create device queue");

    let sender_rxtx = umem
        .rx_tx(&sender_sock, &SocketConfig {
            rx_size: None,
            tx_size: Some(configfile.sender.tx_size),
            bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP,
        })
        .expect("failed to map rxtx for sender");

    umem.bind(&sender_rxtx)
        .expect("failed to bind sender rxtx to umem");

    let responder_sock = Socket::new(&iface).expect("failed to create socket for responder");
    let responder_rxtx = umem
        .rx_tx(&responder_sock, &SocketConfig {
            rx_size: None,
            tx_size: Some(configfile.sender.tx_size),
            bind_flags: 0,
        })
        .expect("failed to map rxtx for responder");

    device
        .bind(&responder_rxtx)
        .expect("failed to bind responder to device queue");

    let iface = get_interfaces()
        .into_iter()
        .find(|i| i.name == configfile.sender.interface_name)
        .unwrap();
    let source_ip = iface.ipv4.first().unwrap().addr;

    let gateway_mac = iface.gateway.unwrap().mac_addr.octets();
    let interface_mac = iface.mac_addr.unwrap().octets();

    let connections = Arc::new(DashMap::with_hasher(FxBuildHasher));
    let connections_purger = connections.clone();

    let client = Client::with_uri_str(configfile.database.url)
        .await
        .expect("failed to initiate database connection");

    let database = client.database(&configfile.database.name);
    let servers_collection = database.collection(&configfile.database.servers_collection);

    let tx = responder_rxtx
        .map_tx()
        .expect("failed to map tx for responder");

    let response_sender = ResponseSender::new(
        tx,
        &gateway_mac,
        &interface_mac,
        source_ip,
        ping_data,
        &umem,
    );

    let (ping_sender, ping_receiver) = flume::unbounded();
    tokio::spawn(async move {
        let mut responder = Responder::new(
            connections,
            seed,
            ring_buf,
            response_sender,
            ping_sender,
            ping_data,
        )
        .expect("failed to initiate responder");

        loop {
            if responder.tick().await {
                break;
            }
        }

        info!("halting responder...")
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

    tokio::spawn(async move {
        let mut completer = PacketCompleter::new(device, configfile.printer.interval);

        loop {
            completer.tick();
        }
    });

    let ping_receiver_a = ping_receiver.clone();
    tokio::spawn(async move {
        let processor = Processor::new(servers_collection, ping_receiver_a);

        loop {
            if let Err(err) = processor.tick().await {
                error!("Error at database: {}", err);
            };
        }
    });

    // be ready to melt your fucking network!
    let tx = sender_rxtx.map_tx().expect("failed to map tx for scanner");
    let syn_sender = SynSender::new(tx, &gateway_mac, &interface_mac, source_ip, &umem);

    let mut scanner = Scanner::new(seed, excludefile, syn_sender, ping_receiver);

    loop {
        _ = scanner.tick().await;
    }
}
