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
use pnet_base::MacAddr;
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::MutableTcpPacket;
use xdpilone::{BufIdx, Errno, IfInfo, Socket, SocketConfig, Umem, UmemConfig};

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

    let iface = get_interfaces().into_iter()
        .find(|i| i.name == configfile.scanner.interface_name).unwrap();
    let source_ip = iface.ipv4.first().unwrap().addr;

    let gateway_mac = iface.gateway.unwrap().mac_addr.octets();
    let gateway_mac = MacAddr::new(gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]);

    let iface_mac = iface.mac_addr.unwrap().octets();
    let iface_mac = MacAddr::new(iface_mac[0], iface_mac[1], iface_mac[2], iface_mac[3], iface_mac[4], iface_mac[5]);

    let frame_count = umem.len_frames();
    let frames = (0..frame_count).map(|n| {
        let mut frame = umem.frame(BufIdx(n)).unwrap();
        let base = unsafe { frame.addr.as_mut() };

        let (ether_base, base) = base.split_at_mut(14);
        {
            let mut ethernet_packet = MutableEthernetPacket::new(ether_base).unwrap();
            ethernet_packet.set_destination(gateway_mac);
            ethernet_packet.set_source(iface_mac);
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
        tcp_packet.set_payload(ping_data);

        (frame.offset, ipv4_packet, tcp_packet)
    }).collect::<Vec<_>>();

    let sender = Arc::new(PacketSender::new(
        frames,
        source_ip,
        rxtx.map_tx()?,
        ping_data
    ).expect("Error initiating packet sender"));
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

    let mut scanner = Scanner::new(collection, seed, excludefile, sender);
    loop {
        scanner.tick();
    }
}
