#![feature(slice_index_methods)]

use std::{
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use aya::{
    Btf, EbpfLoader,
    programs::{Xdp, XdpFlags},
};
use default_net::get_default_interface;
use libc::{
    __c_anonymous_xsk_tx_metadata_union, F_SETFL, O_NONBLOCK, POLLOUT, XDP_TX_METADATA,
    XDP_TXMD_FLAGS_CHECKSUM, XDP_UMEM_TX_METADATA_LEN, XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY, fcntl,
    poll, pollfd, xsk_tx_metadata, xsk_tx_metadata_request,
};
use perfect_rand::PerfectRng;
use rand::random;

use crate::{
    checksum::{finalize_checksum, ipv4_sum, tcp_raw_partial},
    xdp::{
        libc::Umem,
        socket::{UmemOptions, XdpSocket},
    },
};

mod checksum;
mod configfile;
mod xdp;

static SYN_PACKET: [u8; 62] = [
    // ETHER : [0..14]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (dst mac) : [0..6]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (src mac) : [6..12]
    0x08, 0x00, // proto
    // IP : [14..34]
    0x45, 0x00, 0x00, 0x30, // version etc
    0x00, 0x01, 0x00, 0x00, // more irrelevant stuff
    0x40, 0x06, // ttl, protocol = TCP
    0x00, 0x00, // [checksum] : [24..26]
    0, 0, 0, 0, // [src ip] : [26..30]
    0, 0, 0, 0, // [dst ip] : [30..34]
    // TCP : [34..62]
    0x00, 0x00, // [dst port] : [34..36]
    0x00, 0x00, // [dst port] : [36..38]
    0x00, 0x00, 0x00, 0x00, // [sequence number] : [38..42]
    0x00, 0x00, 0x00, 0x00,       // [acknowledgment number] : [42..46]
    0x70,       // data offset
    0b00000010, // flags = SYN
    0x80, 0x00, // window size = 32768
    0x00, 0x00, // [checksum] : [50..52]
    0x00, 0x00, // urgent pointer = 0
    // TCP OPTIONS
    0x02, 0x04, 0x05, 0x3C, // mss: 1340
    0x01, 0x01, // nop + nop
    0x04, 0x02, // sack-perm
];

#[tokio::main]
async fn main() {
    unsafe {
        // set resource limit to infinity
        // oom go brr
        libc::setrlimit(
            libc::RLIMIT_MEMLOCK,
            &libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            },
        );
    }

    let configfile = configfile::parse("config.toml").expect("Error parsing config.toml");

    let source_port = configfile.scanner.source_port;
    let mut ebpf = EbpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_global("SOURCE_PORT", &source_port, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/wadescan"
        )))
        .expect("failed to load ebpf");

    _ = aya_log::EbpfLogger::init(&mut ebpf);

    let default_interface = get_default_interface().unwrap();
    let program: &mut Xdp = ebpf
        .program_mut("wadescan")
        .expect("failed to find ebpf program")
        .try_into()
        .expect("failed to convert program to xdp (how the fuck is this possible)");

    program
        .load()
        .expect("failed to load ebpf program to the kernel");
    program
        .attach(&default_interface.name, XdpFlags::SKB_MODE)
        .unwrap();

    let mut umem = Umem::new(&UmemOptions {
        chunk_count: configfile.scanner.xdp.umem.chunk_count,
        chunk_size: configfile.scanner.xdp.umem.chunk_size as u32,
        headroom: 0,
        flags: XDP_UMEM_TX_METADATA_LEN,
    })
    .expect("failed to create UMEM");

    let socket = XdpSocket::new().expect("failed to create XDP socket");

    let mut frcr = socket
        .frcr(
            &umem,
            configfile.scanner.xdp.ring.fill,
            configfile.scanner.xdp.ring.completion,
        )
        .unwrap_or_else(|e| {
            println!("failed to create frcr, trying without XDP_UMEM_TX_METADATA_LEN flag: {e:?}");

            umem.reset_flags();
            socket
                .frcr(
                    &umem,
                    configfile.scanner.xdp.ring.fill,
                    configfile.scanner.xdp.ring.completion,
                )
                .expect("failed to create frcr, weird")
        });

    let mut rxtx = socket
        .rxtx(
            configfile.scanner.xdp.ring.rx,
            configfile.scanner.xdp.ring.tx,
        )
        .expect("failed to create rxtx, maybe your ring sizes are off?");

    let batch_size = configfile.scanner.xdp.socket.busy_poll_budget;
    socket
        .busy_poll(batch_size)
        .expect("failed to set busy poll budget");

    unsafe {
        fcntl(socket.as_raw_fd(), F_SETFL, O_NONBLOCK);
    }

    socket.bind(
        XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
        default_interface.index,
        0,
        0,
    ).unwrap_or_else(|e| {
        println!("failed to bind XDP socket, trying without XDP_ZEROCOPY flag (should be a little slower): {e:?}");

        socket.bind(
            XDP_USE_NEED_WAKEUP,
            default_interface.index,
            0,
            0,
        ).expect("failed to bind XDP socket")
    });

    let source_ip = default_interface.ipv4.first().unwrap().addr.octets();

    let gateway_mac = default_interface.gateway.unwrap().mac_addr.octets();
    let interface_mac = default_interface.mac_addr.unwrap().octets();

    for i in 0..configfile.scanner.xdp.umem.chunk_count {
        let addr = (i * configfile.scanner.xdp.umem.chunk_size as u32 as usize
            + size_of::<xsk_tx_metadata>()) as u64;
        let desc = &mut rxtx[i as u64];

        desc.addr = addr;
        desc.len = SYN_PACKET.len() as u32;
        desc.options |= XDP_TX_METADATA;

        let frame = &mut umem[addr as usize..];

        frame[..SYN_PACKET.len()].copy_from_slice(&SYN_PACKET);
        frame[..6].copy_from_slice(&gateway_mac);
        frame[6..12].copy_from_slice(&interface_mac);
        frame[26..30].copy_from_slice(&source_ip);
        frame[34..36].copy_from_slice(&source_port.to_be_bytes());

        unsafe {
            frame
                .as_mut_ptr()
                .cast::<xsk_tx_metadata>()
                .sub(1)
                .write(xsk_tx_metadata {
                    flags: XDP_TXMD_FLAGS_CHECKSUM as _,
                    xsk_tx_metadata_union: __c_anonymous_xsk_tx_metadata_union {
                        request: xsk_tx_metadata_request {
                            csum_start: 34,
                            csum_offset: 16,
                        },
                    },
                });
        }
    }

    let mut last_print = Instant::now();
    let mut completed = 0;
    let mut total_sent = 0u64;

    let source_sum = ipv4_sum(&source_ip);
    let checksum_base = 34103 + source_sum;

    let rng = PerfectRng::new(u32::MAX as u64, random(), 4);

    let mut fd = pollfd {
        fd: socket.as_raw_fd(),
        events: POLLOUT,
        revents: 0,
    };

    let batch_size = batch_size as u32;
    let mut outstanding = configfile.scanner.xdp.umem.chunk_count as isize;
    loop {
        let elapsed = last_print.elapsed();
        if elapsed > Duration::from_secs(5) {
            println!("pps: {}", completed as f64 / elapsed.as_secs_f64());
            last_print = Instant::now();

            completed = 0;
        }

        fd.revents = 0;
        if unsafe { poll(&raw mut fd, 1, 0) } < 0 {
            break;
        }

        if (fd.revents & POLLOUT) == 0 {
            continue;
        }

        if outstanding > 0 {
            if let Some(index) = rxtx.tx.reserve(batch_size) {
                for offset in 0..batch_size {
                    let index = index + offset;

                    let desc = &rxtx[index as u64];
                    let frame = &mut umem[desc.addr as usize..];

                    let dest_ip = (rng.shuffle(total_sent + offset as u64) as u32).to_be_bytes();
                    let dest_port = 25565u16;

                    let dest_sum = ipv4_sum(&dest_ip);

                    frame[30..34].copy_from_slice(&dest_ip);
                    frame[36..38].copy_from_slice(&dest_port.to_be_bytes());
                    frame[24..26].copy_from_slice(
                        &finalize_checksum(checksum_base + dest_sum).to_be_bytes(),
                    );
                    frame[50..52]
                        .copy_from_slice(&tcp_raw_partial(source_sum + dest_sum, 28).to_be_bytes());
                }

                rxtx.tx.submit(batch_size);

                total_sent = total_sent.wrapping_add(batch_size as u64);
                outstanding -= batch_size as isize;
            }
        }

        let c = frcr.complete(batch_size);
        completed += c;
        outstanding += c as isize;
    }
}
