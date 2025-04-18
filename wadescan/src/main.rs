use std::{io::Error, os::fd::AsRawFd};

use aya::{
    Btf, EbpfLoader,
    maps::XskMap,
    programs::{Xdp, XdpFlags},
};
use default_net::get_default_interface;
use libc::{
    __c_anonymous_xsk_tx_metadata_union, POLLIN, POLLOUT, STDIN_FILENO, XDP_TX_METADATA,
    XDP_TXMD_FLAGS_CHECKSUM, XDP_TXMD_FLAGS_TIMESTAMP, XDP_USE_NEED_WAKEUP, poll, pollfd,
    xsk_tx_metadata, xsk_tx_metadata_request,
};

use crate::{
    checksum::{finalize_checksum, ipv4_sum, tcp_raw_partial},
    xdp::socket::{SocketConfig, UmemConfig, XdpSocket},
};

mod checksum;
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
    0xA8, 0xA1, // source port = 43169
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
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        });
    }

    let mut ebpf = EbpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_global("SOURCE_PORT", &43169u16, true)
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

    let mut xsk = XskMap::try_from(ebpf.map_mut("SOCKS").unwrap()).unwrap();

    let mut socket = XdpSocket::new(
        &SocketConfig {
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            bind_flags: XDP_USE_NEED_WAKEUP,
            interface_index: default_interface.index,
            queue_id: 0,
            busy_poll_budget: None,
        },
        &UmemConfig {
            fill_ring_size: 1024,
            completion_ring_size: 1024,
            chunk_count: 1024,
            chunk_size: 2048,
            headroom: 0,
            flags: 0,
        },
    )
    .unwrap();
    xsk.set(0, &socket, 0).unwrap();

    let source = default_interface.ipv4.first().unwrap().addr.octets();

    let gateway_mac = default_interface.gateway.unwrap().mac_addr.octets();
    let interface_mac = default_interface.mac_addr.unwrap().octets();

    for i in 0..1024 {
        let addr = (i * 2048 + size_of::<xsk_tx_metadata>()) as u64;
        unsafe {
            let desc = socket.desc(i);

            desc.addr = addr;
            desc.len = SYN_PACKET.len() as _;
            desc.options = XDP_TX_METADATA;
        }

        let dest = [78, 189, 59, 154];
        let dest_port = 25565u16;

        let sum = ipv4_sum(&source) + ipv4_sum(&dest);

        let data = socket.get::<u8>(addr as usize).as_ptr();
        unsafe {
            data.copy_from_nonoverlapping(SYN_PACKET.as_ptr(), SYN_PACKET.len());
            data.offset(26).copy_from_nonoverlapping(source.as_ptr(), 4);
            data.offset(30).copy_from_nonoverlapping(dest.as_ptr(), 4);
            data.offset(36)
                .copy_from_nonoverlapping(dest_port.to_be_bytes().as_ptr(), 2);
            data.copy_from_nonoverlapping(gateway_mac.as_ptr(), 6);
            data.offset(6)
                .copy_from_nonoverlapping(interface_mac.as_ptr(), 6);
            data.offset(24)
                .copy_from_nonoverlapping(finalize_checksum(34103 + sum).to_be_bytes().as_ptr(), 2);
            data.offset(50)
                .copy_from_nonoverlapping(tcp_raw_partial(sum, 28).to_be_bytes().as_ptr(), 2);

            data.cast::<xsk_tx_metadata>()
                .sub(1)
                .write_unaligned(xsk_tx_metadata {
                    flags: (XDP_TXMD_FLAGS_CHECKSUM | XDP_TXMD_FLAGS_TIMESTAMP) as _,
                    xsk_tx_metadata_union: __c_anonymous_xsk_tx_metadata_union {
                        request: xsk_tx_metadata_request {
                            csum_start: 34,
                            csum_offset: 16,
                        },
                    },
                });
        }
    }

    let mut fds: [pollfd; 2] = [
        pollfd {
            fd: socket.as_raw_fd(),
            events: POLLOUT,
            revents: 0,
        },
        pollfd {
            fd: STDIN_FILENO,
            events: POLLIN,
            revents: 0,
        },
    ];

    let batch_size = 256;
    let mut outstanding = 1024;
    loop {
        if outstanding > 0 {
            let sent = socket.submit_tx(batch_size);
            if sent != 0 && socket.kick_tx() != 0 {
                panic!("failed to kick tx, error: {:?}", Error::last_os_error());
            }

            outstanding -= sent;
        }

        fds[0].revents = 0;
        if unsafe { poll(fds.as_mut_ptr(), 2, 1000) } < 0 {
            break;
        }

        if fds[1].revents != 0 {
            break;
        }

        if (fds[0].revents & POLLOUT) == 0 {
            println!("spin! outstanding: {outstanding}");

            continue;
        }

        outstanding += socket.complete_tx(batch_size);
    }
}
