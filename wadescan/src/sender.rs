use crate::{checksum, Packet};
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
use pnet_packet::Packet as _Packet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;
use xdpilone::xdp::XdpDesc;
use xdpilone::RingTx;

type Frame<'a> = (u64, MutableIpv4Packet<'a>, MutableTcpPacket<'a>);

struct WrappedTx(RingTx);

unsafe impl Send for WrappedTx {}
unsafe impl Sync for WrappedTx {}

pub struct PacketSender<'a> {
    frames: Vec<Frame<'a>>,
    frame: AtomicUsize,
    
    source_ip: Ipv4Addr,
    tx: RwLock<WrappedTx>,

    ping_data_len: usize
}

impl<'a> PacketSender<'a> {
    #[inline]
    pub fn new(frames: Vec<Frame<'a>>, source_ip: Ipv4Addr, tx: RingTx, ping_data: &'static [u8]) -> Option<Self> {
        Some(Self {
            frames,
            frame: AtomicUsize::new(0),

            source_ip,
            tx: RwLock::new(WrappedTx(tx)),

            ping_data_len: ping_data.len()
        })
    }
    
    #[inline]
    pub async fn send(&self, Packet { ty, ip, port, seq, ack, ping }: Packet) {
        let frames_len = self.frames.len();
        let frame = self.frame.fetch_add(1, Ordering::SeqCst);
        if frame >= frames_len - 1 {
            self.frame.store(0, Ordering::SeqCst);
        }
        
        // SAFETY: too lazy to explain
        let (offset, ipv4_packet, tcp_packet) = unsafe { &mut *(self.frames.as_ptr() as *mut Frame).add(frame) };

        let tcp_packet_len = if ty == TcpFlags::SYN {
            tcp_packet.set_data_offset(7);
            tcp_packet.set_options(&[TcpOption::mss(1340), TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()]);

            28
        } else {
            tcp_packet.set_data_offset(5);
            tcp_packet.set_options(&[]);

            20
        } + if ping { self.ping_data_len } else { 0 };

        tcp_packet.set_checksum(0);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(seq);
        tcp_packet.set_acknowledgement(ack);
        tcp_packet.set_flags(ty);

        tcp_packet.set_checksum(checksum::tcp(tcp_packet.packet().as_ptr(), tcp_packet_len, &self.source_ip, &ip));

        ipv4_packet.set_destination(ip);
        ipv4_packet.set_total_length((20 + tcp_packet_len) as u16);
        ipv4_packet.set_checksum(
            checksum::ipv4(ipv4_packet.packet())
        );

        let tx = &mut self.tx.write().await.0;

        {
            let mut writer = tx.transmit(1);
            writer.insert_once(XdpDesc {
                addr: *offset,
                len: (34 + tcp_packet_len) as u32,
                options: 0
            });

            writer.commit();
        }

        if tx.needs_wakeup() {
            tx.wake();
        }
    }
}

