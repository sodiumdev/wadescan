use std::net::Ipv4Addr;
use std::sync::Arc;
use flume::Receiver;
use pnet_base::MacAddr;
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::Packet as _Packet;
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
use tokio::sync::RwLock;
use xdpilone::{BufIdx, RingTx, Umem};
use xdpilone::xdp::XdpDesc;
use crate::{checksum, Packet};

type Frame<'a> = (u64, MutableIpv4Packet<'a>, MutableTcpPacket<'a>);

pub struct WrappedTx(pub RingTx);

unsafe impl Send for WrappedTx {}
unsafe impl Sync for WrappedTx {}

pub struct PacketSender<'a> {
    frames: Vec<Frame<'a>>,
    frame: usize,
    
    receiver: Receiver<Packet>,
    
    source_ip: Ipv4Addr,
    tx: Arc<RwLock<WrappedTx>>,

    ping_data_len: usize
}

impl<'a> PacketSender<'a> {
    #[inline]
    pub fn generate_frames(n: usize, frame_count: usize, umem: &Umem, interface_mac: &[u8; 6], gateway_mac: &[u8; 6], source_ip: Ipv4Addr, ping_data: &'static [u8]) -> Vec<Frame<'a>> {
        let offset = n * frame_count;
        (0..frame_count)
            .map(|i| {
                let mut frame = umem.frame(BufIdx((offset + i) as u32)).unwrap();
                let base = unsafe { frame.addr.as_mut() };

                let (ether_base, base) = base.split_at_mut(14);
                {
                    let mut ethernet_packet = MutableEthernetPacket::new(ether_base).unwrap();
                    ethernet_packet.set_destination(MacAddr::new(gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]));
                    ethernet_packet.set_source(MacAddr::new(interface_mac[0], interface_mac[1], interface_mac[2], interface_mac[3], interface_mac[4], interface_mac[5]));
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
            })
            .collect::<Vec<_>>()
    }
    
    #[inline]
    pub fn new(frames: Vec<Frame<'a>>, source_ip: Ipv4Addr, tx: Arc<RwLock<WrappedTx>>, receiver: Receiver<Packet>, ping_data: &'static [u8]) -> Option<Self> {
        Some(Self {
            frames,
            frame: 0,
            
            receiver,

            source_ip,
            tx,

            ping_data_len: ping_data.len()
        })
    }
    
    #[inline]
    pub async fn tick(&mut self) {
        let packet = self.receiver.recv_async().await;
        let Ok(Packet { ty, ip, port, seq, ack, ping }) = packet else {
            return
        };
        
        let frames_len = self.frames.len();
        let (offset, ipv4_packet, tcp_packet) = self.frames.get_mut(self.frame).unwrap();

        self.frame += 1;
        if self.frame >= frames_len {
            self.frame = 0;
        }

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

