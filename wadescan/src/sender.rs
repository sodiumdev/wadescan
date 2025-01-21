use std::net::Ipv4Addr;

use strength_reduce::StrengthReducedUsize;
use xdpilone::{xdp::XdpDesc, BufIdx, RingTx, Umem};

use crate::{checksum, FRAME_SIZE};

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

static OTHER_PACKET: [u8; 54] = [
    // ETHER : [0..14]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (dst mac) : [0..6]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (src mac) : [6..12]
    0x08, 0x00, // proto
    // IP : [14..34]
    0x45, 0x00, 0x00, 0x28, // version etc
    0x00, 0x01, 0x00, 0x00, // more irrelevant stuff
    0x40, 0x06, // ttl, protocol = TCP
    0x00, 0x00, // [checksum] : [24..26]
    0, 0, 0, 0, // [src ip] : [26..30]
    0, 0, 0, 0, // [dst ip] : [30..34]
    // TCP : [34..54]
    0xA8, 0xA1, // source port = 43169
    0x00, 0x00, // [dst port] : [36..38]
    0x00, 0x00, 0x00, 0x00, // [sequence number] : [38..42]
    0x00, 0x00, 0x00, 0x00,       // [acknowledgment number] : [42..46]
    0x50,       // data offset
    0b00000000, // [flags] : [47]
    0x80, 0x00, // window size = 32768
    0x00, 0x00, // [checksum] : [50..52]
    0x00, 0x00, // urgent pointer = 0
];

type Frame<'a> = (u64, &'a mut [u8]);

struct Tx(RingTx);

unsafe impl Send for Tx {}
unsafe impl Sync for Tx {}

#[repr(u8)]
pub enum SenderKind {
    Scanner,
    Responder,
}

pub struct Frames<'a> {
    // ppf = packets per frame
    psh_ppf: StrengthReducedUsize,

    syn_frames: Vec<Frame<'a>>,
    ack_frames: Vec<Frame<'a>>,
    psh_frames: Vec<Frame<'a>>,
    fin_frames: Vec<Frame<'a>>,

    source_ip: Ipv4Addr,
    ping_data_len: u32,
}

// NOT thread-safe
pub struct PacketSender<'a> {
    frames: Frames<'a>,

    syn_packet: usize,
    ack_packet: usize,
    psh_packet: usize,
    fin_packet: usize,

    tx: Tx,
}

impl<'a> PacketSender<'a> {
    #[inline]
    pub fn new(tx: RingTx, frames: Frames<'a>) -> Option<Self> {
        Some(Self {
            frames,

            syn_packet: 0,
            ack_packet: 0,
            psh_packet: 0,
            fin_packet: 0,

            tx: Tx(tx),
        })
    }

    #[inline]
    pub fn frames(
        kind: SenderKind,
        gateway_mac: &[u8; 6],
        interface_mac: &[u8; 6],
        source_ip: Ipv4Addr,
        umem: &Umem,
        ping_data: &'static [u8],
    ) -> Frames<'a> {
        let offset = match kind {
            SenderKind::Scanner => 0,
            SenderKind::Responder => umem.len_frames() / 4,
        };

        let frames = umem.len_frames() / 8;

        let psh_ppf = (FRAME_SIZE as usize).div_floor(54 + ping_data.len());

        Frames {
            psh_ppf: StrengthReducedUsize::new(psh_ppf),

            syn_frames: Self::syn_frames(
                offset,
                frames,
                gateway_mac,
                interface_mac,
                &source_ip,
                umem,
            ),
            ack_frames: Self::ack_frames(
                offset,
                frames,
                gateway_mac,
                interface_mac,
                &source_ip,
                umem,
            ),
            psh_frames: Self::psh_frames(
                offset,
                frames,
                psh_ppf,
                gateway_mac,
                interface_mac,
                &source_ip,
                umem,
                ping_data,
            ),
            fin_frames: Self::fin_frames(
                offset,
                frames,
                gateway_mac,
                interface_mac,
                &source_ip,
                umem,
            ),

            source_ip,
            ping_data_len: ping_data.len() as u32,
        }
    }

    #[inline]
    fn syn_frames(
        offset: u32,
        frames: u32,
        gateway_mac: &[u8; 6],
        interface_mac: &[u8; 6],
        source_ip: &Ipv4Addr,
        umem: &Umem,
    ) -> Vec<Frame<'a>> {
        (offset..(frames + offset))
            .map(|n| {
                let mut frame = umem.frame(BufIdx(n)).unwrap();
                let base = unsafe { frame.addr.as_mut() };

                for packet in 0..64 {
                    let start = 62 * packet;

                    base[start..(start + 62)].copy_from_slice(&SYN_PACKET[..]);

                    base[start..(start + 6)].copy_from_slice(gateway_mac);
                    base[(start + 6)..(start + 12)].copy_from_slice(interface_mac);
                    base[(start + 26)..(start + 30)].copy_from_slice(&source_ip.octets());
                }

                (frame.offset, base)
            })
            .collect::<Vec<_>>()
    }

    #[inline]
    fn ack_frames(
        offset: u32,
        frames: u32,
        gateway_mac: &[u8; 6],
        interface_mac: &[u8; 6],
        source_ip: &Ipv4Addr,
        umem: &Umem,
    ) -> Vec<Frame<'a>> {
        ((frames + offset)..(frames * 2 + offset))
            .map(|n| {
                let mut frame = umem.frame(BufIdx(n)).unwrap();
                let base = unsafe { frame.addr.as_mut() };

                for packet in 0..64 {
                    let start = 54 * packet;

                    base[start..(start + 54)].copy_from_slice(&OTHER_PACKET[..]);

                    base[start..(start + 6)].copy_from_slice(gateway_mac);
                    base[(start + 6)..(start + 12)].copy_from_slice(interface_mac);
                    base[(start + 26)..(start + 30)].copy_from_slice(&source_ip.octets());
                    base[start + 47] = 0b00010000;
                }

                (frame.offset, base)
            })
            .collect::<Vec<_>>()
    }

    #[inline]
    fn psh_frames(
        offset: u32,
        frames: u32,
        ppf: usize,
        gateway_mac: &[u8; 6],
        interface_mac: &[u8; 6],
        source_ip: &Ipv4Addr,
        umem: &Umem,
        ping_data: &'static [u8],
    ) -> Vec<Frame<'a>> {
        ((frames * 2 + offset)..(frames * 3 + offset))
            .map(|n| {
                let mut frame = umem.frame(BufIdx(n)).unwrap();
                let base = unsafe { frame.addr.as_mut() };

                for packet in 0..ppf {
                    let start = 54 * packet;
                    let end = start + 54;

                    base[start..end].copy_from_slice(&OTHER_PACKET[..]);

                    base[start..(start + 6)].copy_from_slice(gateway_mac);
                    base[(start + 6)..(start + 12)].copy_from_slice(interface_mac);
                    base[(start + 26)..(start + 30)].copy_from_slice(&source_ip.octets());
                    base[start + 47] = 0b00010000;
                    base[end..(end + ping_data.len())].copy_from_slice(ping_data);
                }

                (frame.offset, base)
            })
            .collect::<Vec<_>>()
    }

    #[inline]
    fn fin_frames(
        offset: u32,
        frames: u32,
        gateway_mac: &[u8; 6],
        interface_mac: &[u8; 6],
        source_ip: &Ipv4Addr,
        umem: &Umem,
    ) -> Vec<Frame<'a>> {
        ((frames * 3 + offset)..(frames * 4 + offset))
            .map(|n| {
                let mut frame = umem.frame(BufIdx(n)).unwrap();
                let base = unsafe { frame.addr.as_mut() };

                for packet in 0..64 {
                    let start = 54 * packet;

                    base[start..(start + 54)].copy_from_slice(&OTHER_PACKET[..]);

                    base[start..(start + 6)].copy_from_slice(gateway_mac);
                    base[(start + 6)..(start + 12)].copy_from_slice(interface_mac);
                    base[(start + 26)..(start + 30)].copy_from_slice(&source_ip.octets());
                    base[start + 47] = 0b00010000;
                }

                (frame.offset, base)
            })
            .collect::<Vec<_>>()
    }

    #[inline]
    pub fn send_syn(&mut self, ip: &Ipv4Addr, port: u16, seed: u64) {
        self.syn_packet += 1;

        let mut syn_frame = self.syn_packet >> 6;
        if syn_frame >= self.frames.syn_frames.len() {
            self.syn_packet = 0;
            syn_frame = 0;
        }

        // SAFETY: bound checks are done above
        let (addr, syn_frame) = unsafe { &mut *self.frames.syn_frames.as_mut_ptr().add(syn_frame) };

        let start = 62 * (self.syn_packet % 63);

        syn_frame[(start + 30)..(start + 34)].copy_from_slice(&ip.octets());
        syn_frame[(start + 36)..(start + 38)].copy_from_slice(&port.to_be_bytes());
        syn_frame[(start + 38)..(start + 42)]
            .copy_from_slice(&checksum::cookie(ip, port, seed).to_be_bytes()); // sequence

        // set checksum to 0
        syn_frame[start + 50] = 0;
        syn_frame[start + 51] = 0;

        // checksum is not skipped while calculating!!!
        {
            let checksum = checksum::tcp(
                &syn_frame[(start + 34)..(start + 62)],
                &self.frames.source_ip,
                ip,
            );

            syn_frame[(start + 50)..(start + 52)].copy_from_slice(&checksum.to_be_bytes());
        }

        // no need to set the checksum to 0 here because it's skipped while calculating
        {
            let checksum = checksum::ipv4(&syn_frame[(start + 14)..(start + 34)]);

            syn_frame[(start + 24)..(start + 26)].copy_from_slice(&checksum.to_be_bytes());
        }

        {
            let mut writer = self.tx.0.transmit(1);
            writer.insert_once(XdpDesc {
                addr: *addr + start as u64,
                len: 62,
                options: 0,
            });

            writer.commit();
        }

        if self.tx.0.needs_wakeup() {
            self.tx.0.wake();
        }
    }

    #[inline]
    pub fn send_ack(&mut self, ip: &Ipv4Addr, port: u16, seq: u32, ack: u32) {
        self.ack_packet += 1;

        let mut ack_frame = self.ack_packet >> 6;
        if ack_frame >= self.frames.ack_frames.len() {
            self.ack_packet = 0;
            ack_frame = 0;
        }

        // SAFETY: bound checks are done above
        let (addr, ack_frame) = unsafe { &mut *self.frames.ack_frames.as_mut_ptr().add(ack_frame) };

        let start = 62 * (self.ack_packet & 63);

        ack_frame[(start + 30)..(start + 34)].copy_from_slice(&ip.octets());
        ack_frame[(start + 36)..(start + 38)].copy_from_slice(&port.to_be_bytes());
        ack_frame[(start + 38)..(start + 42)].copy_from_slice(&seq.to_be_bytes());
        ack_frame[(start + 42)..(start + 46)].copy_from_slice(&ack.to_be_bytes());

        // set checksum to 0
        ack_frame[start + 50] = 0;
        ack_frame[start + 51] = 0;

        // checksum is not skipped while calculating!!!
        {
            let checksum = checksum::tcp(
                &ack_frame[(start + 34)..(start + 54)],
                &self.frames.source_ip,
                ip,
            );

            ack_frame[50..52].copy_from_slice(&checksum.to_be_bytes());
        }

        // no need to set the checksum to 0 here because it's skipped while calculating
        {
            let checksum = checksum::ipv4(&ack_frame[(start + 14)..(start + 34)]);

            ack_frame[(start + 24)..(start + 26)].copy_from_slice(&checksum.to_be_bytes());
        }

        {
            let mut writer = self.tx.0.transmit(1);
            writer.insert_once(XdpDesc {
                addr: *addr + start as u64,
                len: 54,
                options: 0,
            });

            writer.commit();
        }

        if self.tx.0.needs_wakeup() {
            self.tx.0.wake();
        }
    }

    #[inline]
    pub fn send_psh(&mut self, ip: &Ipv4Addr, port: u16, seq: u32, ack: u32) {
        self.psh_packet += 1;

        let mut psh_frame = self.psh_packet / self.frames.psh_ppf;
        if psh_frame >= self.frames.psh_frames.len() {
            self.psh_packet = 0;
            psh_frame = 0;
        }

        // SAFETY: bound checks are done above
        let (addr, psh_frame) = unsafe { &mut *self.frames.psh_frames.as_mut_ptr().add(psh_frame) };

        let len = 54 + self.frames.ping_data_len;
        let start = len as usize * (self.psh_packet % self.frames.psh_ppf);

        psh_frame[(start + 30)..(start + 34)].copy_from_slice(&ip.octets());
        psh_frame[(start + 36)..(start + 38)].copy_from_slice(&port.to_be_bytes());
        psh_frame[(start + 38)..(start + 42)].copy_from_slice(&seq.to_be_bytes());
        psh_frame[(start + 42)..(start + 46)].copy_from_slice(&ack.to_be_bytes());

        // set checksum to 0
        psh_frame[start + 50] = 0;
        psh_frame[start + 51] = 0;

        // checksum is not skipped while calculating!!!
        {
            let checksum = checksum::tcp(
                &psh_frame[(start + 34)..(start + len as usize)],
                &self.frames.source_ip,
                ip,
            );

            psh_frame[(start + 50)..(start + 52)].copy_from_slice(&checksum.to_be_bytes());
        }

        // no need to set the checksum to 0 here because it's skipped while calculating
        {
            let checksum = checksum::ipv4(&psh_frame[(start + 14)..(start + 34)]);

            psh_frame[(start + 24)..(start + 26)].copy_from_slice(&checksum.to_be_bytes());
        }

        {
            let mut writer = self.tx.0.transmit(1);
            writer.insert_once(XdpDesc {
                addr: *addr,
                len,
                options: 0,
            });

            writer.commit();
        }

        if self.tx.0.needs_wakeup() {
            self.tx.0.wake();
        }
    }

    #[inline]
    pub fn send_fin(&mut self, ip: &Ipv4Addr, port: u16, seq: u32, ack: u32) {
        self.fin_packet += 1;

        let mut fin_frame = self.fin_packet >> 6;
        if fin_frame >= self.frames.fin_frames.len() {
            self.fin_packet = 0;
            fin_frame = 0;
        }

        // SAFETY: bound checks are done above
        let (addr, fin_frame) = unsafe { &mut *self.frames.fin_frames.as_mut_ptr().add(fin_frame) };

        let start = 54 * (self.fin_packet & 63);

        fin_frame[(start + 30)..(start + 34)].copy_from_slice(&ip.octets());
        fin_frame[(start + 36)..(start + 38)].copy_from_slice(&port.to_be_bytes());
        fin_frame[(start + 38)..(start + 42)].copy_from_slice(&seq.to_be_bytes());
        fin_frame[(start + 42)..(start + 46)].copy_from_slice(&ack.to_be_bytes());

        // set checksum to 0
        fin_frame[start + 50] = 0;
        fin_frame[start + 51] = 0;

        // checksum is not skipped while calculating!!!
        {
            let checksum = checksum::tcp(
                &fin_frame[(start + 34)..(start + 54)],
                &self.frames.source_ip,
                ip,
            );

            fin_frame[(start + 50)..(start + 52)].copy_from_slice(&checksum.to_be_bytes());
        }

        // no need to set the checksum to 0 here because it's skipped while calculating
        {
            let checksum = checksum::ipv4(&fin_frame[(start + 14)..(start + 34)]);

            fin_frame[(start + 24)..(start + 26)].copy_from_slice(&checksum.to_be_bytes());
        }

        {
            let mut writer = self.tx.0.transmit(1);
            writer.insert_once(XdpDesc {
                addr: *addr + start as u64,
                len: 54,
                options: 0,
            });

            writer.commit();
        }

        if self.tx.0.needs_wakeup() {
            self.tx.0.wake();
        }
    }
}
