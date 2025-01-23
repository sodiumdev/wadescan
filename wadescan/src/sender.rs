use std::{hint, net::Ipv4Addr};

use log::{debug, trace};
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

static OTHER_PACKET: [u8; 58] = [
    // ETHER : [0..14]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (dst mac) : [0..6]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (src mac) : [6..12]
    0x08, 0x00, // proto
    // IP : [14..34]
    0x45, 0x00, 0x00, 0x2C, // version etc
    0x00, 0x01, 0x00, 0x00, // more irrelevant stuff
    0x40, 0x06, // ttl, protocol = TCP
    0x00, 0x00, // [checksum] : [24..26]
    0, 0, 0, 0, // [src ip] : [26..30]
    0, 0, 0, 0, // [dst ip] : [30..34]
    // TCP : [34..58]
    0xA8, 0xA1, // source port = 43169
    0x00, 0x00, // [dst port] : [36..38]
    0x00, 0x00, 0x00, 0x00, // [sequence number] : [38..42]
    0x00, 0x00, 0x00, 0x00,       // [acknowledgment number] : [42..46]
    0x60,       // data offset
    0b00000000, // [flags] : [47]
    0x80, 0x00, // window size = 32768
    0x00, 0x00, // [checksum] : [50..52]
    0x00, 0x00, // urgent pointer = 0
    0x01, 0x01, // nop + nop
    0x04, 0x02, // sack-perm
];

type Frame<'a> = (u64, &'a mut [u8]);

struct Tx(RingTx);

unsafe impl Send for Tx {}
unsafe impl Sync for Tx {}

// NOT thread-safe
pub struct SynSender<'a> {
    frames: Vec<Frame<'a>>,
    packet: usize,
    ppf: StrengthReducedUsize,
    len: usize,

    source_ip: Ipv4Addr,
    tx: Tx,
}

impl SynSender<'_> {
    #[inline]
    pub fn new(
        tx: RingTx,
        gateway_mac: &[u8; 6],
        interface_mac: &[u8; 6],
        source_ip: Ipv4Addr,
        umem: &Umem,
    ) -> Self {
        let syn_len = SYN_PACKET.len();
        let ppf = FRAME_SIZE as usize / syn_len;

        let frames = umem.len_frames().div_floor(2);
        let frames = (0..frames)
            .map(|n| {
                let mut frame = umem.frame(BufIdx(n)).unwrap();
                let data = unsafe { frame.addr.as_mut() };

                for packet in 0..ppf {
                    let start = syn_len * packet;

                    data[start..start + syn_len].copy_from_slice(&SYN_PACKET[..]);
                    data[start + 26..start + 30].copy_from_slice(&source_ip.octets());
                    data[start + 6..start + 12].copy_from_slice(interface_mac);
                    data[start..start + 6].copy_from_slice(gateway_mac);
                }

                (frame.offset, data)
            })
            .collect();

        Self {
            frames,
            packet: 0,
            ppf: StrengthReducedUsize::new(ppf),
            len: syn_len,

            source_ip,
            tx: Tx(tx),
        }
    }

    #[inline]
    pub fn send_syn(&mut self, ip: &Ipv4Addr, port: u16, seed: u64) {
        self.packet += 1;

        let mut frame = self.packet / self.ppf;
        if frame >= self.frames.len() {
            self.packet = 0;
            frame = 0;
        }

        // SAFETY: bound checks are done above
        let (addr, frame) = unsafe { &mut *self.frames.as_mut_ptr().add(frame) };

        let start = self.len * (self.packet % self.ppf);

        frame[(start + 30)..(start + 34)].copy_from_slice(&ip.octets());
        frame[(start + 36)..(start + 38)].copy_from_slice(&port.to_be_bytes());
        frame[(start + 38)..(start + 42)]
            .copy_from_slice(&checksum::cookie(ip, port, seed).to_be_bytes()); // sequence

        // set checksum to 0
        frame[start + 50] = 0;
        frame[start + 51] = 0;

        // checksum is not skipped while calculating!!!
        {
            let checksum = checksum::tcp(
                &frame[(start + 34)..(start + self.len)],
                &self.source_ip,
                ip,
            );

            frame[(start + 50)..(start + 52)].copy_from_slice(&checksum.to_be_bytes());
        }

        // no need to set the checksum to 0 here because it's skipped while calculating
        {
            let checksum = checksum::ipv4(&frame[(start + 14)..(start + 34)]);

            frame[(start + 24)..(start + 26)].copy_from_slice(&checksum.to_be_bytes());
        }

        {
            let mut writer = self.tx.0.transmit(1);
            writer.insert_once(XdpDesc {
                addr: *addr + start as u64,
                len: self.len as u32,
                options: 0,
            });

            writer.commit();
        }

        if self.tx.0.needs_wakeup() {
            self.tx.0.wake();
        }
    }
}

pub struct ResponseSender<'a> {
    ack_ppf: StrengthReducedUsize,
    ack_frames: Vec<Frame<'a>>,
    ack_packet: usize,
    ack_len: usize,

    fin_ppf: StrengthReducedUsize,
    fin_frames: Vec<Frame<'a>>,
    fin_packet: usize,
    fin_len: usize,

    psh_ppf: StrengthReducedUsize,
    psh_frames: Vec<Frame<'a>>,
    psh_packet: usize,
    psh_len: usize,

    source_ip: Ipv4Addr,

    tx: Tx,
}

impl ResponseSender<'_> {
    #[inline]
    pub fn new(
        tx: RingTx,
        gateway_mac: &[u8; 6],
        interface_mac: &[u8; 6],
        source_ip: Ipv4Addr,
        ping_data: &'static [u8],
        umem: &Umem,
    ) -> Self {
        let packet_len = OTHER_PACKET.len();
        let packet_ppf = FRAME_SIZE as usize / packet_len;

        let psh_len = packet_len + ping_data.len();

        let frames = umem.len_frames();
        let half = umem.len_frames().div_ceil(2);
        let third_half = half.div_floor(3);

        let ack_end = half + third_half;
        let fin_end = half + 2 * third_half;
        let psh_ppf = FRAME_SIZE as usize / psh_len;

        debug!("ack/fin ppf = {packet_ppf}");
        debug!("psh ppf = {psh_ppf}");

        Self {
            ack_ppf: StrengthReducedUsize::new(packet_ppf),
            ack_frames: (half..ack_end)
                .map(|n| {
                    let mut frame = umem.frame(BufIdx(n)).unwrap();
                    let base = unsafe { frame.addr.as_mut() };

                    for packet in 0..64 {
                        let start = packet_len * packet;

                        base[start..(start + packet_len)].copy_from_slice(&OTHER_PACKET[..]);

                        base[start..(start + 6)].copy_from_slice(gateway_mac);
                        base[(start + 6)..(start + 12)].copy_from_slice(interface_mac);
                        base[(start + 26)..(start + 30)].copy_from_slice(&source_ip.octets());
                        base[start + 47] = 0b00010000;
                    }

                    (frame.offset, base)
                })
                .collect(),
            ack_packet: 0,
            ack_len: packet_len,

            fin_ppf: StrengthReducedUsize::new(packet_ppf),
            fin_frames: (ack_end..fin_end)
                .map(|n| {
                    let mut frame = umem.frame(BufIdx(n)).unwrap();
                    let base = unsafe { frame.addr.as_mut() };

                    for packet in 0..64 {
                        let start = packet_len * packet;

                        base[start..(start + packet_len)].copy_from_slice(&OTHER_PACKET[..]);

                        base[start..(start + 6)].copy_from_slice(gateway_mac);
                        base[(start + 6)..(start + 12)].copy_from_slice(interface_mac);
                        base[(start + 26)..(start + 30)].copy_from_slice(&source_ip.octets());
                        base[start + 47] = 0b00000001;
                    }

                    (frame.offset, base)
                })
                .collect(),
            fin_packet: 0,
            fin_len: packet_len,

            psh_ppf: StrengthReducedUsize::new(psh_ppf),
            psh_frames: (fin_end..frames)
                .map(|n| {
                    let mut frame = umem.frame(BufIdx(n)).unwrap();
                    let base = unsafe { frame.addr.as_mut() };

                    for packet in 0..psh_ppf {
                        let start = psh_len * packet;

                        base[start..(start + packet_len)].copy_from_slice(&OTHER_PACKET[..]);
                        base[(start + packet_len)..(start + psh_len)].copy_from_slice(ping_data);
                        base[(start + 26)..(start + 30)].copy_from_slice(&source_ip.octets());
                        base[(start + 6)..(start + 12)].copy_from_slice(interface_mac);
                        base[start..(start + 6)].copy_from_slice(gateway_mac);
                        base[start + 47] = 0b00011000;
                        base[start + 17] = 44 + ping_data.len() as u8;
                    }

                    (frame.offset, base)
                })
                .collect(),
            psh_packet: 0,
            psh_len,

            source_ip,

            tx: Tx(tx),
        }
    }

    #[inline]
    pub fn send_ack(&mut self, ip: &Ipv4Addr, port: u16, seq: u32, ack: u32) {
        trace!("sending ACK packet to {ip}:{port} with seq:{seq}/ack:{ack}");

        self.ack_packet += 1;

        let mut ack_frame = self.ack_packet / self.ack_ppf;
        if ack_frame >= self.ack_frames.len() {
            self.ack_packet = 0;
            ack_frame = 0;
        }

        // SAFETY: bound checks are done above
        let (addr, ack_frame) = unsafe { &mut *self.ack_frames.as_mut_ptr().add(ack_frame) };

        let start = self.ack_len * (self.ack_packet % self.ack_ppf);

        ack_frame[(start + 30)..(start + 34)].copy_from_slice(&ip.octets());
        ack_frame[(start + 36)..(start + 38)].copy_from_slice(&port.to_be_bytes());
        ack_frame[(start + 38)..(start + 42)].copy_from_slice(&seq.to_be_bytes());
        ack_frame[(start + 42)..(start + 46)].copy_from_slice(&ack.to_be_bytes());
        ack_frame[start + 47] = 0b00010000;

        // set checksum to 0
        ack_frame[start + 50] = 0;
        ack_frame[start + 51] = 0;

        // checksum is not skipped while calculating!!!
        {
            let checksum = checksum::tcp(
                &ack_frame[(start + 34)..(start + self.ack_len)],
                &self.source_ip,
                ip,
            );

            ack_frame[(start + 50)..(start + 52)].copy_from_slice(&checksum.to_be_bytes());
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
                len: self.ack_len as u32,
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
        trace!("sending PSH packet to {ip}:{port} with seq:{seq}/ack:{ack}");

        self.psh_packet += 1;

        let mut psh_frame = self.psh_packet / self.psh_ppf;
        if psh_frame >= self.psh_frames.len() {
            self.psh_packet = 0;
            psh_frame = 0;
        }

        // SAFETY: bound checks are done above
        let (addr, psh_frame) = unsafe { &mut *self.psh_frames.as_mut_ptr().add(psh_frame) };

        let start = self.psh_len * (self.psh_packet % self.psh_ppf);

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
                &psh_frame[(start + 34)..(start + self.psh_len)],
                &self.source_ip,
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
                addr: *addr + start as u64,
                len: self.psh_len as u32,
                options: 0,
            });

            writer.commit();
        }
    }

    #[inline]
    pub fn send_fin(&mut self, ip: &Ipv4Addr, port: u16, seq: u32, ack: u32) {
        trace!("sending FIN packet to {ip}:{port} with seq:{seq}/ack:{ack}");

        self.fin_packet += 1;

        let mut fin_frame = self.fin_packet / self.fin_ppf;
        if fin_frame >= self.fin_frames.len() {
            self.fin_packet = 0;
            fin_frame = 0;
        }

        // SAFETY: bound checks are done above
        let (addr, fin_frame) = unsafe { &mut *self.fin_frames.as_mut_ptr().add(fin_frame) };

        let start = self.fin_len * (self.fin_packet % self.fin_ppf);

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
                &fin_frame[(start + 34)..(start + self.fin_len)],
                &self.source_ip,
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
                len: self.fin_len as u32,
                options: 0,
            });

            writer.commit();
        }
    }
}
