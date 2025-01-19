#![no_std]

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum PacketType {
    SynAck = 0,
    Syn = 1,
    Ack = 2,
    Rst = 3,
    Fin = 4,
    PshAck = 5,
}

#[repr(C, packed)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct PacketHeader {
    pub ty: PacketType,
    pub ip: u32,
    pub port: u16,
    pub seq: u32,
    pub ack: u32,
}

impl PacketHeader {
    pub const LEN: usize = size_of::<PacketHeader>();
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketType {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketHeader {}
