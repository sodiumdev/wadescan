use std::{mem::transmute, net::Ipv4Addr};

#[cfg(target_pointer_width = "64")]
const K: usize = 0xf1357aea2e62a9c5;
#[cfg(target_pointer_width = "32")]
const K: usize = 0x93d765dd;

#[inline(always)]
pub const fn cookie(ip: &Ipv4Addr, port: u16, seed: u64) -> u32 {
    (unsafe { transmute::<[u8; 4], u32>(ip.octets()) } as usize)
        .wrapping_mul(K)
        .wrapping_add(port as usize)
        .wrapping_mul(K)
        .wrapping_add(seed as usize)
        .wrapping_mul(K) as u32
}

#[inline(always)]
pub const fn ipv4_sum(ip: &[u8; 4]) -> u32 {
    u16::from_be_bytes([ip[0], ip[1]]) as u32 + u16::from_be_bytes([ip[2], ip[3]]) as u32
}

#[inline(always)]
pub const fn tcp_raw_partial(ipv4_sum: u32, len: usize) -> u16 {
    finalize_partial(ipv4_sum + 6 + len as u32)
}

#[inline(always)]
pub const fn ipv4(ipv4_sum: u32, header: &[u8]) -> u16 {
    unsafe {
        core::hint::assert_unchecked(header.len() == 10);
    }

    finalize_checksum(
        u16::from_be_bytes([header[0], header[1]]) as u32
            + u16::from_be_bytes([header[2], header[3]]) as u32
            + u16::from_be_bytes([header[4], header[5]]) as u32
            + u16::from_be_bytes([header[6], header[7]]) as u32
            + u16::from_be_bytes([header[8], header[9]]) as u32
            // skip checksum field 
            + ipv4_sum,
    )
}

#[inline(always)]
pub const fn finalize_checksum(sum: u32) -> u16 {
    // i copied this somewhere from stackoverflow - thanks
    let sum = (sum >> 16) + (sum & 0xffff);
    let sum = sum + (sum >> 16);

    !(sum as u16)
}

#[inline(always)]
pub const fn finalize_partial(sum: u32) -> u16 {
    let sum = (sum >> 16) + (sum & 0xffff);
    (sum + (sum >> 16)) as u16
}
