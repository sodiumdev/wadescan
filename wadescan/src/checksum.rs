use std::net::Ipv4Addr;
use std::ptr;

#[cfg(target_pointer_width = "64")]
const K: usize = 0xf1357aea2e62a9c5;
#[cfg(target_pointer_width = "32")]
const K: usize = 0x93d765dd;

#[inline(always)]
pub const fn cookie(ip: &Ipv4Addr, port: u16, seed: u64) -> u32 {
    (u32::from_ne_bytes(ip.octets()) as usize).wrapping_mul(K)
        .wrapping_add(port as usize).wrapping_mul(K)
        .wrapping_add(seed as usize).wrapping_mul(K) as u32
}

#[inline(always)]
pub const fn ipv4(header: &[u8]) -> u16 {
    unsafe {
        core::hint::assert_unchecked(header.len() >= 20);
    }

    finalize_checksum(
        u16::from_be_bytes([header[0], header[1]]) as u32
            + u16::from_be_bytes([header[2], header[3]]) as u32
            + u16::from_be_bytes([header[4], header[5]]) as u32
            + u16::from_be_bytes([header[6], header[7]]) as u32
            + u16::from_be_bytes([header[8], header[9]]) as u32
            // skip checksum field
            + u16::from_be_bytes([header[12], header[13]]) as u32
            + u16::from_be_bytes([header[14], header[15]]) as u32
            + u16::from_be_bytes([header[16], header[17]]) as u32
            + u16::from_be_bytes([header[18], header[19]]) as u32
    )
}

#[inline(always)]
const fn finalize_checksum(sum: u32) -> u16 { // i copied this somewhere from stackoverflow - thanks
    let sum = (sum >> 16) + (sum & 0xffff);
    let sum = sum + (sum >> 16);

    !(sum as u16)
}

#[inline(always)]
const fn tcp_sum(data: &[u8]) -> u32 { // gets optimized to SIMD instructions :)
    let len = data.len();
    let data_ptr = data.as_ptr();
    
    let mut sum = 0u32;
    let mut i = 0;
    while (i * 2) + 1 < len {
        sum += u16::from_be(
            unsafe { 
                ptr::read_unaligned(data_ptr.add(i * 2).cast()) 
            }
        ) as u32;

        i += 1;
    }

    if len & 1 != 0 {
        sum += unsafe { (*(data_ptr.add(len - 1))) as u32 } << 8;
    }

    sum
}

#[inline(always)]
const fn ipv4_word_sum(ip: &Ipv4Addr) -> u32 {
    let octets = ip.octets();
    u16::from_be_bytes([octets[0], octets[1]]) as u32
        + u16::from_be_bytes([octets[2], octets[3]]) as u32
}

#[inline(always)]
pub const fn tcp(
    data: &[u8],
    source: &Ipv4Addr,
    destination: &Ipv4Addr
) -> u16 {
    finalize_checksum(
        ipv4_word_sum(source)
            + ipv4_word_sum(destination)
            + 6
            + data.len() as u32
            + tcp_sum(data)
    )
}
