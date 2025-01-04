use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};

use std::net::Ipv4Addr;

#[cfg(target_pointer_width = "64")]
const K: usize = 0xf1357aea2e62a9c5;
#[cfg(target_pointer_width = "32")]
const K: usize = 0x93d765dd;

#[inline(always)]
const fn finalize_checksum(sum: u32) -> u16 {
    let sum = (sum >> 16) + (sum & 0xffff);
    let sum = sum + (sum >> 16);

    !(sum as u16)
}

#[inline(always)]
const fn tcp_sum(data: &[u8]) -> u32 {
    let len = data.len();

    let mut sum = 0u32;
    let mut i = 0;
    while (i * 2) + 1 < len {
        sum += u16::from_be_bytes([data[i * 2], data[(i * 2) + 1]]) as u32;

        i += 1;
    }

    if len & 1 != 0 {
        sum += (*data.last().unwrap() as u32) << 8;
    }

    sum
}

#[inline(always)]
const fn tcp_raw_sum(data: *const u8, len: usize) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while len >= (i + 1) * 2 {
        sum += u16::from_be(unsafe { *(data.add(i * 2).cast()) }) as u32;

        i += 1;
    }

    if len & 1 != 0 {
        sum += unsafe { (*(data.add(len - 1))) as u32 } << 8;
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

#[inline(always)]
pub const fn tcp_raw(
    data: *const u8,
    len: usize,
    source: &Ipv4Addr,
    destination: &Ipv4Addr
) -> u16 {
    finalize_checksum(
        ipv4_word_sum(source)
            + ipv4_word_sum(destination)
            + 6
            + len as u32
            + tcp_raw_sum(data, len)
    )
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("tcp checksum", |b| {
        b.iter(|| {
            let a = black_box([0u8; 84]);
            let len = black_box(62);
            let source = black_box(Ipv4Addr::new(0, 1, 2, 3));
            let dest = black_box(Ipv4Addr::new(0, 5, 6, 7));

            black_box(tcp(
                &a[..len],
                &source,
                &dest
            ));
        });
    });

    c.bench_function("tcp checksum p", |b| {
        b.iter(|| {
            let a = black_box([0u8; 84]);
            let len = black_box(84);
            let source = black_box(Ipv4Addr::new(0, 1, 2, 3));
            let dest = black_box(Ipv4Addr::new(0, 5, 6, 7));

            black_box(tcp(
                &a[..len],
                &source,
                &dest
            ));
        });
    });
    
    c.bench_function("tcp checksum raw", |b| {
        b.iter(|| {
            let a = black_box([0u8; 84]);
            let len = black_box(62);
            let source = black_box(Ipv4Addr::new(0, 1, 2, 3));
            let dest = black_box(Ipv4Addr::new(0, 5, 6, 7));

            black_box(tcp_raw(
                a.as_ptr(),
                len,
                &source,
                &dest
            ));
        });
    });

    c.bench_function("tcp checksum rawp", |b| {
        b.iter(|| {
            let a = black_box([0u8; 84]);
            let len = black_box(84);
            let source = black_box(Ipv4Addr::new(0, 1, 2, 3));
            let dest = black_box(Ipv4Addr::new(0, 5, 6, 7));

            black_box(tcp_raw(
                a.as_ptr(),
                len,
                &source,
                &dest
            ));
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);