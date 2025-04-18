#![feature(thread_local)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

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
const fn finalize_partial(sum: u32) -> u16 {
    let sum = (sum >> 16) + (sum & 0xffff);
    (sum + (sum >> 16)) as u16
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
const fn ipv4_sum(ip: &[u8; 4]) -> u32 {
    u16::from_be_bytes([ip[0], ip[1]]) as u32 + u16::from_be_bytes([ip[2], ip[3]]) as u32
}

#[inline(always)]
pub const fn tcp(data: &[u8], source: &[u8; 4], destination: &[u8; 4]) -> u16 {
    finalize_checksum(
        ipv4_sum(source) + ipv4_sum(destination) + 6 + data.len() as u32 + tcp_sum(data),
    )
}

#[inline(always)]
pub const fn tcp_raw(data: *const u8, len: usize, source: &[u8; 4], destination: &[u8; 4]) -> u16 {
    finalize_checksum(
        ipv4_sum(source) + ipv4_sum(destination) + 6 + len as u32 + tcp_raw_sum(data, len),
    )
}

#[inline(always)]
pub const fn tcp_raw_partial(len: usize, source: &[u8; 4], destination: &[u8; 4]) -> u16 {
    finalize_partial(ipv4_sum(source) + ipv4_sum(destination) + 6 + len as u32)
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ip checksum", |b| {
        let source = black_box([0, 1, 2, 3]);

        b.iter(|| {
            black_box(ipv4_sum(&source));
        });
    });

    group.bench_function("tcp checksum", |b| {
        let a = black_box([12u8; 84]);
        let len = black_box(84);
        let source = black_box([0, 1, 2, 3]);
        let dest = black_box([0, 5, 6, 7]);

        b.iter(|| {
            black_box(tcp_raw(a.as_ptr(), len, &source, &dest));
        });
    });

    group.bench_function("tcp partial checksum", |b| {
        let len = black_box(84);
        let source = black_box([0, 1, 2, 3]);
        let dest = black_box([0, 5, 6, 7]);

        b.iter(|| {
            black_box(tcp_raw_partial(len, &source, &dest));
        });
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
