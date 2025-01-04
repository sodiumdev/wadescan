#![no_std]
#![no_main]

use core::ptr;
use aya_ebpf::bindings::xdp_action::XDP_PASS;
use aya_ebpf::helpers::bpf_xdp_load_bytes;
use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use aya_ebpf::{macros::xdp, programs::XdpContext};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use wadescan_common::{PacketHeader, PacketType};

const LEN_SIZE: usize = size_of::<u16>();
const MAX_SIZE: usize = u16::MAX as usize;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size((128 * (PacketHeader::LEN + LEN_SIZE + MAX_SIZE + 8)) as u32, 0);

const PORT: u16 = 61000u16.to_be();

#[xdp]
pub fn wadescan(ctx: XdpContext) -> u32 {
    match try_receive(ctx) {
        Ok(ret) => ret,
        _ => XDP_PASS,
    }
}

#[inline(always)]
fn try_receive(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr = unsafe { ptr_at::<EthHdr>(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(XDP_PASS);
    }

    let ip_hdr = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)? };
    if unsafe { (*ip_hdr).proto } != IpProto::Tcp {
        return Ok(XDP_PASS)
    }

    let tcp_hdr = unsafe { ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    if unsafe { (*tcp_hdr).dest } != PORT {
        return Ok(XDP_PASS)
    }

    let offset = EthHdr::LEN + Ipv4Hdr::LEN + unsafe { (*tcp_hdr).doff() as usize } * 4;
    let start = ctx.data();
    let end = ctx.data_end();

    let addr = start + offset;
    let len = end - addr;

    let (ip, port) = unsafe {
        (u32::from_be((*ip_hdr).src_addr), u16::from_be((*tcp_hdr).source))
    };

    let (seq, ack) = unsafe {
        (u32::from_be((*tcp_hdr).seq), u32::from_be((*tcp_hdr).ack_seq))
    };
    
    output(
        &ctx,
        PacketHeader {
            ty: {
                if unsafe { (*tcp_hdr).rst() } != 0 {
                    return Ok(XDP_PASS)
                } else if unsafe { (*tcp_hdr).fin() } != 0 {
                    PacketType::Fin
                } else if unsafe { (*tcp_hdr).ack() } != 0 {
                    if unsafe { (*tcp_hdr).syn() } != 0 {
                        PacketType::SynAck
                    } else {
                        PacketType::Ack
                    }
                } else { return Ok(XDP_PASS) }
            },
            ip,
            port,
            seq,
            ack,
        },
        offset,
        len
    )
}

#[inline(always)]
const unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = (*ctx.ctx).data as usize;
    let end = (*ctx.ctx).data_end as usize;
    let len = size_of::<T>();

    let addr = start + offset;
    if addr + len > end {
        return Err(());
    }

    Ok(addr as *const T)
}

#[inline(always)]
fn output(ctx: &XdpContext, packet: PacketHeader, offset: usize, len: usize) -> Result<u32, ()> {
    match RING_BUF.reserve::<[u8; PacketHeader::LEN + LEN_SIZE + MAX_SIZE]>(0) {
        Some(mut event) => {
            unsafe {
                ptr::write_unaligned(event.as_mut_ptr() as *mut _, packet);
                ptr::write_unaligned(event.as_mut_ptr().byte_add(PacketHeader::LEN) as *mut _, len as u16);
            }

            if len == 0 {
                event.submit(0);

                return Ok(XDP_PASS);
            }

            if !aya_ebpf::check_bounds_signed(len as i64, 1, MAX_SIZE as i64) {
                event.discard(0);

                return Err(())
            }

            match unsafe { bpf_xdp_load_bytes(
                ctx.ctx,
                offset as u32,
                event.as_mut_ptr().byte_add(PacketHeader::LEN + LEN_SIZE) as *mut _,
                len as u32
            ) } {
                0 => {
                    event.submit(0);
                    Ok(XDP_PASS)
                },

                _ => {
                    event.discard(0);
                    Err(())
                }
            }
        }

        None => Err(())
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
