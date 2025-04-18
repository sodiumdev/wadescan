#![no_std]
#![no_main]

use core::{mem::offset_of, ptr, ptr::read_volatile};

use aya_ebpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    helpers::bpf_xdp_load_bytes,
    macros::{map, xdp},
    maps::{RingBuf, XskMap},
    programs::XdpContext,
};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};
use wadescan_common::{PacketHeader, PacketType};

#[map]
static SOCKS: XskMap = XskMap::with_max_entries(1, 0);

#[unsafe(no_mangle)]
static SOURCE_PORT: u16 = 0;

#[xdp]
pub fn wadescan(ctx: XdpContext) -> u32 {
    try_receive(ctx).unwrap_or_else(|ret| ret)
}

#[inline(always)]
fn try_receive(ctx: XdpContext) -> Result<u32, u32> {
    let source_port = unsafe { read_volatile(&SOURCE_PORT) };
    if source_port == 0 {
        error!(&ctx, "Source port not set");
        return Err(XDP_PASS);
    }

    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(XDP_PASS);
    }

    let ip_hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    if unsafe { (*ip_hdr).proto } != IpProto::Tcp {
        return Ok(XDP_PASS);
    }

    let tcp_hdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    if unsafe { (*tcp_hdr).dest } != source_port {
        return Err(XDP_PASS);
    }

    if unsafe { (*tcp_hdr).rst() } == 0 {
        return Ok(XDP_DROP);
    }

    /*SOCKS.redirect(
        0, // unsafe { &*ctx.ctx }.rx_queue_index,
        XDP_DROP as u64
    )*/

    Ok(XDP_PASS)
}

#[inline]
const fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = unsafe { &*ctx.ctx }.data as usize;
    let end = unsafe { &*ctx.ctx }.data_end as usize;

    let addr = start + offset;
    if addr + size_of::<T>() > end {
        return Err(XDP_PASS);
    }

    Ok(addr as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
