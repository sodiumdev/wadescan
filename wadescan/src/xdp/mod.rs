pub mod libc;
pub mod ring;
pub mod socket;

#[cfg(test)]
mod tests {
    use std::mem;

    use libc::{xdp_mmap_offsets, xdp_ring_offset, xdp_umem_reg, xsk_tx_metadata};

    use crate::xdp::{
        libc::{MmapOffsets, RingAddressOffsets, Umem},
        socket::UmemConfig,
    };

    #[test]
    pub fn test_sizes() {
        assert_eq!(size_of::<Umem>(), size_of::<xdp_umem_reg>());
        assert_eq!(
            size_of::<RingAddressOffsets>(),
            size_of::<xdp_ring_offset>()
        );
        assert_eq!(size_of::<MmapOffsets>(), size_of::<xdp_mmap_offsets>());
    }

    #[test]
    pub fn test_umem_compat() {
        let umem = Umem::new(&UmemConfig {
            fill_ring_size: 1024,
            completion_ring_size: 1024,
            chunk_count: 1024,
            chunk_size: 2048,
            headroom: 0,
            flags: 0,
        })
        .unwrap();

        assert_eq!(size_of::<Umem>(), size_of::<xdp_umem_reg>());
        assert_eq!(align_of::<Umem>(), align_of::<xdp_umem_reg>());

        let umem_reg = xdp_umem_reg {
            addr: umem.mmap.area.as_ptr() as _,
            len: 1024 * 2048,
            chunk_size: 2048,
            headroom: 0,
            flags: 0,
            tx_metadata_len: size_of::<xsk_tx_metadata>() as u32,
        };

        let mut diff = 0;
        unsafe {
            for (i, (a, b)) in mem::transmute::<libc::xdp_umem_reg, [u8; 32]>(umem_reg)
                .iter()
                .zip(mem::transmute::<Umem<'_>, [u8; 32]>(umem).iter())
                .enumerate()
            {
                if *a != *b {
                    println!("{i}: {a}, {b}");
                    diff += 1;
                }
            }
        }

        println!("diff: {}", diff);
    }
}
