pub mod libc;
pub mod ring;
pub mod socket;

#[cfg(test)]
mod tests {
    use libc::{xdp_mmap_offsets, xdp_ring_offset, xdp_umem_reg};

    use crate::xdp::libc::{MmapOffsets, RingAddressOffsets, Umem};

    #[test]
    pub fn test_sizes() {
        assert_eq!(size_of::<Umem>(), size_of::<xdp_umem_reg>());
        assert_eq!(
            size_of::<RingAddressOffsets>(),
            size_of::<xdp_ring_offset>()
        );
        assert_eq!(size_of::<MmapOffsets>(), size_of::<xdp_mmap_offsets>());
    }
}
