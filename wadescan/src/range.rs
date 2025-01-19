use std::{mem, net::Ipv4Addr};
use rayon::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRange {
    pub addr_start: Ipv4Addr,
    pub addr_end: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
}

impl ScanRange {
    #[inline(always)]
    pub const fn count_addresses(&self) -> usize {
        (self.addr_end.to_bits() as u64 - self.addr_start.to_bits() as u64 + 1) as usize
    }

    #[inline(always)]
    pub const fn count_ports(&self) -> usize {
        ((self.port_end - self.port_start) + 1) as usize
    }

    #[inline(always)]
    pub const fn count(&self) -> usize {
        self.count_addresses() * self.count_ports()
    }

    #[inline(always)]
    pub const fn index(&self, index: usize) -> (Ipv4Addr, u16) {
        let port_count = self.count_ports();
        let addr_index = index / port_count;
        let port_index = index % port_count;
        let addr = self.addr_start.to_bits() + addr_index as u32;
        let port = self.port_start + port_index as u16;

        (Ipv4Addr::from_bits(addr), port)
    }

    #[inline(always)]
    pub const fn single(addr: Ipv4Addr, port: u16) -> Self {
        Self {
            addr_start: addr,
            addr_end: addr,
            port_start: port,
            port_end: port,
        }
    }

    #[inline(always)]
    pub const fn single_port(addr_start: Ipv4Addr, addr_end: Ipv4Addr, port: u16) -> Self {
        Self {
            addr_start,
            addr_end,
            port_start: port,
            port_end: port,
        }
    }

    #[inline(always)]
    pub const fn single_address(addr: Ipv4Addr, port_start: u16, port_end: u16) -> Self {
        Self {
            addr_start: addr,
            addr_end: addr,
            port_start,
            port_end,
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct ScanRanges {
    /// The ranges in order of `addr_start`.
    ranges: Vec<ScanRange>,
}

impl ScanRanges {
    #[inline]
    pub fn from_excluding(ranges: Vec<ScanRange>, excludes: &Ipv4Ranges) -> Self {
        let mut this = Self { ranges };
        this.apply_exclude(excludes);
        this
    }
    
    #[inline]
    pub fn extend(&mut self, ranges: Vec<ScanRange>) {
        self.ranges.extend(ranges);
        self.ranges.sort_by_key(|r| r.addr_start);
    }

    #[inline]
    pub fn apply_exclude(&mut self, exclude_ranges: &Ipv4Ranges) -> Vec<Ipv4Range> {
        let mut ranges: Vec<ScanRange> = Vec::new();
        let mut removed_ranges: Vec<Ipv4Range> = Vec::new();

        let mut scan_ranges = mem::take(&mut self.ranges).into_iter();
        let mut exclude_ranges = exclude_ranges.ranges.iter();

        let Some(mut scan_range) = scan_ranges.next() else {
            return vec![];
        };
        
        let Some(mut exclude_range) = exclude_ranges.next() else {
            ranges.extend(scan_ranges);
            self.ranges = ranges;
            return vec![];
        };

        loop {
            if scan_range.addr_end < exclude_range.start {
                ranges.push(scan_range);
                scan_range = match scan_ranges.next() {
                    Some(scan_range) => scan_range,
                    None => break
                };
            } else if scan_range.addr_start > exclude_range.end {
                exclude_range = match exclude_ranges.next() {
                    Some(exclude_range) => exclude_range,
                    None => {
                        ranges.push(scan_range);
                        break
                    }
                };
            } else if scan_range.addr_start < exclude_range.start && scan_range.addr_end > exclude_range.end {
                ranges.push(ScanRange {
                    addr_start: scan_range.addr_start,
                    addr_end: Ipv4Addr::from(u32::from(exclude_range.start) - 1),
                    port_start: scan_range.port_start,
                    port_end: scan_range.port_end,
                });
                
                removed_ranges.push(*exclude_range);
                scan_range.addr_start = Ipv4Addr::from(u32::from(exclude_range.end) + 1);
            } else if scan_range.addr_start < exclude_range.start {
                ranges.push(ScanRange {
                    addr_start: scan_range.addr_start,
                    addr_end: Ipv4Addr::from(u32::from(exclude_range.start) - 1),
                    port_start: scan_range.port_start,
                    port_end: scan_range.port_end,
                });
                
                removed_ranges.push(Ipv4Range {
                    start: exclude_range.start,
                    end: scan_range.addr_end,
                });
                
                scan_range = match scan_ranges.next() {
                    Some(scan_range) => scan_range,
                    None => break,
                };
            } else if scan_range.addr_end > exclude_range.end {
                removed_ranges.push(Ipv4Range {
                    start: scan_range.addr_start,
                    end: exclude_range.end,
                });
                scan_range.addr_start = Ipv4Addr::from(u32::from(exclude_range.end) + 1);
            } else {
                removed_ranges.push(Ipv4Range {
                    start: scan_range.addr_start,
                    end: scan_range.addr_end,
                });
                scan_range = match scan_ranges.next() {
                    Some(scan_range) => scan_range,
                    None => break,
                };
            }
        }

        ranges.extend(scan_ranges);
        self.ranges = ranges;
        removed_ranges
    }

    #[inline]
    pub fn count(&self) -> usize {
        let mut total = 0;
        for range in &self.ranges {
            total += range.count();
        }
        total
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    #[inline]
    pub fn ranges(&self) -> &Vec<ScanRange> {
        &self.ranges
    }

    #[inline]
    pub fn into_static(self) -> StaticScanRanges {
        let mut ranges = Vec::with_capacity(self.ranges.len());
        let mut index = 0;
        for range in self.ranges {
            let count = range.count();
            ranges.push(StaticScanRange {
                count,
                range,
                index,
            });
            index += count;
        }
        
        StaticScanRanges {
            ranges,
            count: index,
        }
    }
}

pub struct StaticScanRanges {
    pub ranges: Vec<StaticScanRange>,
    pub count: usize,
}

pub struct StaticScanRange {
    pub range: ScanRange,
    count: usize,
    index: usize,
}

impl StaticScanRanges {
    #[inline]
    pub const fn index(&self, index: usize) -> (Ipv4Addr, u16) {
        let mut start = 0;
        let mut end = self.ranges.len();
        while start < end {
            let mid = (start + end) >> 1;
            let range = unsafe {
                core::hint::assert_unchecked(mid < self.ranges.len());
                
                &*(self.ranges.as_ptr().add(mid))
            };
            
            if range.index + range.count <= index {
                start = mid + 1;
            } else if range.index > index {
                end = mid;
            } else {
                return range.range.index(index - range.index);
            }
        }

        panic!("index out of bounds");
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Ipv4Range {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl Ipv4Range {
    pub fn single(addr: Ipv4Addr) -> Self {
        Self {
            start: addr,
            end: addr,
        }
    }
}

#[derive(Default, Debug)]
pub struct Ipv4Ranges {
    ranges: Vec<Ipv4Range>,
}

impl Ipv4Ranges {
    pub fn new(mut ranges: Vec<Ipv4Range>) -> Self {
        ranges.sort_by_key(|r| r.start);
        Self { ranges }
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mut start = 0;
        let mut end = self.ranges.len();
        while start < end {
            let mid = (start + end) / 2;
            let range = &self.ranges[mid];
            if range.end < addr {
                start = mid + 1;
            } else if range.start > addr {
                end = mid;
            } else {
                return true;
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn ranges(&self) -> &Vec<Ipv4Range> {
        &self.ranges
    }

    pub fn count(&self) -> usize {
        let mut total: u64 = 0;
        for range in &self.ranges {
            total += (u32::from(range.end) as u64) - (u32::from(range.start) as u64) + 1;
        }
        total as usize
    }
}
