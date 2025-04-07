use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use log::{Level, info};
use xdpilone::DeviceQueue;

pub struct PacketCompleter {
    device: DeviceQueue,

    completed: usize,
    completed_last: usize,

    print_threshold: Duration,
    last_print_time: Instant,
}

impl PacketCompleter {
    pub fn new(device: DeviceQueue, print_threshold: Duration) -> Self {
        Self {
            device,

            completed: 0,
            completed_last: 0,

            print_threshold,
            last_print_time: Instant::now(),
        }
    }

    #[inline]
    pub fn tick(&mut self) {
        let mut reader = self.device.complete(u32::MAX);
        while reader.read().is_some() {
            self.completed += 1;
        }

        reader.release();

        if self.last_print_time.elapsed() > self.print_threshold {
            let packets_per_second = (self.completed - self.completed_last) as f64
                / self.last_print_time.elapsed().as_secs_f64();
            if packets_per_second > 10_000_000. {
                info!("{} mpps", (packets_per_second / 1_000_000.).round() as u64)
            } else if packets_per_second > 10_000. {
                info!("{} kpps", (packets_per_second / 1_000.).round() as u64)
            } else {
                info!("{} pps", packets_per_second.round() as u64)
            };

            self.completed_last = self.completed;
            self.last_print_time = Instant::now();
        }
    }
}
