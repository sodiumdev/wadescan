use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use log::info;
use xdpilone::DeviceQueue;

pub struct PacketCompleter {
    device: DeviceQueue,
    completed: Arc<AtomicUsize>,
}

impl PacketCompleter {
    pub fn new(device: DeviceQueue, completed: Arc<AtomicUsize>) -> Self {
        Self { device, completed }
    }

    #[inline]
    pub fn tick(&mut self) {
        let mut reader = self.device.complete(100);
        while reader.read().is_some() {
            self.completed.fetch_add(1, Ordering::Relaxed);
        }

        reader.release();
    }
}

pub struct Printer {
    completed: Arc<AtomicUsize>,
    completed_last: usize,

    threshold: Duration,
    last_print_time: Instant,
}

impl Printer {
    #[inline]
    pub fn new(completed: Arc<AtomicUsize>, threshold: Duration) -> Self {
        Self {
            completed,
            completed_last: 0,

            threshold,
            last_print_time: Instant::now(),
        }
    }

    #[inline]
    pub async fn tick(&mut self) {
        let completed = self.completed.load(Ordering::Relaxed);
        let packets_per_second =
            (completed - self.completed_last) as f64 / self.last_print_time.elapsed().as_secs_f64();
        if packets_per_second > 10_000_000. {
            info!("{} mpps", (packets_per_second / 1_000_000.).round() as u64)
        } else if packets_per_second > 10_000. {
            info!("{} kpps", (packets_per_second / 1_000.).round() as u64)
        } else {
            info!("{} pps", packets_per_second.round() as u64)
        };

        self.completed_last = completed;
        self.last_print_time = Instant::now();

        tokio::time::sleep(self.threshold).await;
    }
}
