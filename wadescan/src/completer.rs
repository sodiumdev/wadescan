use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use xdpilone::DeviceQueue;

pub struct PacketCompleter {
    device: DeviceQueue,
    completed: Arc<AtomicUsize>,
}

impl PacketCompleter {
    pub fn new(device: DeviceQueue, completed: Arc<AtomicUsize>) -> Self {
        Self {
            device,
            completed
        }
    }

    pub fn tick(&mut self) {
        let mut reader = self.device.complete(self.device.available());
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
    last_print_time: Instant
}

impl Printer {
    #[inline]
    pub fn new(completed: Arc<AtomicUsize>, threshold: Duration) -> Self {
        Self {
            completed,
            completed_last: 0,
            
            threshold,
            last_print_time: Instant::now()
        }
    }

    #[inline]
    pub async fn tick(&mut self) {
        let completed = self.completed.load(Ordering::Acquire);
        let packets_per_second = (completed - self.completed_last) as f64 / self.last_print_time.elapsed().as_secs_f64();
        if packets_per_second > 10_000_000. {
            println!("{} mpps", (packets_per_second / 1_000_000.).round() as u64)
        } else if packets_per_second > 10_000. {
            println!("{} kpps", (packets_per_second / 1_000.).round() as u64)
        } else {
            println!("{} pps", packets_per_second.round() as u64)
        };

        self.completed_last = completed;
        self.last_print_time = Instant::now();
        
        tokio::time::sleep(self.threshold).await;
    }
}
