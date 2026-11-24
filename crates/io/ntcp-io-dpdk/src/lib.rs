//! Caller-driven native DPDK packet I/O.
//!
//! EAL device contract: [`Eal::init`] refuses arguments that would let EAL
//! probe PCI devices implicitly. They must name each device with an
//! allow-list entry (`-a <pci>`, `-a<pci>`, `-a=<pci>`, `--allow <pci>`,
//! `--allow=<pci>`) or exclude PCI with `--no-pci` (virtual devices only).
//! Without either, DPDK probes every supported PCI device, and on bifurcated
//! mlx5 that takes all traffic of every ConnectX port from the kernel, the
//! management (SSH) port included.
//!
//! Hugepage memory: `Port::start` creates one mbuf pool per queue,
//! `PortConfig::mbufs_per_queue` mbufs (default 16383) of 2368 octets each
//! with the default 2048-octet data room, plus 1.06 MB of per-lcore caches
//! and ring. On 2 MiB pages that is 40.01 MB a queue (10.80 MB at 4095
//! mbufs), 160.0 MB for a port of 4 queues; EAL must be given that much
//! hugepage memory on the device's NUMA socket (`-m`/`--socket-mem`, or the
//! hugepages reserved) besides its own.
//!
//! Received frames: `Dpdk::receive_frame` hands the mbuf itself over (one
//! segment of the queue's own pool), released back to the pool from any
//! thread when the frame drops, also after the adapter and its queue have
//! gone (the pool is kept while any mbuf is out). `HostedQueue` reports
//! the frame budget a Network holds them within (`PortConfig::
//! mbufs_per_queue`).

mod calibration;
pub use calibration::{
    CalibrationError, ClockCalibration, ClockFit, MAX_CALIBRATION_WINDOW, bracketed_reading,
};
#[cfg(any(feature = "native", test))]
mod eal_args;
#[cfg(feature = "native")]
mod host;
#[cfg(feature = "native")]
pub use host::{Eal, Flow, HostedQueue, Port, PortConfig, QueueHandle, Rss, RssAlgorithm};
#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::{DEFAULT_TX_COPYBREAK, Dpdk, DpdkBuffer, MAX_PACKET_LEN, RxTimestampStatus};
