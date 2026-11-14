//! Caller-driven native DPDK packet I/O.
//!
//! EAL device contract: [`Eal::init`] refuses arguments that would let EAL
//! probe PCI devices implicitly. They must name each device with an
//! allow-list entry (`-a <pci>`, `-a<pci>`, `-a=<pci>`, `--allow <pci>`,
//! `--allow=<pci>`) or exclude PCI with `--no-pci` (virtual devices only).
//! Without either, DPDK probes every supported PCI device, and on bifurcated
//! mlx5 that takes all traffic of every ConnectX port from the kernel, the
//! management (SSH) port included.

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
pub use native::{Dpdk, DpdkBuffer, MAX_PACKET_LEN, RxTimestampStatus};
