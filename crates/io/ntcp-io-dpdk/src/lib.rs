#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::{Dpdk, DpdkBuffer, MAX_PACKET_LEN, RxTimestampStatus};
