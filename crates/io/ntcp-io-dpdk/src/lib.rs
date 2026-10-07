#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::{Dpdk, MAX_PACKET_LEN};
