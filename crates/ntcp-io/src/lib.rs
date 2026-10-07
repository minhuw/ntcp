use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketLayer {
    Ip,
    Ethernet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxOutcome {
    Submitted,
    WouldBlock,
}

// Each call does bounded, nonblocking work on one complete packet. The caller
// owns its buffers: receive copies into out, transmit retains no borrow.
// Submitted transfers a copy to the backend; it implies neither wire delivery
// nor a TCP acknowledgement. Backend DMA buffers are reclaimed internally.
// None/WouldBlock leaves the caller free to retry. Errors never report a
// truncated packet as valid. Drivers, threads and scheduling belong to callers.
pub trait PacketIo {
    fn layer(&self) -> PacketLayer;
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>>;
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome>;
}

#[cfg(target_os = "linux")]
pub mod af_packet;
#[cfg(target_os = "linux")]
pub mod tun;
