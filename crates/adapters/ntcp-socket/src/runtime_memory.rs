// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Test-only IP backend. No offload capabilities: reservations emit software segments.
use super::*;

pub(super) struct PacketBackend {
    pub(super) profile: crate::packet_profile::Profile,
    input: VecDeque<(Vec<u8>, Option<core::num::NonZeroU16>)>,
    // Accepted output, each with the packet mark it was submitted under.
    pub(super) output: VecDeque<(Reply, u32)>,
    capacity: usize,
    pub(super) local_reject: bool,
    mark: u32,
}
impl PacketBackend {
    pub(super) fn new(profile: crate::packet_profile::Profile, capacity: usize) -> Result<Self> {
        let mut input = VecDeque::new();
        let mut output = VecDeque::new();
        input.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
        output.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
        Ok(Self {
            profile,
            input,
            output,
            capacity,
            local_reject: false,
            mark: 0,
        })
    }
    #[cfg(test)]
    pub(super) fn inject(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.inject_segmented(bytes, None)
    }
    pub(super) fn inject_segmented(
        &mut self,
        bytes: Vec<u8>,
        size: Option<core::num::NonZeroU16>,
    ) -> Result<()> {
        if self.input.len() == self.capacity {
            return Err(EAGAIN);
        }
        self.input.push_back((bytes, size));
        Ok(())
    }
}
impl PacketIo for PacketBackend {
    fn layer(&self) -> ntcp_io::PacketLayer {
        ntcp_io::PacketLayer::Ip
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(crate::packet_profile::BYTES)
    }
    fn packet_mark_supported(&self) -> bool {
        true
    }
    fn set_packet_mark(&mut self, mark: u32) -> std::io::Result<()> {
        self.mark = mark;
        Ok(())
    }
    fn receive(&mut self, out: &mut [u8]) -> std::io::Result<Option<usize>> {
        self.receive_with_metadata(out).map(|r| r.map(|p| p.len))
    }
    fn receive_with_metadata(
        &mut self,
        out: &mut [u8],
    ) -> std::io::Result<Option<ntcp_io::ReceivedPacket>> {
        let Some((packet, _)) = self.input.front() else {
            return Ok(None);
        };
        if packet.len() > out.len() {
            return Err(std::io::Error::from_raw_os_error(EMSGSIZE));
        }
        let (packet, tcp_segment_size) = self.input.pop_front().unwrap();
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(ntcp_io::ReceivedPacket {
            len: packet.len(),
            timestamps: Default::default(),
            tcp_segment_size,
        }))
    }
    fn transmit(&mut self, packet: &[u8]) -> std::io::Result<TxOutcome> {
        if self.local_reject {
            return Ok(TxOutcome::Rejected);
        }
        if packet.len() > crate::packet_profile::BYTES {
            return Err(std::io::Error::from_raw_os_error(EMSGSIZE));
        }
        if self.output.len() == self.capacity {
            return Ok(TxOutcome::WouldBlock);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(packet.len())
            .map_err(|_| std::io::Error::from_raw_os_error(ENOMEM))?;
        bytes.extend_from_slice(packet);
        // ABI capture time is realtime epoch microseconds at backend acceptance,
        // not capture dequeue. Protocol timers continue to use Owner::now().
        self.output.push_back((
            Reply {
                value: bytes.len() as i32,
                bytes,
                stamp: (timestamps::realtime() / 1000).min(i64::MAX as u64) as i64,
                ..Reply::default()
            },
            self.mark,
        ));
        Ok(TxOutcome::Submitted)
    }
}

impl Owner {
    pub(super) fn packet_listener_present(&self, port: u16) -> Result<bool> {
        self.packets.as_ref().ok_or(EOPNOTSUPP)?;
        if port == 0 {
            return Err(EINVAL);
        }
        // A socket label alone can outlive its core handle. Binding is immutable
        // while a listener generation is live; resolve it in the core as well.
        Ok(self.sockets.values().any(|socket| {
            let Handle::Listener(listener) = socket.handle else {
                return false;
            };
            socket.local.is_some_and(|address| address.port() == port)
                && self.endpoint.listener_queue_info(listener).is_ok()
        }))
    }
}

#[cfg(test)]
#[path = "runtime_memory_tests.rs"]
mod tests;
