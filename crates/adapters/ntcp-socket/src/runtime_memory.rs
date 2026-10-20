// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Test-only IP backend. No offload capabilities: reservations emit software segments.
use super::*;

pub(super) struct PacketBackend {
    pub(super) profile: crate::packet_profile::Profile,
    input: VecDeque<Vec<u8>>,
    pub(super) output: VecDeque<Reply>,
    capacity: usize,
    pub(super) local_reject: bool,
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
        })
    }
    pub(super) fn inject(&mut self, bytes: Vec<u8>) -> Result<()> {
        if self.input.len() == self.capacity {
            return Err(EAGAIN);
        }
        self.input.push_back(bytes);
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
    fn receive(&mut self, out: &mut [u8]) -> std::io::Result<Option<usize>> {
        let Some(packet) = self.input.front() else {
            return Ok(None);
        };
        if packet.len() > out.len() {
            return Err(std::io::Error::from_raw_os_error(EMSGSIZE));
        }
        let packet = self.input.pop_front().unwrap();
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
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
        self.output.push_back(Reply {
            value: bytes.len() as i32,
            bytes,
            stamp: (timestamps::realtime() / 1000).min(i64::MAX as u64) as i64,
            ..Reply::default()
        });
        Ok(TxOutcome::Submitted)
    }
}

#[cfg(test)]
#[path = "runtime_memory_tests.rs"]
mod tests;
