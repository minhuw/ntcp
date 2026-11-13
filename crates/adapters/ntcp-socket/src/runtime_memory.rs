// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Test-only IP backend. No offload capabilities: reservations emit software segments.
use super::*;

pub(super) struct PacketBackend {
    pub(super) profile: crate::packet_profile::Profile,
    pub(super) input: VecDeque<(Vec<u8>, Option<core::num::NonZeroU16>)>,
    // Accepted output, each with the packet mark it was submitted under.
    pub(super) output: VecDeque<(Reply, u32)>,
    capacity: usize,
    mtu: u32,
    pub(super) local_reject: bool,
    mark: u32,
}
impl PacketBackend {
    pub(super) fn new(
        profile: crate::packet_profile::Profile,
        local: IpAddr,
        capacity: usize,
    ) -> Result<Self> {
        // The port stands for packetdrill's tun device: the runner's default
        // 1500-octet MTU for IPv4 runs (IPv4-mapped ones included) and the
        // 1520 octets its IPv6 variant pins, so 1460-octet segments fit in
        // either family. Explicit packet-test link profiles override it. The
        // port still accepts every complete IP packet up to BYTES, as a tun
        // device does not drop inbound packets above its MTU.
        let mtu = match profile {
            crate::packet_profile::Profile::Upstream(options) => {
                options.link_mtu.or(options.pmtud1500.then_some(1500))
            }
            _ => None,
        }
        .unwrap_or(if local.is_ipv4() { 1500 } else { 1520 });
        let mut input = VecDeque::new();
        let mut output = VecDeque::new();
        input.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
        output.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
        Ok(Self {
            profile,
            input,
            output,
            capacity,
            mtu,
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
    fn local_ip_mtu(&self) -> std::io::Result<Option<u32>> {
        Ok(Some(self.mtu))
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
            l4_checksum: Default::default(),
        }))
    }
    fn transmit(&mut self, packet: &[u8]) -> std::io::Result<TxOutcome> {
        if self.local_reject {
            return Ok(TxOutcome::Rejected);
        }
        if packet.len() > self.local_ip_mtu()?.unwrap() as usize {
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
pub(super) mod tests;
