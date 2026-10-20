use std::net::IpAddr;

use ntcp::{Endpoint, EndpointError, Instant, Transmit, TransmitAttempt, TransmitGroup, wire};
use ntcp_io::{
    PacketIo, PacketLayer, TcpSegmentationError, TcpSegmentationRequest, TransmitTime, TxOutcome,
    TxTimestampRequest,
};

#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub max_segments: usize,
    pub max_wire_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Charge {
    pub segments: usize,
    // Repeated Ethernet/IP/TCP headers and minimum-frame padding; no FCS/preamble.
    pub wire_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct Ethernet {
    pub source: [u8; 6],
    pub destination: [u8; 6],
}

// These must be the matching, certainly-unsubmitted poll result and TCP bytes.
// Include any caller-side metadata: segmented IO has no EDT/timestamp support.
pub struct Scalar<'a> {
    pub attempt: TransmitAttempt,
    pub packet: Transmit,
    pub tcp: &'a [u8],
    pub when: Option<TransmitTime>,
    pub timestamp: Option<TxTimestampRequest>,
}

// Owns the core identity, NOT the storage or endpoint. The exclusive buffer
// borrow prevents mutation/reuse while a retry is pending. Dropping is not reject.
#[must_use]
#[derive(Debug)]
pub struct Pending<'a> {
    group: TransmitGroup,
    bytes: &'a mut [u8],
    request: TcpSegmentationRequest,
    charge: Charge,
}

#[derive(Debug)]
pub enum Rejection {
    Unsupported,
    InvalidInput,
    Preflight(EndpointError),
}

#[derive(Debug)]
pub enum QuarantineReason {
    Io(std::io::Error),
    Core(EndpointError),
    StaleToken,
}

// Intentionally no conversion back to Pending or cleanup/fallback methods.
// Retain under caller quarantine policy; never resubmit or reject uncertain IO.
#[must_use]
#[derive(Debug)]
pub struct Quarantined<'a> {
    pending: Pending<'a>,
    pub reason: QuarantineReason,
}

impl Quarantined<'_> {
    pub fn bytes(&self) -> &[u8] {
        self.pending.bytes()
    }

    pub fn charge(&self) -> Charge {
        self.pending.charge()
    }
}

#[must_use]
#[derive(Debug)]
pub enum Submission<'a> {
    // Backend ownership transfer and core commit only, NOT delivery.
    Submitted(Charge),
    WouldBlock(Pending<'a>),
    // Group rejected; caller must repoll scalar, never transmit the aggregate.
    Rejected(Rejection),
    Quarantined(Quarantined<'a>),
}

// None/error preserves the scalar identity. Caller supplies preallocated storage
// and a per-turn fairness budget, not a NIC burst constant. No hotpath allocation.
pub fn prepare<'a, I: PacketIo + ?Sized>(
    endpoint: &mut Endpoint,
    io: &I,
    scalar: Scalar<'_>,
    buffer: &'a mut [u8],
    ethernet: Ethernet,
    budget: Budget,
) -> Result<Option<Pending<'a>>, EndpointError> {
    let p = scalar.packet;
    if io.layer() != PacketLayer::Ethernet
        || scalar.when.is_some()
        || scalar.timestamp.is_some()
        || p.ecn != 0
        || p.ipv4_options != ntcp::OutgoingIpv4Options::default()
        || p.hop_limit == 0
        || p.dscp > 63
        || scalar.tcp.len() != p.len
    {
        return Ok(None);
    }
    let Some(caps) = io.tcp_segmentation_capabilities() else {
        return Ok(None);
    };
    // A scalar tx_timestamp token names a stream range, not a request. Core
    // GSO eligibility excludes pending observations; explicit IO requests above
    // are declined, and the prepared group itself has no observation token.
    let Some(segmentation) = endpoint.transmit_segmentation(scalar.attempt) else {
        return Ok(None);
    };
    let Ok(tcp) = wire::parse(p.ip, scalar.tcp) else {
        return Ok(None);
    };
    if segmentation.tcp_header_len != 20
        || !tcp.raw_options.is_empty()
        || tcp.header.flags != wire::ACK
        || tcp.header.urgent_pointer != 0
        || scalar.tcp[12] != 0x50
        || segmentation.terminal_flags & !(wire::ACK | wire::PSH) != 0
    {
        return Ok(None);
    }
    let (ip_len, ether_type, max_payload) = match (p.ip.source, p.ip.destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => (20, 0x0800u16, 65535 - 40),
        (IpAddr::V6(_), IpAddr::V6(_)) => (40, 0x86ddu16, 65535 - 20),
        _ => return Ok(None),
    };
    let headers: usize = 14 + ip_len + 20;
    let mss = segmentation.segment_payload_len;
    let Some(frame_len) = headers.checked_add(mss) else {
        return Ok(None);
    };
    if mss == 0 || mss > u16::MAX as usize || frame_len - 14 > caps.local_ip_mtu as usize {
        return Ok(None);
    }
    let wire_per_segment = frame_len.max(60);
    let max_bytes = buffer
        .len()
        .min(caps.max_aggregate_len)
        .saturating_sub(headers)
        .min(max_payload);
    let count = budget
        .max_segments
        .min(caps.max_segments)
        .min(budget.max_wire_bytes.min(caps.max_wire_bytes) / wire_per_segment)
        .min(max_bytes / mss);
    if count < 2 {
        return Ok(None);
    }
    // Validate/encode IP before changing the scalar token. IP codecs encode only
    // the IP header here; never checksum a logical aggregate with wire::encode.
    let packet = Transmit {
        len: 20 + count * mss,
        ..p
    };
    let ip_buffer = &mut buffer[14..headers + count * mss];
    let encoded = if ip_len == 20 {
        ntcp_ip::encode(ip_buffer, packet, 0)
    } else {
        ntcp_ip6::encode(ip_buffer, packet)
    };
    if encoded.is_err() {
        return Ok(None);
    }
    let Some(group) = endpoint.prepare_transmit_group(
        scalar.attempt,
        ntcp::TransmitGroupLimits {
            max_bytes: count * mss,
            max_segments: count,
            allow_psh: false,
            allow_cwr: false,
        },
    )?
    else {
        return Ok(None);
    };
    let view = endpoint.transmit_group(group).expect("just prepared group");
    let len = headers + view.payload.len();
    buffer[..6].copy_from_slice(&ethernet.destination);
    buffer[6..12].copy_from_slice(&ethernet.source);
    buffer[12..14].copy_from_slice(&ether_type.to_be_bytes());
    if ip_len == 20 {
        buffer[16..18].copy_from_slice(&((len - 14) as u16).to_be_bytes());
        buffer[24..26].fill(0);
    } else {
        buffer[18..20].copy_from_slice(&((len - 54) as u16).to_be_bytes());
    }
    let h = view.header;
    let tcp = &mut buffer[14 + ip_len..headers];
    tcp.fill(0);
    tcp[..2].copy_from_slice(&h.source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&h.destination_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&h.sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&h.acknowledgment.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = h.flags;
    tcp[14..16].copy_from_slice(&h.window.to_be_bytes());
    buffer[headers..len].copy_from_slice(view.payload);
    Ok(Some(Pending {
        group,
        bytes: &mut buffer[..len],
        request: TcpSegmentationRequest {
            segment_payload_len: mss,
        },
        charge: Charge {
            segments: view.segment_count,
            wire_bytes: view.segment_count * wire_per_segment,
        },
    }))
}

impl<'a> Pending<'a> {
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn request(&self) -> TcpSegmentationRequest {
        self.request
    }

    pub fn charge(&self) -> Charge {
        self.charge
    }

    fn quarantine(self, reason: QuarantineReason) -> Quarantined<'a> {
        Quarantined {
            pending: self,
            reason,
        }
    }

    // Required before MTU updates/resegmentation. Only Pending certifies that
    // nothing was submitted; Quarantined deliberately cannot call this method.
    pub fn reject(self, endpoint: &mut Endpoint) -> Result<(), Quarantined<'a>> {
        match endpoint.reject_unsubmitted_group(self.group) {
            Ok(true) => Ok(()),
            Ok(false) => Err(self.quarantine(QuarantineReason::StaleToken)),
            Err(e) => Err(self.quarantine(QuarantineReason::Core(e))),
        }
    }

    // Deadline abandonment is legal only while submission is certainly absent.
    pub fn abandon(self, endpoint: &mut Endpoint) -> Result<(), Quarantined<'a>> {
        match endpoint.abandon_transmit_group(self.group) {
            Ok(true) => Ok(()),
            Ok(false) => Err(self.quarantine(QuarantineReason::StaleToken)),
            Err(e) => Err(self.quarantine(QuarantineReason::Core(e))),
        }
    }

    fn rejected(self, endpoint: &mut Endpoint, reason: Rejection) -> Submission<'a> {
        match self.reject(endpoint) {
            Ok(()) => Submission::Rejected(reason),
            Err(q) => Submission::Quarantined(q),
        }
    }

    // Same endpoint/backend/configuration as preparation; serialize endpoint
    // access through validation, IO and commit. Clock uses Endpoint's timebase.
    // One bounded attempt: caller schedules/charges the whole group, and bounds
    // WouldBlock retries. A panic during IO/clock likewise NEVER permits retry.
    pub fn submit<I: PacketIo + ?Sized>(
        self,
        endpoint: &mut Endpoint,
        io: &mut I,
        mut clock: impl FnMut() -> Instant,
    ) -> Submission<'a> {
        match endpoint.validate_transmit_group(clock(), self.group) {
            Ok(true) => {}
            Ok(false) => {
                return Submission::Quarantined(self.quarantine(QuarantineReason::StaleToken));
            }
            Err(e) => return self.rejected(endpoint, Rejection::Preflight(e)),
        }
        match io.transmit_segmented(self.bytes, self.request) {
            Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => Submission::WouldBlock(self),
            Ok(TxOutcome::Submitted) => match endpoint.accept_transmit_group(clock(), self.group) {
                Ok(true) => Submission::Submitted(self.charge),
                Ok(false) => Submission::Quarantined(self.quarantine(QuarantineReason::StaleToken)),
                Err(e) => Submission::Quarantined(self.quarantine(QuarantineReason::Core(e))),
            },
            Err(TcpSegmentationError::Unsupported) => {
                self.rejected(endpoint, Rejection::Unsupported)
            }
            Err(TcpSegmentationError::InvalidInput) => {
                self.rejected(endpoint, Rejection::InvalidInput)
            }
            Err(TcpSegmentationError::Other(e)) => {
                Submission::Quarantined(self.quarantine(QuarantineReason::Io(e)))
            }
        }
    }
}

#[cfg(test)]
mod tests;
