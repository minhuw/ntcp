use alloc::vec::Vec;

use crate::{EndpointError, Error, Instant, Transmit, wire};

// Only physical-departure work; sequence, recovery and PRR charges stay selected.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Departure {
    pub discovery: Option<crate::DiscoveryIntent>,
    pub data_ack: bool,
    pub defer_push: bool,
    pub fresh_data: bool,
    pub deferred_fresh: bool,
    pub segmentation: Option<TransmitSegmentation>,
    pub selected_at: Instant,
    pub start: u32,
    pub payload: usize,
    pub stream: bool,
    pub syn: bool,
    pub syn_timestamp: Option<u32>,
    pub fast_open: bool,
    pub simultaneous_response: bool,
    pub fast_open_option: bool,
    pub received_syn_data_acked: bool,
    pub fin: bool,
    pub rto: bool,
    pub rto_head: bool,
    pub prior_rto_deadline: Option<Instant>,
    pub tlp: bool,
    // A tail loss probe (RFC 8985 section 7), of new data or a
    // retransmission: counted in LossCounters::loss_probes at acceptance.
    pub loss_probe: bool,
    // Selected while its connection recovered from a retransmission timeout
    // (`TransportInfo::loss`).
    pub timeout_recovery: bool,
    pub persist: bool,
    pub keepalive: bool,
    pub shrink: bool,
    pub unanswered: bool,
    // A retransmitted copy of stream bytes and/or of an already sent FIN.
    pub retransmission: bool,
    pub fin_retransmission: bool,
    // Exact-range Packet Too Big repair: every accepted fragment is a PTB
    // replacement copy, charged (PRR, RACK, pipe, Restart) at acceptance.
    pub ptb_repair: bool,
    pub bypass: bool,
    pub interval: Option<u128>,
    pub initial_burst: bool,
    pub legacy_rate: Option<(u64, u32)>,
}

/// Opt-in bounds for immutable fresh-data reservations, not wire packet sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GsoLimits {
    pub max_bytes: usize,
    pub max_segments: usize,
}

/// Segmentation of the entire selected range. Polling still returns one actual
/// segment; only `Endpoint::prepare_transmit_group` turns a prefix of the
/// remaining range into one backend aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitSegmentation {
    pub payload_len: usize,
    pub segment_payload_len: usize,
    pub tcp_header_len: usize,
    pub terminal_flags: u8,
}

/// What one backend aggregate may carry: its bounds, and the per-segment
/// header semantics the backend reproduces, as Linux tcp_gso_segment does
/// (PSH and FIN only on the last segment, CWR only on the first, every TCP
/// option repeated on every segment). A declined semantic shortens or
/// refuses the group; it never changes the bytes on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitGroupLimits {
    /// Maximum payload bytes (excludes all repeated protocol headers).
    pub max_bytes: usize,
    /// Maximum number of physical segments; fewer than two declines.
    pub max_segments: usize,
    /// PSH and FIN on the last segment only. Linux clears both together on
    /// all others (tcp_gso_segment), and NETIF_F_TSO has no separate FIN
    /// capability: a device placing one there places the other.
    pub allow_psh: bool,
    pub allow_cwr: bool,
    pub allow_options: bool,
}

/// One prepared, indivisible backend submission; never a scalar attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitGroup(pub(crate) TransmitAttempt);

/// Logical aggregate, not a checksummed jumbo wire packet: `header` and
/// `options` are the first segment's TCP header with the group's terminal
/// flags, `payload` the contiguous payload of all `segment_count` segments of
/// `segment_payload_len` bytes each but the last, which may be shorter (as
/// with Linux TSO, the device cuts `segment_payload_len` chunks and the
/// remainder). `packet.len` is the aggregate's TCP length (header, options
/// and all payload); it has no timestamp observation. Segment n carries
/// sequence `header.sequence + n * segment_payload_len`; PSH and FIN belong
/// to the last segment and CWR to the first only.
pub struct TransmitGroupView<'a> {
    pub packet: Transmit,
    pub header: wire::Header,
    pub options: &'a [u8],
    pub payload: &'a [u8],
    pub segment_payload_len: usize,
    pub segment_count: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedGroup {
    pub token: TransmitGroup,
    pub segments: usize,
    pub bytes: usize,
}

pub(crate) struct GsoBuffer<'a> {
    pub limits: GsoLimits,
    pub payload: &'a mut [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitAttempt {
    pub(crate) ordinal: u64,
    pub(crate) reservation: usize,
}

pub(crate) struct OutputReservation {
    pub index: usize,
    pub bytes: Vec<u8>,
    pub payload: Vec<u8>,
    pub shared: Vec<crate::Payload>,
    shared_header: Option<wire::Header>,
    shared_options: [u8; 40],
    shared_option_len: usize,
    pub gso: Option<GsoLimits>,
    pub current: Option<ReservedOutput>,
    pub ordinal: u64,
}

pub(crate) struct ReservedOutput {
    pub emitted_packet: Transmit,
    pub packet: Transmit,
    pub attempt: Option<TransmitAttempt>,
    // Set together with `attempt`, which then names this group.
    pub group: Option<PreparedGroup>,
    pub abandon_attempt: TransmitAttempt,
    pub offset: usize,
    pub sacks: usize,
    pub emitted_bytes: usize,
    pub emitted_sacks: usize,
    pub finished: bool,
    pub repaired: bool,
    pub departure: Option<Departure>,
    // The link scoping the packet (`Endpoint::transmit_attempt_zone`).
    pub zone: Option<ntcp_path::LinkId>,
    // A stateless reply already counted as undeliverable.
    pub undeliverable: bool,
}

impl OutputReservation {
    pub fn new() -> Self {
        Self {
            index: 0,
            bytes: Vec::new(),
            payload: Vec::new(),
            shared: Vec::new(),
            shared_header: None,
            shared_options: [0; 40],
            shared_option_len: 0,
            gso: None,
            current: None,
            ordinal: 0,
        }
    }

    pub fn token(&mut self) -> Result<TransmitAttempt, Error> {
        self.ordinal = self.ordinal.checked_add(1).ok_or(Error::InvalidArgument)?;
        Ok(TransmitAttempt {
            ordinal: self.ordinal,
            reservation: self.index,
        })
    }

    pub fn clear(&mut self) {
        self.current = None;
        self.shared.clear();
        self.shared_header = None;
    }

    pub fn is_shared(&self) -> bool {
        self.shared_header.is_some()
    }

    pub fn capture_shared(
        &mut self,
        packet: Transmit,
        header: &[u8],
        payload: &[crate::Payload],
        attempt: TransmitAttempt,
    ) -> Result<(), EndpointError> {
        let length = payload
            .iter()
            .try_fold(0usize, |n, p| n.checked_add(p.len()))
            .ok_or(Error::InvalidArgument)?;
        let n = packet
            .len
            .checked_sub(length)
            .ok_or(Error::InvalidArgument)?;
        if !(20..=60).contains(&n) || n > header.len() || payload.len() > self.shared.capacity() {
            return Err(Error::InvalidArgument.into());
        }
        self.clear();
        self.bytes[..n].copy_from_slice(&header[..n]);
        self.shared.extend(payload.iter().cloned());
        let word = |at| u16::from_be_bytes(header[at..at + 2].try_into().unwrap());
        let seq = |at| u32::from_be_bytes(header[at..at + 4].try_into().unwrap());
        self.shared_header = Some(wire::Header {
            source_port: word(0),
            destination_port: word(2),
            sequence: seq(4),
            acknowledgment: seq(8),
            flags: header[13],
            window: word(14),
            urgent_pointer: word(18),
        });
        self.shared_options[..n - 20].copy_from_slice(&header[20..n]);
        self.shared_option_len = n - 20;
        self.current = Some(ReservedOutput {
            emitted_packet: packet,
            packet,
            attempt: Some(attempt),
            group: None,
            abandon_attempt: attempt,
            offset: 0,
            sacks: 0,
            emitted_bytes: length,
            emitted_sacks: 0,
            finished: true,
            repaired: false,
            departure: None,
            zone: None,
            undeliverable: false,
        });
        Ok(())
    }

    pub fn fragment_shared(
        &mut self,
        limit: usize,
        out: &mut [u8],
        payload: &mut Vec<crate::Payload>,
    ) -> Result<Transmit, EndpointError> {
        payload.clear();
        let r = self.current.as_mut().ok_or(Error::InvalidState)?;
        let mut header = self.shared_header.ok_or(Error::InvalidState)?;
        let header_len = 20 + self.shared_option_len;
        let limit = limit.min(out.len());
        if limit <= header_len || out.len() < header_len || payload.capacity() == 0 {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        let total: usize = self.shared.iter().map(crate::Payload::len).sum();
        let mut count = 0;
        let mut skip = r.offset;
        let max = limit - header_len;
        for part in &self.shared {
            if skip >= part.len() {
                skip -= part.len();
                continue;
            }
            let n = (part.len() - skip).min(max - count);
            payload.push(part.slice(skip..skip + n).unwrap());
            count += n;
            skip = 0;
            if count == max || payload.len() == payload.capacity() {
                break;
            }
        }
        let finished = r.offset + count == total;
        header.sequence = header.sequence.wrapping_add(r.offset as u32);
        if !finished {
            header.flags &= !(wire::FIN | wire::PSH);
        }
        if r.offset != 0 {
            header.flags &= !wire::CWR;
        }
        if header.flags & wire::URG != 0 {
            header.urgent_pointer = header
                .urgent_pointer
                .saturating_sub(r.offset.min(u16::MAX as usize) as u16);
            if header.urgent_pointer == 0 {
                header.flags &= !wire::URG;
            }
        }
        let n = wire::encode_shared(
            r.packet.ip,
            header,
            &self.shared_options[..self.shared_option_len],
            payload,
            out,
        )
        .map_err(Error::Wire)?;
        r.emitted_bytes = count;
        r.emitted_sacks = 0;
        r.finished = finished;
        let packet = Transmit {
            len: n + count,
            tx_timestamp: None,
            ecn: if count == 0 { 0 } else { r.packet.ecn },
            ..r.packet
        };
        r.emitted_packet = packet;
        Ok(packet)
    }

    pub fn capture(&mut self, packet: Transmit, bytes: &[u8], attempt: TransmitAttempt) {
        self.clear();
        self.bytes[..packet.len].copy_from_slice(&bytes[..packet.len]);
        self.current = Some(ReservedOutput {
            emitted_packet: packet,
            packet,
            attempt: Some(attempt),
            group: None,
            abandon_attempt: attempt,
            offset: 0,
            sacks: 0,
            emitted_bytes: 0,
            emitted_sacks: 0,
            finished: true,
            repaired: false,
            departure: None,
            zone: None,
            undeliverable: false,
        });
    }

    // Encode only from immutable, already-admitted output. No sender selection or
    // credit accounting occurs here. Buffer space was reserved before selection.
    pub fn fragment(&mut self, limit: usize, out: &mut [u8]) -> Result<Transmit, EndpointError> {
        if self.is_shared() {
            return Err(Error::InvalidArgument.into());
        }
        if limit < 20 {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        let r = self.current.as_mut().unwrap();
        // ponytail: reparsing costs O(original length) per fragment, bounded by
        // one configured packet; cache parsed metadata if repair throughput matters.
        let original =
            wire::parse(r.packet.ip, &self.bytes[..r.packet.len]).map_err(Error::Wire)?;
        // A SYN is one handshake, not a stream fragment. Splitting TFO data
        // would repeat SYN at the wrong sequence and release ownership before
        // the handshake can acknowledge the retained suffix. Keep it indivisible.
        if original.header.flags & wire::SYN != 0 && r.packet.len > limit {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        let segmentation = r.departure.and_then(|d| d.segmentation);
        let payload = segmentation.map_or(original.payload, |s| &self.payload[..s.payload_len]);
        let mut header = original.header;
        if let Some(s) = segmentation {
            header.flags = s.terminal_flags;
        }
        let mut options = [0; 40];
        let mut used = 0;
        let mut sack_data = &[][..];
        let mut at = 0;
        while at < original.raw_options.len() {
            let kind = original.raw_options[at];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                at += 1;
                continue;
            }
            let len = original.raw_options[at + 1] as usize;
            let option = &original.raw_options[at..at + len];
            if kind == 5 {
                sack_data = &option[2..];
            } else {
                options[used..used + len].copy_from_slice(option);
                used += len;
            }
            at += len;
        }
        let remaining_sacks = sack_data.len() / 8 - r.sacks;
        let option_budget = limit.saturating_sub(20).min(40) & !3;
        let emitted_sacks = remaining_sacks.min(option_budget.saturating_sub(used + 2) / 8);
        // An above-ACK D-SACK is recognizable only together with its containing
        // second block. Never turn it into an ordinary SACK by splitting the pair.
        if r.sacks == 0 && sack_data.len() >= 16 {
            let word =
                |offset| u32::from_be_bytes(sack_data[offset..offset + 4].try_into().unwrap());
            let (left, right, outer_left, outer_right) = (word(0), word(4), word(8), word(12));
            let contained = left.wrapping_sub(outer_left) < outer_right.wrapping_sub(outer_left)
                && right.wrapping_sub(outer_left) <= outer_right.wrapping_sub(outer_left);
            let above_ack = left.wrapping_sub(header.acknowledgment) < 1 << 31;
            if contained && above_ack && emitted_sacks < 2 {
                return Err(EndpointError::ReservationMtuTooSmall);
            }
        }
        if emitted_sacks != 0 {
            options[used] = 5;
            options[used + 1] = (2 + emitted_sacks * 8) as u8;
            let start = r.sacks * 8;
            options[used + 2..used + 2 + emitted_sacks * 8]
                .copy_from_slice(&sack_data[start..start + emitted_sacks * 8]);
            used += 2 + emitted_sacks * 8;
        }
        used = (used + 3) & !3;
        if used > option_budget || remaining_sacks != 0 && emitted_sacks == 0 {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        if segmentation.is_some() {
            // Every segment repeats the selected options, SACK blocks included
            // (GSO admission excludes a D-SACK); preserve negotiated TS padding
            // and all other option bytes, rather than repacking them.
            used = original.raw_options.len();
            options[..used].copy_from_slice(original.raw_options);
            if used > option_budget {
                return Err(EndpointError::ReservationMtuTooSmall);
            }
        }
        let count = payload
            .len()
            .saturating_sub(r.offset)
            .min(limit.saturating_sub(20 + used))
            .min(segmentation.map_or(usize::MAX, |s| s.segment_payload_len));
        if count == 0 && r.offset < payload.len() && emitted_sacks == 0 {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        let finished = r.offset + count == payload.len() && emitted_sacks == remaining_sacks;
        header.sequence = header.sequence.wrapping_add(r.offset as u32);
        if !finished {
            header.flags &= !(wire::FIN | wire::PSH);
        }
        if (count == 0 && header.flags & wire::SYN == 0) || r.offset != 0 {
            header.flags &= !wire::CWR;
        }
        if header.flags & wire::URG != 0 {
            header.urgent_pointer = header
                .urgent_pointer
                .saturating_sub(r.offset.min(u16::MAX as usize) as u16);
            if header.urgent_pointer == 0 {
                header.flags &= !wire::URG;
            }
        }
        let len = wire::encode(
            r.packet.ip,
            header,
            &options[..used],
            &payload[r.offset..r.offset + count],
            out,
        )
        .map_err(Error::Wire)?;
        r.emitted_bytes = count;
        r.emitted_sacks = emitted_sacks;
        r.finished = finished;
        // A cancelled backend observation must not masquerade as a retry's actual
        // submit timestamp. Scheduled/ACK observations remain owned by the stream.
        // A GSO segment carries the token of its own bytes, as when selected
        // alone: its range holds no pending Transmit phase to cancel.
        let packet = Transmit {
            len,
            tx_timestamp: segmentation
                .and(r.packet.tx_timestamp)
                .map(|token| token.part(r.offset, count)),
            ecn: if count == 0 { 0 } else { r.packet.ecn },
            ..r.packet
        };
        r.emitted_packet = packet;
        Ok(packet)
    }
}
