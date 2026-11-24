use alloc::vec::Vec;
use ntcp_buffer::{ChunkArena, ChunkRef, ChunkSlice, PayloadSlice, TxPart};

use crate::{
    EndpointError, Error, Instant, Transmit,
    seq::Seq,
    tx_pool::{TxPartsBuf, TxPool},
    wire,
};

pub(crate) const RESERVATION_INITIAL_PARTS: usize = 16;

pub(crate) enum OwnedTxPart {
    Chunk {
        chunk: ChunkRef,
        offset: u32,
        len: u32,
    },
    Shared(crate::Payload),
}

impl OwnedTxPart {
    #[inline]
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Chunk { len, .. } => *len as usize,
            Self::Shared(payload) => payload.len(),
        }
    }
}

// Only physical-departure work; sequence, recovery and PRR charges stay selected.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Departure {
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

impl Departure {
    pub(crate) fn submitted_range(&self, offset: usize, count: usize) -> (Seq, Seq) {
        if self.segmentation.is_some() || self.deferred_fresh {
            let start = Seq(self.start).wrapping_add(u32::from(self.syn) + offset as u32);
            (start, start.wrapping_add(count as u32))
        } else {
            let start = Seq(self.start);
            let length = self.payload as u32 + u32::from(self.syn) + u32::from(self.fin);
            (start, start.wrapping_add(length))
        }
    }
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
/// flags, `payload_len` the total payload bytes (accessible zero-copy via
/// `Endpoint::with_transmit_group_parts`) of all `segment_count` segments of
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
    pub payload_len: usize,
    pub segment_payload_len: usize,
    pub segment_count: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedGroup {
    pub token: TransmitGroup,
    pub segments: usize,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitAttempt {
    pub(crate) ordinal: core::num::NonZeroU64,
    pub(crate) reservation: usize,
}

pub(crate) struct OutputReservation {
    pub index: usize,
    pub packet_bytes: usize,
    // Max 60B TCP header + optional 1B keepalive garbage octet.
    pub header: [u8; 64],
    pub header_len: usize,
    pub inline_payload_len: usize,
    pub parts: Vec<OwnedTxPart>,
    pub shared: Vec<crate::Payload>,
    shared_header: Option<wire::Header>,
    shared_option_len: usize,
    pub gso: Option<GsoLimits>,
    pub current: Option<ReservedOutput>,
    pub ordinal: u64,
    // Fragments leave their checksum for the device to complete
    // (`ConnectionConfig::tcp_checksum_offload`).
    pub checksum_partial: bool,
}

pub(crate) struct ReservedOutput {
    // Only suffix repair and segmentation can change the current packet.
    pub emitted_packet: Option<Transmit>,
    pub packet: Transmit,
    pub attempt: Option<TransmitAttempt>,
    // Set together with `attempt`, which then names this group.
    pub group: Option<PreparedGroup>,
    pub abandon_attempt: TransmitAttempt,
    pub offset: usize,
    pub sacks: usize,
    pub emitted_bytes: usize,
    pub emitted_header_len: usize,
    pub emitted_sacks: usize,
    pub finished: bool,
    pub repaired: bool,
    // The last fragment carries a TSval other than the selection's: the
    // owner's state keyed on it follows (`Connection::restamp_reserved`).
    pub restamped: bool,
    pub departure: Option<Departure>,
    // A PLPMTUD probe's intent, kept beside its departure: copied only
    // for a probe, while every output copies its departure.
    // The held owner keeps its selection and probe intent until release.
    pub probe: bool,
    // The link scoping the packet (`Endpoint::transmit_attempt_zone`).
    pub zone: Option<ntcp_path::LinkId>,
    // A stateless reply already counted as undeliverable.
    pub undeliverable: bool,
}

impl ReservedOutput {
    pub(crate) fn emitted(&self) -> &Transmit {
        self.emitted_packet.as_ref().unwrap_or(&self.packet)
    }
}

fn parts_len(parts: &[OwnedTxPart]) -> usize {
    parts.iter().map(OwnedTxPart::len).sum()
}

fn collect_parts_from<'a>(
    parts: &'a [OwnedTxPart],
    arena: &'a ChunkArena,
    offset: usize,
    count: usize,
    out: &mut TxPartsBuf<'a>,
) {
    if count == 0 {
        return;
    }
    let mut skip = offset;
    let mut remaining = count;
    for part in parts {
        let len = part.len();
        if skip >= len {
            skip -= len;
            continue;
        }
        let take = (len - skip).min(remaining);
        match part {
            OwnedTxPart::Chunk {
                chunk,
                offset: chunk_off,
                ..
            } => {
                let start = *chunk_off as usize + skip;
                let slice = ChunkSlice::new(arena.get(chunk), start..start + take)
                    .expect("reserved chunk slice within filled prefix");
                out.push_merged(TxPart::Chunk(slice));
            }
            OwnedTxPart::Shared(payload) => {
                let slice = PayloadSlice::new(payload, skip..skip + take)
                    .expect("reserved shared slice within bounds");
                out.push_merged(TxPart::Shared(slice));
            }
        }
        remaining -= take;
        skip = 0;
        if remaining == 0 {
            break;
        }
    }
    debug_assert_eq!(remaining, 0);
}

impl OutputReservation {
    pub fn new() -> Self {
        Self {
            index: 0,
            packet_bytes: usize::MAX,
            header: [0; 64],
            header_len: 0,
            inline_payload_len: 0,
            parts: Vec::new(),
            shared: Vec::new(),
            shared_header: None,
            shared_option_len: 0,
            gso: None,
            current: None,
            ordinal: 0,
            checksum_partial: false,
        }
    }

    pub fn token(&mut self) -> Result<TransmitAttempt, Error> {
        let next = self
            .ordinal
            .checked_add(1)
            .and_then(core::num::NonZeroU64::new)
            .ok_or(Error::InvalidArgument)?;
        self.ordinal = next.get();
        Ok(TransmitAttempt {
            ordinal: next,
            reservation: self.index,
        })
    }

    pub fn clear(&mut self, pool: &mut TxPool) {
        for part in self.parts.drain(..) {
            if let OwnedTxPart::Chunk { chunk, .. } = part {
                pool.release(chunk);
            }
        }
        self.header_len = 0;
        self.inline_payload_len = 0;
        self.current = None;
        self.shared.clear();
        self.shared_header = None;
    }

    pub fn is_shared(&self) -> bool {
        self.shared_header.is_some()
    }

    pub fn parts_len(&self) -> usize {
        parts_len(&self.parts)
    }

    pub fn collect_parts<'a>(
        &'a self,
        arena: &'a ChunkArena,
        offset: usize,
        count: usize,
        out: &mut TxPartsBuf<'a>,
    ) {
        collect_parts_from(&self.parts, arena, offset, count, out);
    }

    pub fn capture_shared(
        &mut self,
        pool: &mut TxPool,
        packet: &Transmit,
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
        self.clear(pool);
        self.header[..n].copy_from_slice(&header[..n]);
        self.header_len = n;
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
        self.shared_option_len = n - 20;
        self.current = Some(ReservedOutput {
            emitted_packet: None,
            packet: *packet,
            attempt: Some(attempt),
            group: None,
            abandon_attempt: attempt,
            offset: 0,
            sacks: 0,
            emitted_bytes: length,
            emitted_header_len: n,
            emitted_sacks: 0,
            finished: true,
            repaired: false,
            restamped: false,
            departure: None,
            probe: false,
            zone: None,
            undeliverable: false,
        });
        Ok(())
    }

    /// `fragment` of a shared-payload reservation: every fragment repeats
    /// the selected options, written anew with `tsval`.
    pub fn fragment_shared(
        &mut self,
        limit: usize,
        out: &mut [u8],
        payload: &mut Vec<crate::Payload>,
        tsval: u32,
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
        let mut set = wire::parse_unchecked(r.packet.ip, &self.header[..header_len])
            .map_err(Error::Wire)?
            .options;
        restamp(r, header.flags, &mut set, tsval);
        let mut options = [0; 40];
        let used = wire::write_options(&set, &mut options);
        debug_assert_eq!(used, self.shared_option_len);
        let n = wire::encode_shared_with(
            r.packet.ip,
            header,
            &options[..used],
            payload,
            out,
            self.checksum_partial,
        )
        .map_err(Error::Wire)?;
        r.emitted_bytes = count;
        r.emitted_header_len = n;
        r.emitted_sacks = 0;
        r.finished = finished;
        let packet = Transmit {
            len: n + count,
            tx_timestamp: None,
            ecn: if count == 0 { 0 } else { r.packet.ecn },
            ..r.packet
        };
        r.emitted_packet = Some(packet);
        Ok(packet)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn capture_parts(
        &mut self,
        pool: &mut TxPool,
        packet: &Transmit,
        header: &[u8],
        inline_payload: &[u8],
        payload_len: usize,
        attempt: TransmitAttempt,
        fill_parts: impl FnOnce(&mut TxPool, &mut Vec<OwnedTxPart>),
    ) {
        debug_assert!(header.len() + inline_payload.len() <= self.header.len());
        debug_assert!(inline_payload.len() <= 1);
        self.clear(pool);
        self.header[..header.len()].copy_from_slice(header);
        self.header_len = header.len();
        if !inline_payload.is_empty() {
            self.header[header.len()..header.len() + inline_payload.len()]
                .copy_from_slice(inline_payload);
            self.inline_payload_len = inline_payload.len();
        }
        fill_parts(pool, &mut self.parts);
        debug_assert_eq!(
            if self.inline_payload_len != 0 {
                self.inline_payload_len
            } else {
                self.parts_len()
            },
            payload_len
        );
        self.current = Some(ReservedOutput {
            emitted_packet: None,
            packet: *packet,
            attempt: Some(attempt),
            group: None,
            abandon_attempt: attempt,
            offset: 0,
            sacks: 0,
            emitted_bytes: payload_len,
            emitted_header_len: header.len() + inline_payload.len(),
            emitted_sacks: 0,
            finished: true,
            repaired: false,
            restamped: false,
            departure: None,
            probe: false,
            zone: None,
            undeliverable: false,
        });
    }

    #[cfg(test)]
    pub(crate) fn capture_bytes_for_test(
        &mut self,
        pool: &mut TxPool,
        packet: &Transmit,
        bytes: &[u8],
        attempt: TransmitAttempt,
    ) {
        let tcp_hdr_len = usize::from(bytes[12] >> 4) * 4;
        let payload = &bytes[tcp_hdr_len..packet.len];
        self.capture_parts(
            pool,
            packet,
            &bytes[..tcp_hdr_len],
            &[],
            payload.len(),
            attempt,
            |_, parts| {
                if !payload.is_empty() {
                    parts.push(OwnedTxPart::Shared(crate::Payload::new(payload.to_vec())));
                }
            },
        );
    }

    // Encode only from immutable, already-admitted output. No sender selection or
    // credit accounting occurs here. Buffer space was reserved before selection.
    // The options are written anew by `wire::write_options`, as at selection,
    // with `tsval`, the timestamp clock now, as Linux's tcp_transmit_skb writes
    // each transmission's options (`restamped`).
    pub fn fragment(
        &mut self,
        arena: &ChunkArena,
        limit: usize,
        out: &mut [u8],
        gather: bool,
        tsval: u32,
    ) -> Result<Transmit, EndpointError> {
        if self.is_shared() {
            return Err(Error::InvalidArgument.into());
        }
        let limit = limit.min(self.packet_bytes);
        if limit < 20 {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        let r = self.current.as_mut().unwrap();
        let original = wire::parse_unchecked(r.packet.ip, &self.header[..self.header_len])
            .map_err(Error::Wire)?;
        // A SYN is one handshake, not a stream fragment. Splitting TFO data
        // would repeat SYN at the wrong sequence and release ownership before
        // the handshake can acknowledge the retained suffix. Keep it indivisible.
        if original.header.flags & wire::SYN != 0 && r.packet.len > limit {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        let segmentation = r.departure.and_then(|d| d.segmentation);
        let total_payload = if self.inline_payload_len != 0 {
            self.inline_payload_len
        } else {
            parts_len(&self.parts)
        };
        let mut header = original.header;
        if let Some(s) = segmentation {
            header.flags = s.terminal_flags;
        }
        let option_budget = limit.saturating_sub(20).min(40) & !3;
        let mut options = [0; 40];
        let used;
        let mut emitted_sacks = 0;
        let mut omitted_sacks = 0;
        let mut remaining_sacks = 0;
        let mut rewritten = false;
        if segmentation.is_some() {
            // A GSO segment repeats the range's options, SACK blocks and
            // TSval included (GSO admission excludes a D-SACK), as Linux's
            // tcp_gso_segment repeats the skb's header on every segment and
            // as `transmit_group` offers the rest of the range: one
            // transmission, cut by the device. Until a segment of it departs
            // (a refused first segment), the range is not transmitted yet:
            // its options are written anew with `tsval` and kept in the held
            // header, which its later segments and groups repeat.
            if r.offset == 0 {
                let mut set = original.options;
                rewritten = restamp(r, header.flags, &mut set, tsval);
                used = wire::write_options(&set, &mut options);
                debug_assert_eq!(used, original.raw_options.len());
            } else {
                used = original.raw_options.len();
                options[..used].copy_from_slice(original.raw_options);
            }
            if used > option_budget {
                return Err(EndpointError::ReservationMtuTooSmall);
            }
        } else {
            let mut set = original.options;
            restamp(r, header.flags, &mut set, tsval);
            let sacks = core::mem::take(&mut set.sack_blocks);
            let blocks = sacks.iter().map_while(|block| *block).count();
            remaining_sacks = blocks - r.sacks;
            let mut first = r.sacks;
            if remaining_sacks != 0 {
                let base = wire::write_options(&set, &mut options);
                let room = option_budget.saturating_sub(base + 4) / 8;
                emitted_sacks = remaining_sacks.min(room);
                // An above-ACK D-SACK is recognizable only together with its
                // containing second block, so the pair is never split into an
                // ordinary SACK. Without room for both the D-SACK is omitted
                // and its containing block reported, as a one-block option
                // is chosen at selection (RxQueue::sack_blocks).
                if r.sacks == 0 && blocks >= 2 && emitted_sacks < 2 {
                    let block = |index: usize| sacks[index].unwrap();
                    let ((left, right), (outer_left, outer_right)) = (block(0), block(1));
                    let contained = left.wrapping_sub(outer_left)
                        < outer_right.wrapping_sub(outer_left)
                        && right.wrapping_sub(outer_left) <= outer_right.wrapping_sub(outer_left);
                    let above_ack = left.wrapping_sub(header.acknowledgment) < 1 << 31;
                    if contained && above_ack {
                        omitted_sacks = 1;
                        first = 1;
                        emitted_sacks = (remaining_sacks - 1).min(room);
                    }
                }
                set.sack_blocks[..emitted_sacks]
                    .copy_from_slice(&sacks[first..first + emitted_sacks]);
            }
            used = wire::write_options(&set, &mut options);
            if used > option_budget || remaining_sacks != omitted_sacks && emitted_sacks == 0 {
                return Err(EndpointError::ReservationMtuTooSmall);
            }
        }
        let count = total_payload
            .saturating_sub(r.offset)
            .min(limit.saturating_sub(20 + used))
            .min(segmentation.map_or(usize::MAX, |s| s.segment_payload_len));
        if count == 0 && r.offset < total_payload && emitted_sacks == 0 {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        let finished =
            r.offset + count == total_payload && omitted_sacks + emitted_sacks == remaining_sacks;
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
        let header_len = 20 + used;
        let written = if self.inline_payload_len != 0 {
            let inline = &self.header[self.header_len + r.offset..self.header_len + r.offset + count];
            wire::encode_with(
                r.packet.ip,
                header,
                &options[..used],
                inline,
                out,
                self.checksum_partial,
            )
            .map_err(Error::Wire)?
        } else {
            let mut parts = TxPartsBuf::new();
            if count != 0 && (!self.checksum_partial || gather) {
                collect_parts_from(&self.parts, arena, r.offset, count, &mut parts);
            }
            wire::encode_parts_with(
                r.packet.ip,
                header,
                &options[..used],
                parts.as_slice(),
                count,
                out,
                self.checksum_partial,
                gather,
            )
            .map_err(Error::Wire)?
        };
        debug_assert_eq!(
            written,
            if gather || self.inline_payload_len != 0 {
                header_len + count
            } else {
                header_len
            }
        );
        if rewritten {
            self.header[20..20 + used].copy_from_slice(&options[..used]);
        }
        r.emitted_bytes = count;
        r.emitted_header_len = header_len + if self.inline_payload_len != 0 { count } else { 0 };
        r.emitted_sacks = omitted_sacks + emitted_sacks;
        r.finished = finished;
        // A cancelled backend observation must not masquerade as a retry's actual
        // submit timestamp. Scheduled/ACK observations remain owned by the stream.
        // A GSO segment carries the token of its own bytes, as when selected
        // alone: its range holds no pending Transmit phase to cancel.
        let packet = Transmit {
            len: header_len + count,
            tx_timestamp: segmentation
                .and(r.packet.tx_timestamp)
                .map(|token| token.part(r.offset, count)),
            ecn: if count == 0 { 0 } else { r.packet.ecn },
            ..r.packet
        };
        r.emitted_packet = Some(packet);
        Ok(packet)
    }
}

// Give a rebuilt segment's Timestamps option `tsval`, the clock at its
// transmission, unless it is a reset: a reactive one carries 0 (RFC 7323
// section 5.2), and no reset is timed. A changed TSval becomes the
// departure's and flags the owner's update (`restamped`); returns whether
// it changed.
fn restamp(r: &mut ReservedOutput, flags: u8, options: &mut wire::Options, tsval: u32) -> bool {
    if flags & wire::RST == 0
        && let Some((value, _)) = &mut options.timestamps
        && *value != tsval
    {
        *value = tsval;
        if let Some(d) = &mut r.departure {
            d.syn_timestamp = Some(tsval);
        }
        r.restamped = true;
        return true;
    }
    false
}
