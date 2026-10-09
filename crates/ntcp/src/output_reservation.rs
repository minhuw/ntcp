use alloc::vec::Vec;

use crate::{ConnectionId, EndpointError, Error, Instant, Transmit, wire};

// Only physical-departure work; sequence, recovery and PRR charges stay selected.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Departure {
    pub selected_at: Instant,
    pub start: u32,
    pub payload: usize,
    pub stream: bool,
    pub syn: bool,
    pub fin: bool,
    pub rto: bool,
    pub rto_head: bool,
    pub prior_rto_deadline: Option<Instant>,
    pub tlp: bool,
    pub persist: bool,
    pub keepalive: bool,
    pub shrink: bool,
    pub unanswered: bool,
    pub bypass: bool,
    pub interval: Option<u128>,
    pub legacy_rate: Option<(u64, u32)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitAttempt {
    pub(crate) ordinal: u64,
    pub(crate) connection: Option<ConnectionId>,
}

pub(crate) struct OutputReservation {
    pub bytes: Vec<u8>,
    pub current: Option<ReservedOutput>,
    pub ordinal: u64,
}

pub(crate) struct ReservedOutput {
    pub packet: Transmit,
    pub attempt: Option<TransmitAttempt>,
    pub abandon_attempt: TransmitAttempt,
    pub offset: usize,
    pub sacks: usize,
    pub emitted_bytes: usize,
    pub emitted_sacks: usize,
    pub finished: bool,
    pub repaired: bool,
    pub departure: Option<Departure>,
}

impl OutputReservation {
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current: None,
            ordinal: 0,
        }
    }

    pub fn token(&mut self, connection: Option<ConnectionId>) -> Result<TransmitAttempt, Error> {
        self.ordinal = self.ordinal.checked_add(1).ok_or(Error::InvalidArgument)?;
        Ok(TransmitAttempt {
            ordinal: self.ordinal,
            connection,
        })
    }

    pub fn capture(&mut self, packet: Transmit, bytes: &[u8], attempt: TransmitAttempt) {
        self.bytes[..packet.len].copy_from_slice(&bytes[..packet.len]);
        self.current = Some(ReservedOutput {
            packet,
            attempt: Some(attempt),
            abandon_attempt: attempt,
            offset: 0,
            sacks: 0,
            emitted_bytes: 0,
            emitted_sacks: 0,
            finished: true,
            repaired: false,
            departure: None,
        });
    }

    // Encode only from immutable, already-admitted output. No sender selection or
    // credit accounting occurs here. Buffer space was reserved before selection.
    pub fn fragment(&mut self, limit: usize, out: &mut [u8]) -> Result<Transmit, EndpointError> {
        if limit < 20 {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        let r = self.current.as_mut().unwrap();
        // ponytail: reparsing costs O(original length) per fragment, bounded by
        // one configured packet; cache parsed metadata if repair throughput matters.
        let original =
            wire::parse(r.packet.ip, &self.bytes[..r.packet.len]).map_err(Error::Wire)?;
        let mut header = original.header;
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
        let count = original
            .payload
            .len()
            .saturating_sub(r.offset)
            .min(limit.saturating_sub(20 + used));
        if count == 0 && r.offset < original.payload.len() && emitted_sacks == 0 {
            return Err(EndpointError::ReservationMtuTooSmall);
        }
        let finished =
            r.offset + count == original.payload.len() && emitted_sacks == remaining_sacks;
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
            &original.payload[r.offset..r.offset + count],
            out,
        )
        .map_err(Error::Wire)?;
        r.emitted_bytes = count;
        r.emitted_sacks = emitted_sacks;
        r.finished = finished;
        // A cancelled backend observation must not masquerade as a retry's actual
        // submit timestamp. Scheduled/ACK observations remain owned by the stream.
        Ok(Transmit {
            len,
            tx_timestamp: None,
            ecn: if count == 0 { 0 } else { r.packet.ecn },
            ..r.packet
        })
    }
}
