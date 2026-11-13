use crate::{Error, RxPacketTimestamps, wire};
use core::num::NonZeroU16;

/// Validated by the TCP input path before any protocol state changes. The
/// producer must preserve coalescible flags/options and a fully checksummed
/// aggregate. A segment size describes payload, never IP/TCP headers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxPacketMetadata {
    pub timestamps: RxPacketTimestamps,
    pub tcp_segment_size: Option<NonZeroU16>,
    /// The receiving device verified the TCP checksum over exactly these
    /// bytes (Linux's CHECKSUM_UNNECESSARY), so input does not verify it
    /// again. False, the default: verified in software. Never true for a
    /// datagram other than the packet as the device received it (one
    /// reassembled from fragments, or handed over without the verdict).
    pub tcp_checksum_verified: bool,
}
impl RxPacketMetadata {
    pub fn validate_segment(self, segment: &wire::Segment<'_>) -> Result<(), Error> {
        if let Some(size) = self.tcp_segment_size
            && (usize::from(size.get()) > segment.payload.len()
                || segment.header.flags & wire::ACK == 0
                || segment.header.flags & (wire::SYN | wire::RST | wire::URG) != 0)
        {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// Estimate of the sender's current full data segment size. A larger sample
/// supplies immediate evidence. Two equal, unmarked smaller samples allow a
/// path-size decrease; a short application tail does not lower the estimate.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReceiveMss {
    value: u16,
    smaller: Option<u16>,
}
impl ReceiveMss {
    pub(crate) fn new(offer: u16) -> Self {
        Self {
            value: offer.min(536),
            smaller: None,
        }
    }
    pub(crate) fn value(self, offer: u16) -> u16 {
        self.value.min(offer)
    }
    pub(crate) fn observe(&mut self, size: usize, terminal: bool, offer: u16) {
        if size == 0 {
            return;
        }
        let sample = size.min(usize::from(offer)) as u16;
        self.value = self.value.min(offer);
        if sample >= self.value {
            self.value = sample;
            self.smaller = None;
        } else if terminal {
            self.smaller = None;
        } else if self.smaller == Some(sample) {
            self.value = sample;
            self.smaller = None;
        } else {
            self.smaller = Some(sample);
        }
    }
}
