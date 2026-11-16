pub use ntcp_buffer::{
    ChunkSlice, HeapChunkSource, Payload, PayloadSlice, RxFrame, RxFrameVtable,
    StablePayloadStorage, TxChunk, TxChunkSource, TxChunkVtable,
};
use std::io;

/// Header bytes owned by the sender, followed by immutable shared payload ranges.
/// Only the header may be copied by a zero-copy backend. Payload leases must be
/// retained until the device/driver has finished reading the original storage.
#[derive(Debug, Default)]
pub struct OwnedPacket {
    pub header: Vec<u8>,
    pub payload: Vec<Payload>,
}
impl OwnedPacket {
    pub fn checked_len(&self) -> Option<usize> {
        self.payload
            .iter()
            .try_fold(self.header.len(), |n, p| n.checked_add(p.len()))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZeroCopyCapabilities {
    pub max_payload_segments: usize,
    pub max_packet_len: usize,
}

/// One packet to transmit, borrowed for the call: the header bytes the
/// caller built, then the payload in order, as ranges of transmit chunks
/// and shared payloads. A backend copies what it sends before it returns,
/// or takes its own reference on a part's memory (a device reference on a
/// chunk, `PayloadSlice::to_payload`) and keeps it until the device is done
/// with it; it keeps no borrow.
#[derive(Clone, Copy, Debug)]
pub struct TxPacket<'a> {
    pub header: &'a [u8],
    pub payload: &'a [TxPart<'a>],
}
impl TxPacket<'_> {
    pub fn checked_len(&self) -> Option<usize> {
        self.payload
            .iter()
            .try_fold(self.header.len(), |n, p| n.checked_add(p.len()))
    }
}

/// A payload range of a `TxPacket`.
#[derive(Clone, Copy, Debug)]
pub enum TxPart<'a> {
    /// Bytes a copying write put in a transmit chunk.
    Chunk(ChunkSlice<'a>),
    /// Bytes of a payload the application shared.
    Shared(PayloadSlice<'a>),
}
impl<'a> TxPart<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        match self {
            Self::Chunk(slice) => slice.bytes(),
            Self::Shared(slice) => slice.bytes(),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Chunk(slice) => slice.len(),
            Self::Shared(slice) => slice.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// How `transmit_packet` hands a packet to the device: the options the
/// separate transmit methods take, together.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransmitRequest {
    /// The device completes the TCP checksum, as for
    /// `transmit_tcp_checksum_offload`.
    pub tcp_checksum_offload: bool,
    /// The packet is an aggregate the device segments, as for
    /// `transmit_segmented`.
    pub segmentation: Option<TcpSegmentationRequest>,
    /// TX timestamps requested, as for `transmit_with_timestamp`.
    pub timestamp: Option<TxTimestampRequest>,
    /// Send at this time, as for `transmit_at`.
    pub when: Option<TransmitTime>,
}

/// Why `transmit_packet` failed. Unsupported and InvalidInput certify that
/// nothing was submitted, so the caller may fall back (to a copy, to
/// software segmentation, to no timestamp); Other is uncertain and must not
/// authorize a fallback or a retransmission on its own, as for
/// `TcpSegmentationError`.
#[derive(Debug)]
pub enum TransmitError {
    Unsupported,
    InvalidInput,
    Other(io::Error),
}

impl std::fmt::Display for TransmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("transmit request unsupported (not submitted)"),
            Self::InvalidInput => f.write_str("invalid transmit request (not submitted)"),
            Self::Other(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for TransmitError {}

impl From<TcpSegmentationError> for TransmitError {
    fn from(error: TcpSegmentationError) -> Self {
        match error {
            TcpSegmentationError::Unsupported => Self::Unsupported,
            TcpSegmentationError::InvalidInput => Self::InvalidInput,
            TcpSegmentationError::Other(error) => Self::Other(error),
        }
    }
}

// An error from a transmit method that validates before it submits:
// Unsupported, and InvalidInput where the method says so, certify that
// nothing was submitted; anything else stays uncertain.
fn certified(error: io::Error, invalid_input_certified: bool) -> TransmitError {
    match error.kind() {
        io::ErrorKind::Unsupported => TransmitError::Unsupported,
        io::ErrorKind::InvalidInput if invalid_input_certified => TransmitError::InvalidInput,
        _ => TransmitError::Other(error),
    }
}

// One contiguous packet through the transmit method `request` names. The
// separate methods take no combination of segmentation with timestamps or
// scheduling, nor of checksum offload with either: those are Unsupported
// here, before anything is submitted.
fn transmit_contiguous<P: PacketIo + ?Sized>(
    io: &mut P,
    packet: &[u8],
    request: TransmitRequest,
) -> Result<TxOutcome, TransmitError> {
    let TransmitRequest {
        tcp_checksum_offload,
        segmentation,
        timestamp,
        when,
    } = request;
    if let Some(segmentation) = segmentation {
        if timestamp.is_some() || when.is_some() {
            return Err(TransmitError::Unsupported);
        }
        return Ok(io.transmit_segmented(packet, segmentation)?);
    }
    if tcp_checksum_offload && (timestamp.is_some() || when.is_some()) {
        return Err(TransmitError::Unsupported);
    }
    if let Some(when) = when {
        return io
            .transmit_at(packet, when, timestamp)
            .map_err(|e| certified(e, true));
    }
    if let Some(timestamp) = timestamp {
        return io
            .transmit_with_timestamp(packet, timestamp)
            .map_err(|e| certified(e, true));
    }
    if tcp_checksum_offload {
        return io
            .transmit_tcp_checksum_offload(packet)
            .map_err(|e| certified(e, false));
    }
    io.transmit(packet).map_err(TransmitError::Other)
}

/// A received frame and what the device reported about it; `metadata.len`
/// is the frame's length.
#[derive(Debug)]
pub struct ReceivedFrame {
    pub frame: RxFrame,
    pub metadata: ReceivedPacket,
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod linux;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketLayer {
    Ip,
    Ethernet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxOutcome {
    Submitted,
    WouldBlock,
    // Synchronous local rejection: no packet, timestamp request or scheduled
    // object was submitted. Never report this for unknown/asynchronous errors.
    Rejected,
}

// Explicit aggregate submission; all maxima are in layer() bytes, not IP MTU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegmentationCapabilities {
    pub max_aggregate_len: usize,
    pub max_segments: usize,
    // Sum of emitted layer bytes, including repeated headers and L2 padding,
    // excluding FCS/preamble.
    pub max_wire_bytes: usize,
    pub local_ip_mtu: u32,
    // The device keeps PSH and FIN only on the last emitted segment / CWR
    // only on the first, as Linux does (tcp_gso_segment, NETIF_F_TSO_ECN).
    // False: the aggregate must not carry it. Other flags and TCP options
    // are backend-specific.
    pub allow_psh: bool,
    pub allow_cwr: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegmentationRequest {
    pub segment_payload_len: usize,
}

#[derive(Debug)]
pub enum TcpSegmentationError {
    // Both typed rejections certify no submission; software fallback is safe.
    Unsupported,
    InvalidInput,
    // Unknown failure: MUST NOT authorize fallback or retransmit on its own.
    Other(io::Error),
}

impl std::fmt::Display for TcpSegmentationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("TCP segmentation unsupported (not submitted)"),
            Self::InvalidInput => f.write_str("invalid TCP aggregate (not submitted)"),
            Self::Other(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for TcpSegmentationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampSource {
    Software,
    Hardware,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampPoint {
    UserReceive,
    UserTransmit,
    KernelReceive,
    KernelTransmit,
    DeviceReceive,
    DeviceTransmit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockDomain {
    Realtime,
    Monotonic,
    Device(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampUnit {
    Nanoseconds,
    // Host-assigned calibration identity. No implicit conversion to nanoseconds.
    RawTicks { identity: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockDescriptor {
    pub domain: ClockDomain,
    pub unit: TimestampUnit,
}

// Absolute value in an explicit clock; no implicit clock conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitTime {
    pub value: u64,
    pub clock: ClockDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxSchedulingCapabilities {
    pub clock: ClockDescriptor,
    pub hardware: bool,
}

// Best-effort negative observation, not a delivery completion. Requested time
// is identity, not a unique cookie. errno/code are native backend diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxSchedulingError {
    pub when: TransmitTime,
    pub errno: u32,
    pub code: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketTimestamp {
    pub value: u64,
    pub source: TimestampSource,
    pub point: TimestampPoint,
    pub clock: ClockDescriptor,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketTimestamps {
    pub software: Option<PacketTimestamp>,
    pub hardware: Option<PacketTimestamp>,
}

/// What the receiving device reported about a packet's transport (TCP or
/// UDP) checksum, as DPDK reports it (RTE_MBUF_F_RX_L4_CKSUM_*). Only Good
/// lets a consumer skip its own verification, as Linux trusts a driver's
/// CHECKSUM_UNNECESSARY (skb_checksum_init in tcp_v4_rcv).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RxChecksum {
    /// Not verified by the device, or not reported: DPDK's UNKNOWN, and its
    /// NONE (the packet's checksum field is not final).
    #[default]
    Unknown,
    /// The device verified it over exactly the bytes delivered.
    Good,
    /// The device found it wrong. A consumer verifies it again, as Linux
    /// drivers hand such a packet up as CHECKSUM_NONE (ixgbe_rx_checksum,
    /// mlx5e_handle_csum): the device's verdict alone drops nothing.
    Bad,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedPacket {
    pub len: usize,
    pub timestamps: PacketTimestamps,
    // Original full TCP segment payload size of a checksummed aggregate.
    // None means ordinary raw ingress, never an inferred segmentation hint.
    pub tcp_segment_size: Option<std::num::NonZeroU16>,
    // The device's verdict on this packet's transport checksum; Unknown
    // unless the backend reports one.
    pub l4_checksum: RxChecksum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxTimestampRequest {
    pub cookie: u64,
    pub software: bool,
    pub hardware: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxTimestampCompletion {
    pub cookie: u64,
    pub timestamp: PacketTimestamp,
}

// Packet buffers a backend or its device ran short of, cumulative since it
// started, as the device reports them (a host that resets the device's
// counters resets these). Zero where the backend has no such buffers or
// does not know. None of these packets reached the stack, or left it: they
// are not discards the stack made.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceCounters {
    // Receive buffer allocation failures (DPDK rte_eth_stats rx_nombuf): the
    // driver found its receive pool empty while refilling the RX ring.
    // Failures, not packets: the packets the device then had no posted
    // buffer for are rx_missed.
    pub rx_nombuf: u64,
    // Received packets the device dropped for want of a posted receive
    // buffer, its RX ring full (DPDK imissed, mlx5's out_of_buffer; Linux's
    // rx_missed_errors).
    pub rx_missed: u64,
    // Transmit attempts that found the transmit pool empty. Each returned
    // WouldBlock and kept nothing: the packet stays the caller's to retry.
    pub tx_nombuf: u64,
}

/// When a backend's device is done with a frame it submitted, for
/// autocorking: Linux's tcp_push holds a small write while an earlier data
/// skb of the socket is still in the qdisc or device (sk_wmem_alloc, freed
/// at TX completion). Completion only decides whether a push holds; the
/// next drive sends whatever a push held, whatever the completion state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TxCompletion {
    /// Done when `transmit` returns: the frame was copied out (TUN,
    /// AF_PACKET, in-memory wires). Never holds.
    #[default]
    Synchronous,
    /// Learned only when the owner polls the device again: a frame
    /// submitted before a drive counts as completed at that drive (DPDK,
    /// whose PMD frees transmitted mbufs only in later bursts).
    NextPoll,
    /// Completions counted in submission order (`tx_submissions_completed`),
    /// as a completion ring reports them (AF_XDP).
    Counter,
}

// Enabled adapter paths, not a guarantee that every packet has metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimestampCapabilities {
    pub rx_software: bool,
    pub rx_hardware: bool,
    pub tx_software: bool,
    pub tx_hardware: bool,
    pub tx_completion_capacity: usize,
}

// Packet operations do bounded, nonblocking work on one complete packet. The caller
// owns its buffers: receive copies into out, transmit retains no borrow.
// Ordinary transmit transfers a copy; explicit transmit_zero_copy instead
// retains owning immutable leases until reclamation. Submitted implies neither
// wire delivery nor a TCP acknowledgement. DMA buffers are reclaimed internally.
// None/WouldBlock leaves the caller free to retry. Errors never report a
// truncated packet as valid. Drivers, threads and scheduling belong to callers.
pub trait PacketIo {
    fn layer(&self) -> PacketLayer;

    fn zero_copy_capabilities(&self) -> Option<ZeroCopyCapabilities> {
        None
    }
    // Request reclamation of at most budget completed transmissions. This is
    // service work, not proof of wire delivery or a TCP acknowledgement. An
    // asynchronous shared backend must also make progress when TX is idle.
    fn reclaim_transmit(&mut self, _budget: usize) -> io::Result<usize> {
        Ok(0)
    }
    // Storage registration/mapping is backend-specific. A positive result must
    // remain valid while the borrowed backend configuration is unchanged.
    fn zero_copy_payload_supported(&self, _payload: &Payload) -> bool {
        false
    }
    // Submitted retains shared leases until actual TX reclamation. WouldBlock
    // retains nothing. Unsupported/InvalidInput certify no submission; all other
    // errors must be treated as uncertain, just as ordinary transmit errors.
    fn transmit_zero_copy(&mut self, _packet: &OwnedPacket) -> io::Result<TxOutcome> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared TX unsupported",
        ))
    }

    // Current interface IP MTU, including IP header, excluding L2/FCS.
    // Read-only control-plane query; unknown is distinct from a failed query.
    // May block: Linux's synchronous rtnetlink send can wait for kernel locks
    // before the response poll. Call outside latency-sensitive packet service.
    // Linux queries use the caller's current network namespace.
    //= https://www.rfc-editor.org/rfc/rfc4821#section-3
    //= reason=PacketIo reports IP MTU separately from layer-unit buffer capacity. Executable backend fixture distinguishes9000 IP MTU from3514 Ethernet/3500 IP capacity; no physical-link enforcement claim.
    //# MTU: Maximum Transmission Unit, the size in bytes of the largest IP packet,
    //# including the IP header and payload, that can be transmitted on a link or path. Note
    //# that this could more properly be called the IP MTU, to be consistent with how other
    //# standards organizations use the acronym MTU.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-3
    //= reason=PacketIo reports IP MTU separately from layer-unit buffer capacity. Executable backend fixture distinguishes9000 IP MTU from3514 Ethernet/3500 IP capacity; no physical-link enforcement claim.
    //# Link MTU: The Maximum Transmission Unit, i.e., maximum IP packet size in bytes, that
    //# can be conveyed in one piece over a link. Be aware that this definition is different
    //# from the definition used by other standards organizations.

    //= https://www.rfc-editor.org/rfc/rfc4821#section-3
    //= reason=PacketIo reports IP MTU separately from layer-unit buffer capacity. Executable backend fixture distinguishes9000 IP MTU from3514 Ethernet/3500 IP capacity; no physical-link enforcement claim.
    //# For IETF documents, link MTU is uniformly defined as the IP MTU over the link. This
    //# includes the IP header, but excludes link layer headers and other framing that is
    //# not part of IP or the IP payload.

    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        Ok(None)
    }

    // Independent adapter buffer limit in layer() bytes, not a path/link MTU.
    // Ethernet includes its 14-byte header, not FCS. None means unknown.
    fn max_packet_len(&self) -> Option<usize> {
        None
    }

    // Host-local output policy metadata, never encoded into packet bytes.
    // Owners serialize this setting with submission and must restore zero for
    // unmarked flows. Unsupported backends reject nonzero marks explicitly.
    fn packet_mark_supported(&self) -> bool {
        false
    }
    fn set_packet_mark(&mut self, mark: u32) -> io::Result<()> {
        if mark == 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "packet marks unsupported",
            ))
        }
    }

    // Read on demand, never on the packet path: a backend may ask its device
    // (DPDK rte_eth_stats_get, which mlx5 serves with a system call).
    fn device_counters(&self) -> DeviceCounters {
        DeviceCounters::default()
    }

    // How the device completes what this backend submits (`TxCompletion`).
    fn tx_completion(&self) -> TxCompletion {
        TxCompletion::Synchronous
    }
    // A `TxCompletion::Counter` backend: how many of its submissions (each
    // transmit call that returned Submitted, an aggregate one) the device
    // has completed, oldest first. Read on the push path: a load, no device
    // access.
    fn tx_submissions_completed(&self) -> u64 {
        0
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>>;
    // Synchronous TX EMSGSIZE rejects this packet before submission, including
    // timestamp/scheduled TX. Other errors do NOT imply non-submission; async
    // scheduling errors are observations, not synchronous TX rejections.
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome>;

    fn tcp_segmentation_capabilities(&self) -> Option<TcpSegmentationCapabilities> {
        None
    }

    // The device computes the TCP checksum of every frame handed to
    // transmit_tcp_checksum_offload, as a Linux device with NETIF_F_IP_CSUM
    // and NETIF_F_IPV6_CSUM completes a CHECKSUM_PARTIAL skb.
    fn tcp_checksum_offload(&self) -> bool {
        false
    }

    // `transmit` of one TCP segment over IPv4 (any header length) or IPv6
    // (base header, Next Header TCP), its IPv4 header checksum complete and
    // its TCP checksum field holding the pseudo-header sum, which the
    // device completes. Unsupported certifies no submission; other
    // outcomes as for transmit.
    fn transmit_tcp_checksum_offload(&mut self, _packet: &[u8]) -> io::Result<TxOutcome> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP checksum offload unsupported",
        ))
    }

    // Contiguous normal-length aggregate headers plus payload, not a wire packet.
    // Backend-specific header/checksum restrictions apply. No scheduling or TX
    // timestamp combination. Submitted transfers the WHOLE aggregate copy;
    // WouldBlock transfers NONE. Only typed rejections certify safe fallback.
    fn transmit_segmented(
        &mut self,
        _packet: &[u8],
        _request: TcpSegmentationRequest,
    ) -> Result<TxOutcome, TcpSegmentationError> {
        Err(TcpSegmentationError::Unsupported)
    }

    fn tx_scheduling_capabilities(&self) -> Option<TxSchedulingCapabilities> {
        None
    }

    // Validate clock, horizon and optional timestamp sources before submission.
    // WouldBlock consumes neither packet nor request. Never fall back to an
    // immediate send on failure. Submitted is ownership, NOT scheduling success.
    fn transmit_at(
        &mut self,
        _packet: &[u8],
        _when: TransmitTime,
        _timestamp: Option<TxTimestampRequest>,
    ) -> io::Result<TxOutcome> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "scheduled TX unsupported",
        ))
    }

    // Bounded nonblocking polling; absence is NOT evidence of delivery. When
    // timestamps share a queue, callers must budget both polling APIs.
    fn poll_tx_scheduling_error(&mut self) -> io::Result<Option<TxSchedulingError>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "scheduled TX unsupported",
        ))
    }

    fn timestamp_capabilities(&self) -> TimestampCapabilities {
        TimestampCapabilities::default()
    }

    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        self.receive(out).map(|packet| {
            packet.map(|len| ReceivedPacket {
                len,
                timestamps: PacketTimestamps::default(),
                tcp_segment_size: None,
                l4_checksum: RxChecksum::Unknown,
            })
        })
    }

    // Validate every requested source before submission. Unsupported requests
    // must have no TX side effects. WouldBlock consumes neither packet nor
    // request. Implementations bound outstanding requests/completions and
    // preserve the opaque cookie; callers keep cookies unique while pending.
    // Requesting both sources may produce two separate completions. Submission
    // alone is not a device timestamp, and completion is not a TCP ACK.
    fn transmit_with_timestamp(
        &mut self,
        _packet: &[u8],
        request: TxTimestampRequest,
    ) -> io::Result<TxOutcome> {
        if !request.software && !request.hardware {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty timestamp request",
            ));
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TX timestamps unsupported",
        ))
    }

    // Release an outstanding request without affecting its submitted packet.
    // True means a request was cancelled; false means none was pending. A
    // backend must discard late completions without binding them to a reused
    // cookie. Cancellation is bounded and nonblocking like completion polling.
    fn cancel_tx_timestamp(&mut self, _cookie: u64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TX timestamp cancellation unsupported",
        ))
    }

    // Bounded, nonblocking work returning at most one observation. None means
    // not ready; consumers must budget polls. No clock sampling is implied.
    fn poll_tx_timestamp(&mut self) -> io::Result<Option<TxTimestampCompletion>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TX timestamps unsupported",
        ))
    }

    // One received packet as a frame the caller keeps, as receive_with_metadata
    // receives one. A backend that receives into its own memory (a DPDK mbuf,
    // an AF_XDP UMEM frame) hands that over and ignores scratch. The default,
    // for every backend that copies, receives into scratch, sized as for
    // receive, and copies the packet into a heap frame of its length, so the
    // frame's truesize is what it holds.
    fn receive_frame(&mut self, scratch: &mut [u8]) -> io::Result<Option<ReceivedFrame>> {
        let Some(metadata) = self.receive_with_metadata(scratch)? else {
            return Ok(None);
        };
        let bytes = scratch.get(..metadata.len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "backend returned an invalid packet length",
            )
        })?;
        Ok(Some(ReceivedFrame {
            frame: RxFrame::copy_from_slice(bytes),
            metadata,
        }))
    }

    // One packet given as header bytes and payload ranges, sent as the
    // request says. Outcomes as for the transmit method the request names.
    // The default gathers the packet into one buffer and calls that method:
    // transmit_segmented, transmit_at, transmit_with_timestamp,
    // transmit_tcp_checksum_offload or transmit. A combination none of them
    // takes is Unsupported, with nothing submitted.
    fn transmit_packet(
        &mut self,
        packet: &TxPacket<'_>,
        request: TransmitRequest,
    ) -> Result<TxOutcome, TransmitError> {
        let len = packet.checked_len().ok_or(TransmitError::InvalidInput)?;
        let mut contiguous = Vec::with_capacity(len);
        contiguous.extend_from_slice(packet.header);
        for part in packet.payload {
            contiguous.extend_from_slice(part.bytes());
        }
        transmit_contiguous(self, &contiguous, request)
    }

    // Where an owner of this backend gets its transmit chunks: memory the
    // backend can give the device by reference. Called once per owner; the
    // source and its chunks outlive any borrow of the backend. The default
    // allocates heap chunks, for a backend that copies on transmit.
    fn tx_chunk_source(&self) -> Box<dyn TxChunkSource> {
        Box::new(HeapChunkSource::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_defaults_never_submit_timestamp_requests() {
        struct Mock {
            transmitted: usize,
            received: bool,
        }
        impl PacketIo for Mock {
            fn layer(&self) -> PacketLayer {
                PacketLayer::Ip
            }
            fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
                if self.received {
                    return Ok(None);
                }
                if out.is_empty() {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                out[0] = 7;
                self.received = true;
                Ok(Some(1))
            }
            fn transmit(&mut self, _: &[u8]) -> io::Result<TxOutcome> {
                self.transmitted += 1;
                Ok(TxOutcome::Submitted)
            }
        }
        let mut mock = Mock {
            transmitted: 0,
            received: false,
        };
        let io: &mut dyn PacketIo = &mut mock;
        assert_eq!(io.reclaim_transmit(0).unwrap(), 0);
        assert_eq!(io.reclaim_transmit(1).unwrap(), 0);
        assert_eq!(io.local_ip_mtu().unwrap(), None);
        assert_eq!(io.max_packet_len(), None);
        assert_eq!(io.tcp_segmentation_capabilities(), None);
        assert!(!io.tcp_checksum_offload());
        assert_eq!(
            io.transmit_tcp_checksum_offload(&[1]).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(matches!(
            io.transmit_segmented(
                &[],
                TcpSegmentationRequest {
                    segment_payload_len: 0,
                }
            ),
            Err(TcpSegmentationError::Unsupported)
        ));
        assert_eq!(
            io.timestamp_capabilities(),
            TimestampCapabilities::default()
        );
        assert!(io.receive_with_metadata(&mut []).is_err());
        let mut out = [0];
        assert_eq!(
            io.receive_with_metadata(&mut out).unwrap(),
            Some(ReceivedPacket {
                len: 1,
                timestamps: PacketTimestamps::default(),
                tcp_segment_size: None,
                l4_checksum: RxChecksum::Unknown,
            })
        );
        assert_eq!(out, [7]);
        assert_eq!(io.receive_with_metadata(&mut out).unwrap(), None);
        for (software, hardware) in [(true, false), (false, true), (true, true), (false, false)] {
            let error = io
                .transmit_with_timestamp(
                    &[1],
                    TxTimestampRequest {
                        cookie: u64::MAX,
                        software,
                        hardware,
                    },
                )
                .unwrap_err();
            assert_eq!(
                error.kind(),
                if software || hardware {
                    io::ErrorKind::Unsupported
                } else {
                    io::ErrorKind::InvalidInput
                }
            );
        }
        assert_eq!(
            io.poll_tx_timestamp().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            io.cancel_tx_timestamp(u64::MAX).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(io.tx_scheduling_capabilities(), None);
        assert_eq!(
            io.transmit_at(
                &[1],
                TransmitTime {
                    value: 123,
                    clock: ClockDescriptor {
                        domain: ClockDomain::Monotonic,
                        unit: TimestampUnit::Nanoseconds
                    }
                },
                None
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            io.poll_tx_scheduling_error().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(!io.packet_mark_supported());
        io.set_packet_mark(0).unwrap();
        assert_eq!(
            io.set_packet_mark(1).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(mock.transmitted, 0);
        assert_eq!(mock.transmit(&[1]).unwrap(), TxOutcome::Submitted);
        assert_eq!(mock.transmitted, 1);
    }

    // Records which transmit method each call reached, and with what bytes.
    #[derive(Default)]
    struct Recorder {
        calls: Vec<(&'static str, Vec<u8>)>,
        inbound: Vec<Vec<u8>>,
        // A length to report instead of the packet's.
        lie: Option<usize>,
        segmented: Option<fn() -> TcpSegmentationError>,
        timestamp: Option<io::ErrorKind>,
    }
    impl PacketIo for Recorder {
        fn layer(&self) -> PacketLayer {
            PacketLayer::Ip
        }
        fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
            let Some(packet) = self.inbound.pop() else {
                return Ok(None);
            };
            out[..packet.len()].copy_from_slice(&packet);
            Ok(Some(self.lie.unwrap_or(packet.len())))
        }
        fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
            self.calls.push(("transmit", packet.to_vec()));
            Ok(TxOutcome::Submitted)
        }
        fn transmit_tcp_checksum_offload(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
            self.calls.push(("offload", packet.to_vec()));
            Ok(TxOutcome::WouldBlock)
        }
        fn transmit_segmented(
            &mut self,
            packet: &[u8],
            request: TcpSegmentationRequest,
        ) -> Result<TxOutcome, TcpSegmentationError> {
            assert_eq!(request.segment_payload_len, 3);
            self.calls.push(("segmented", packet.to_vec()));
            self.segmented
                .map_or(Ok(TxOutcome::Submitted), |e| Err(e()))
        }
        fn transmit_with_timestamp(
            &mut self,
            packet: &[u8],
            request: TxTimestampRequest,
        ) -> io::Result<TxOutcome> {
            assert_eq!(request.cookie, 9);
            self.calls.push(("timestamp", packet.to_vec()));
            match self.timestamp {
                Some(kind) => Err(kind.into()),
                None => Ok(TxOutcome::Submitted),
            }
        }
        fn transmit_at(
            &mut self,
            packet: &[u8],
            when: TransmitTime,
            timestamp: Option<TxTimestampRequest>,
        ) -> io::Result<TxOutcome> {
            assert_eq!(when.value, 77);
            self.calls.push((
                if timestamp.is_some() {
                    "at+timestamp"
                } else {
                    "at"
                },
                packet.to_vec(),
            ));
            Ok(TxOutcome::Rejected)
        }
    }

    #[test]
    fn receive_frame_copies_into_a_heap_frame_of_the_packets_length() {
        let mut io = Recorder {
            inbound: vec![vec![1, 2, 3], vec![]],
            ..Default::default()
        };
        let mut scratch = [0; 64];
        let empty = io.receive_frame(&mut scratch).unwrap().unwrap();
        assert!(empty.frame.is_empty());
        let received = io.receive_frame(&mut scratch).unwrap().unwrap();
        assert_eq!(received.frame.as_slice(), &[1, 2, 3]);
        assert_eq!(received.frame.truesize(), 3);
        assert_eq!(received.metadata.len, 3);
        assert_eq!(received.metadata.l4_checksum, RxChecksum::Unknown);
        assert_ne!(received.frame.as_ptr(), scratch.as_ptr());
        assert!(io.receive_frame(&mut scratch).unwrap().is_none());

        // A backend reporting more than the scratch holds is refused.
        io.inbound.push(vec![5; 4]);
        io.lie = Some(65);
        let error = io.receive_frame(&mut scratch).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn transmit_packet_gathers_and_routes_each_request_to_its_method() {
        let mut chunk = TxChunk::heap(16);
        chunk.append(&[10, 11, 12, 13]);
        let shared = Payload::from_vec(vec![20, 21, 22]);
        let parts = [
            TxPart::Chunk(ChunkSlice::new(&chunk, 1..3).unwrap()),
            TxPart::Shared(PayloadSlice::new(&shared, 0..2).unwrap()),
            TxPart::Chunk(ChunkSlice::new(&chunk, 3..4).unwrap()),
        ];
        let packet = TxPacket {
            header: &[1, 2],
            payload: &parts,
        };
        assert_eq!(packet.checked_len(), Some(7));
        let wire = vec![1, 2, 11, 12, 20, 21, 13];
        let segmentation = Some(TcpSegmentationRequest {
            segment_payload_len: 3,
        });
        let timestamp = Some(TxTimestampRequest {
            cookie: 9,
            software: true,
            hardware: false,
        });
        let when = Some(TransmitTime {
            value: 77,
            clock: ClockDescriptor {
                domain: ClockDomain::Monotonic,
                unit: TimestampUnit::Nanoseconds,
            },
        });
        let mut io = Recorder::default();
        let send = |io: &mut Recorder, request| io.transmit_packet(&packet, request);
        let routes = [
            (TransmitRequest::default(), "transmit", TxOutcome::Submitted),
            (
                TransmitRequest {
                    tcp_checksum_offload: true,
                    ..Default::default()
                },
                "offload",
                TxOutcome::WouldBlock,
            ),
            (
                TransmitRequest {
                    tcp_checksum_offload: true,
                    segmentation,
                    ..Default::default()
                },
                "segmented",
                TxOutcome::Submitted,
            ),
            (
                TransmitRequest {
                    timestamp,
                    ..Default::default()
                },
                "timestamp",
                TxOutcome::Submitted,
            ),
            (
                TransmitRequest {
                    when,
                    ..Default::default()
                },
                "at",
                TxOutcome::Rejected,
            ),
            (
                TransmitRequest {
                    when,
                    timestamp,
                    ..Default::default()
                },
                "at+timestamp",
                TxOutcome::Rejected,
            ),
        ];
        for (request, method, outcome) in routes {
            assert_eq!(send(&mut io, request).unwrap(), outcome, "{method}");
            assert_eq!(io.calls.pop().unwrap(), (method, wire.clone()));
            assert!(io.calls.is_empty());
        }

        // Combinations no separate method takes submit nothing.
        for request in [
            TransmitRequest {
                segmentation,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                when,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                when,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                send(&mut io, request),
                Err(TransmitError::Unsupported)
            ));
        }
        assert!(io.calls.is_empty());

        // Typed rejections stay typed; other failures stay uncertain.
        io.segmented = Some(|| TcpSegmentationError::InvalidInput);
        let request = TransmitRequest {
            segmentation,
            ..Default::default()
        };
        assert!(matches!(
            send(&mut io, request),
            Err(TransmitError::InvalidInput)
        ));
        io.segmented = Some(|| TcpSegmentationError::Other(io::ErrorKind::Unsupported.into()));
        assert!(matches!(
            send(&mut io, request),
            Err(TransmitError::Other(_))
        ));
        let request = TransmitRequest {
            timestamp,
            ..Default::default()
        };
        for (kind, certified) in [
            (io::ErrorKind::Unsupported, true),
            (io::ErrorKind::InvalidInput, true),
            (io::ErrorKind::Other, false),
        ] {
            io.timestamp = Some(kind);
            match send(&mut io, request) {
                Err(TransmitError::Other(error)) => {
                    assert!(!certified);
                    assert_eq!(error.kind(), kind);
                }
                Err(TransmitError::Unsupported | TransmitError::InvalidInput) => {
                    assert!(certified)
                }
                Ok(_) => panic!("{kind:?} reported as sent"),
            }
        }
    }

    #[test]
    fn transmit_packet_defaults_reach_the_legacy_defaults_and_chunks_come_from_the_heap() {
        // Only the required methods, as Stackbench's and Xylem's wires.
        struct Minimal(Vec<Vec<u8>>);
        impl PacketIo for Minimal {
            fn layer(&self) -> PacketLayer {
                PacketLayer::Ethernet
            }
            fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
                Ok(None)
            }
            fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
                self.0.push(packet.to_vec());
                Ok(TxOutcome::Submitted)
            }
        }
        let mut minimal = Minimal(Vec::new());
        let io: &mut dyn PacketIo = &mut minimal;
        let packet = TxPacket {
            header: &[1, 2, 3],
            payload: &[],
        };
        assert_eq!(
            io.transmit_packet(&packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        for request in [
            TransmitRequest {
                tcp_checksum_offload: true,
                ..Default::default()
            },
            TransmitRequest {
                segmentation: Some(TcpSegmentationRequest {
                    segment_payload_len: 1,
                }),
                ..Default::default()
            },
            TransmitRequest {
                timestamp: Some(TxTimestampRequest {
                    cookie: 1,
                    software: true,
                    hardware: false,
                }),
                ..Default::default()
            },
        ] {
            assert!(matches!(
                io.transmit_packet(&packet, request),
                Err(TransmitError::Unsupported)
            ));
        }
        // An empty timestamp request is refused before anything is sent.
        let empty = TransmitRequest {
            timestamp: Some(TxTimestampRequest {
                cookie: 1,
                software: false,
                hardware: false,
            }),
            ..Default::default()
        };
        assert!(matches!(
            io.transmit_packet(&packet, empty),
            Err(TransmitError::InvalidInput)
        ));
        assert!(io.receive_frame(&mut [0; 16]).unwrap().is_none());
        let mut source = io.tx_chunk_source();
        assert_eq!(source.chunk_size(), HeapChunkSource::DEFAULT_CHUNK_SIZE);
        assert_eq!(source.allocate().unwrap().capacity(), 16 * 1024);
        assert_eq!(minimal.0, vec![vec![1, 2, 3]]);
    }
}
