// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use ntcp_egress::{FlowKey, Metadata, Outcome, PacketId, Poll, Scheduler};

struct Entry {
    owner: Option<ConnectionId>,
    flow: FlowKey,
    attempt: ntcp::TransmitAttempt,
    timestamp: Option<ntcp::TxTimestampToken>,
    packet: Option<PacketId>,
    deadline: Option<u64>,
    not_before: u64,
    waiting_mtu: bool,
    mark: u32,
    context: Option<ntcp_host::EgressContext>,
    // Resident IP bytes only: neither Ethernet padding nor shared payload.
    ip_len: usize,
    blocked: Option<ntcp_host::Error>,
    // The Host's evidence reservation for this physical attempt. Kept across
    // WouldBlock and retained rejections (the replacement attempt reuses it);
    // consumed by a sealed outcome; cancelled when the entry is cleared.
    ticket: Option<ntcp_host::SubmissionTicket>,
}
struct TxSlot {
    bytes: Vec<u8>,
    entry: Option<Entry>,
    shared: ntcp_io::OwnedPacket,
}
struct RxSlot {
    // A retained TCP segment is a complete datagram, never a fragment:
    // its bytes and processed Host envelope (None in Host-less fixtures).
    bytes: Vec<u8>,
    envelope: Option<ntcp_host::ProcessedEnvelope>,
    owner: Option<ConnectionId>,
    // A Host-dispatched ICMP report deferred for this exact owner generation.
    icmp: Option<ntcp_host::DeferredIcmp>,
    stamps: ntcp::RxPacketTimestamps,
    segment_size: Option<core::num::NonZeroU16>,
}
pub(super) struct Egress {
    scheduler: Scheduler<usize>,
    tx: Vec<TxSlot>,
    rx: Vec<RxSlot>,
    received: VecDeque<usize>,
    candidates: Vec<ConnectionId>,
    packet_capacity: usize,
    // Largest retained input: a physical packet or a reassembled datagram.
    rx_capacity: usize,
    cursor: usize,
    shared_segments: usize,
}
fn buffer(size: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| ENOMEM)?;
    Ok(bytes)
}
impl Egress {
    pub(super) fn shared_enabled(&self) -> bool {
        self.shared_segments != 0
    }
    fn new(
        capacity: usize,
        packet_capacity: usize,
        rx_capacity: usize,
        connections: usize,
    ) -> Result<Self> {
        let retained = capacity.checked_mul(packet_capacity).ok_or(EINVAL)?;
        let scheduler = Scheduler::new(
            1,
            ntcp_egress::Config {
                max_flows: capacity,
                max_packets: capacity,
                max_retained_bytes: retained,
                quantum: 1514,
            },
        )
        .map_err(|_| ENOMEM)?;
        // Handles never leave this owner/scheduler lifetime. Fixed shared slots,
        // not capacity packets for every possible TCP connection.
        let mut tx = Vec::new();
        let mut rx = Vec::new();
        let mut received = VecDeque::new();
        let mut candidates = Vec::new();
        tx.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
        rx.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
        received.try_reserve_exact(capacity).map_err(|_| ENOMEM)?;
        candidates
            .try_reserve_exact(connections)
            .map_err(|_| ENOMEM)?;
        for _ in 0..capacity {
            tx.push(TxSlot {
                bytes: buffer(packet_capacity)?,
                entry: None,
                shared: ntcp_io::OwnedPacket::default(),
            });
            rx.push(RxSlot {
                bytes: buffer(rx_capacity)?,
                envelope: None,
                owner: None,
                icmp: None,
                stamps: ntcp::RxPacketTimestamps::default(),
                segment_size: None,
            });
        }
        Ok(Self {
            scheduler,
            tx,
            rx,
            received,
            candidates,
            packet_capacity,
            rx_capacity,
            cursor: 0,
            shared_segments: 0,
        })
    }
    #[cfg(test)]
    pub(super) fn attempt(&self, owner: ConnectionId) -> ntcp::TransmitAttempt {
        self.tx
            .iter()
            .filter_map(|slot| slot.entry.as_ref())
            .find(|entry| entry.owner == Some(owner))
            .unwrap()
            .attempt
    }
    #[cfg(test)]
    pub(super) fn context(&self, owner: ConnectionId) -> Option<ntcp_host::EgressContext> {
        self.tx
            .iter()
            .filter_map(|s| s.entry.as_ref())
            .find(|e| e.owner == Some(owner))
            .and_then(|e| e.context)
    }
    #[cfg(test)]
    pub(super) fn blocked(&self, owner: ConnectionId) -> Option<ntcp_host::Error> {
        self.tx
            .iter()
            .filter_map(|s| s.entry.as_ref())
            .find(|e| e.owner == Some(owner))
            .and_then(|e| e.blocked)
    }
    pub(super) fn mtu_refreshed(&mut self) {
        for slot in &mut self.tx {
            if let Some(entry) = &mut slot.entry {
                entry.waiting_mtu = false;
            }
        }
    }
    pub(super) fn has_held(&self) -> bool {
        self.tx.iter().any(|s| s.entry.is_some()) || !self.received.is_empty()
    }
    pub(super) fn retained_rx(&self, id: ConnectionId) -> bool {
        self.rx.iter().any(|slot| slot.owner == Some(id))
    }
    // Test fixture: substitute the frame retained for `id`, keeping its
    // deferred association, to model a quote that correlates elsewhere.
    #[cfg(test)]
    pub(super) fn replace_retained_rx(&mut self, id: ConnectionId, bytes: &[u8]) {
        let slot = self.rx.iter_mut().find(|slot| slot.owner == Some(id)).unwrap();
        slot.bytes.clear();
        slot.bytes.extend_from_slice(bytes);
    }
    // Every caller has certified that the attempt was not submitted (or was
    // finalized): an unconsumed evidence reservation is cancelled with it.
    fn clear(&mut self, index: usize, host: &mut Option<ntcp_host::Host>) -> Result<()> {
        let slot = &mut self.tx[index];
        let mut entry = slot.entry.take().ok_or(EIO)?;
        if let (Some(host), Some(ticket)) = (host, entry.ticket.take()) {
            host.cancel_submission(ticket);
        }
        if let Some(packet) = entry.packet {
            self.scheduler.cancel(packet).map_err(|_| EIO)?;
        }
        self.scheduler.disable_flow(entry.flow).map_err(|_| EIO)?;
        slot.bytes.clear();
        slot.shared.header.clear();
        slot.shared.payload.clear();
        Ok(())
    }
    pub(super) fn wait(&self, now: u64, core: Option<u64>) -> std::time::Duration {
        core.into_iter()
            .chain(self.tx.iter().filter_map(|s| {
                let entry = s.entry.as_ref()?;
                entry.packet.map(|_| entry.not_before)
            }))
            .chain(self.tx.iter().filter_map(|s| s.entry.as_ref()?.deadline))
            .min()
            .map(|d| std::time::Duration::from_micros(d.saturating_sub(now)))
            .unwrap_or(std::time::Duration::from_millis(1))
            .min(std::time::Duration::from_millis(1))
    }
}
impl Owner {
    pub(super) fn enable_egress(
        &mut self,
        capacity: usize,
        gso: Option<ntcp::GsoLimits>,
    ) -> Result<()> {
        // A slot holds a packet for whichever port it leaves through.
        let offset = self.link_offset();
        let mut packet_capacity = 0;
        for port in &self.ports {
            let capacity = if let Some(backend) = &port.ethernet {
                let capacity = backend.io.max_packet_len().unwrap_or(65535 + 14);
                backend
                    .io
                    .zero_copy_capabilities()
                    .map_or(capacity, |caps| capacity.min(caps.max_packet_len))
            } else {
                port.tun
                    .as_ref()
                    .and_then(|io| io.max_packet_len())
                    .unwrap_or(65535 + offset)
            };
            packet_capacity = packet_capacity.max(capacity);
        }
        // Zero-copy output is chosen before the packet's port is: only when
        // every port can send it.
        let zero_copy = self
            .ports
            .iter()
            .map(|port| {
                port.ethernet
                    .as_ref()
                    .and_then(|b| b.io.zero_copy_capabilities())
            })
            .try_fold(None::<ntcp_io::ZeroCopyCapabilities>, |all, caps| {
                let caps = caps?;
                Some(Some(all.map_or(caps, |all| ntcp_io::ZeroCopyCapabilities {
                    max_payload_segments: all.max_payload_segments.min(caps.max_payload_segments),
                    max_packet_len: all.max_packet_len.min(caps.max_packet_len),
                })))
            })
            .flatten();
        // Core charges aggregate storage separately from these scalar wire buffers.
        match gso {
            Some(limits) => self
                .endpoint
                .enable_output_reservations_with_gso(capacity, limits),
            None => self
                .endpoint
                .enable_output_reservations_with_capacity(capacity),
        }
        .map_err(engine)?;
        // Retention holds a completed datagram, up to the Host's
        // reassembly capacity (attached before egress is enabled).
        let rx_capacity = packet_capacity.max(self.completed.len());
        let mut egress = Egress::new(
            capacity,
            packet_capacity,
            rx_capacity,
            self.defaults.max_connections,
        )?;
        if let Some(caps) = zero_copy {
            let segments = caps
                .max_payload_segments
                .min(self.defaults.connection.send_capacity);
            if segments == 0 || caps.max_packet_len < 60 {
                return Err(EINVAL);
            }
            for slot in &mut egress.tx {
                slot.shared
                    .payload
                    .try_reserve_exact(segments)
                    .map_err(|_| ENOMEM)?;
                slot.shared
                    .header
                    .try_reserve_exact(134)
                    .map_err(|_| ENOMEM)?;
            }
            self.endpoint
                .enable_shared_output(segments)
                .map_err(engine)?;
            egress.shared_segments = segments;
        }
        self.egress = Some(egress);
        Ok(())
    }
    pub(super) fn command_held(&self, id: u64, op: &Op) -> bool {
        // Receive-authority selection uses the normal ownership guard below:
        // only a fresh socket may change it, never a held connection.
        // This policy-only command cannot rewrite a held packet or its owner.
        if matches!(
            op,
            Op::SetFastOpenClientEnabled(_)
                | Op::SetListenerFastOpenEarlyDataPolicy(_)
                | Op::SetFastOpenServerCookie(_)
        ) {
            return false;
        }
        #[cfg(feature = "packet-test")]
        if matches!(op, Op::ListenerPresent(_)) {
            return false;
        }
        let op = if let Op::Wait(op, _) = op { &**op } else { op };
        // poll/epoll query sockets serially. Never park their read-only probe
        // behind one held owner; readiness_bits masks that owner's I/O instead.
        if matches!(op, Op::Ready) {
            return false;
        }
        self.sockets.get(&id).is_some_and(|s| match s.handle {
            Handle::Connection(cid) => {
                self.endpoint.is_output_reserved(cid)
                    || self.egress.as_ref().is_some_and(|e| e.retained_rx(cid))
            }
            Handle::Listener(_) => {
                matches!(op, Op::Close)
                    && self.child_timeouts.iter().any(|&(cid, listener, ..)| {
                        listener == id
                            && (self.endpoint.is_output_reserved(cid)
                                || self.egress.as_ref().is_some_and(|e| e.retained_rx(cid)))
                    })
            }
            _ => false,
        })
    }
    pub(super) fn expire_egress(&mut self, now: u64) -> Result<()> {
        let mut egress = self.egress.take().unwrap();
        let result = (|| {
            for index in 0..egress.tx.len() {
                if let Some(entry) = &egress.tx[index].entry {
                    let application = self
                        .endpoint
                        .reserved_application_deadline(entry.attempt)
                        .map_err(engine)?;
                    let app_first = application
                        .is_some_and(|at| at <= now && entry.deadline.is_none_or(|io| at <= io));
                    if app_first {
                        if !self
                            .endpoint
                            .expire_reserved_application(now, entry.attempt)
                            .map_err(engine)?
                        {
                            return Err(EIO);
                        }
                        egress.clear(index, &mut self.host)?;
                    } else if entry.deadline.is_some_and(|at| at <= now) {
                        if !self
                            .endpoint
                            .abandon_transmit(entry.attempt)
                            .map_err(engine)?
                        {
                            return Err(EIO);
                        }
                        egress.clear(index, &mut self.host)?;
                    }
                }
            }
            self.drain_timestamps(ClockPair::sample(self));
            self.cancel_unused_backend_timestamps();
            Ok(())
        })();
        self.egress = Some(egress);
        result
    }
    // IP_PMTUDISC_DONT, the application's request to send without DF (the
    // user's disposition of RFC 4821's SHOULD set DF): the connection's
    // ordinary IPv4 packets go without DF, which makes each one a
    // non-atomic datagram (RFC 6864 section 4.1) whose Identification must
    // not repeat for its (source, destination, TCP) tuple within the
    // maximum datagram lifetime (RFC 6864 section 4.3). The IPv4 codec
    // encodes atomic datagrams (DF, Identification 0), so the Identification
    // is leased from the Host allocator when the packet is submitted, a
    // fresh one for every physical attempt. PLPMTUD probes keep DF: a probe
    // that a router fragmented would prove nothing (RFC 4821 section 1), so
    // the attempt's discovery intent keeps the atomic encoding. TCP is never
    // source-fragmented either way. Without a Host there is no allocator and
    // the packet keeps DF rather than repeat an Identification.
    pub(super) fn dont_identified(
        &self,
        owner: Option<ConnectionId>,
        attempt: Option<ntcp::TransmitAttempt>,
    ) -> bool {
        self.local.is_ipv4()
            && self.host.is_some()
            && owner
                .and_then(|cid| self.connection_options.iter().find(|p| p.0 == cid))
                .is_some_and(|p| p.2 == IP_PMTUDISC_DONT)
            && attempt.is_none_or(|a| self.endpoint.transmit_discovery_intent(a).is_none())
    }
    // Whether the packet leaves without DF: the connection asked for it
    // (IP_PMTUDISC_DONT), or its IPv4 route or path is one whose owner
    // disabled discovery, where the IP layer leaves DF clear whatever the
    // socket requests (RFC 1191 section 6.6; the route disable dominates
    // IP_PMTUDISC_DO/WANT and needs no per-socket request).
    pub(super) fn df_cleared(
        &self,
        owner: Option<ConnectionId>,
        attempt: ntcp::TransmitAttempt,
        context: Option<ntcp_host::EgressContext>,
    ) -> bool {
        self.dont_identified(owner, Some(attempt))
            || self
                .host
                .as_ref()
                .zip(context)
                .is_some_and(|(host, context)| host.clears_dont_fragment(context))
    }
    // Clear DF on one encoded IPv4 header and give it a leased
    // Identification. Backpressure (the RFC 6864 ceiling of 65536
    // non-atomic datagrams per tuple per MDL, the quiet period after start,
    // or entropy failure) leaves the packet unchanged and unsubmittable.
    pub(super) fn lease_dont_identification(
        &mut self,
        now: u64,
        ip: &mut [u8],
    ) -> std::result::Result<(), ntcp_host::IdentifierBackpressure> {
        let host = self
            .host
            .as_mut()
            .ok_or(ntcp_host::IdentifierBackpressure::Unavailable { until: None })?;
        host.lease_df_clear(now, ip).map(|_| ())
    }
    // No TCP pacer here: core selected polling returns only currently eligible
    // packets. The scheduler's EDT is selection time, or a backend retry time.
    fn select_egress(&mut self, egress: &mut Egress, owner: Option<ConnectionId>) -> Result<()> {
        let existing = egress
            .tx
            .iter()
            .position(|s| s.entry.as_ref().is_some_and(|e| e.owner == owner));
        let index = if let Some(index) = existing {
            let entry = egress.tx[index].entry.as_ref().unwrap();
            if entry.packet.is_some() || entry.waiting_mtu {
                return Ok(());
            }
            index
        } else if let Some(index) = egress.tx.iter().position(|s| s.entry.is_none()) {
            index
        } else {
            return Ok(());
        };
        if owner.is_some_and(|id| !self.endpoint.is_output_reserved(id) && egress.retained_rx(id)) {
            return Ok(());
        }
        if let (Some(host), Some(owner)) = (&mut self.host, owner) {
            // Refresh before selecting a new packet or a reserved suffix. A
            // failed rebind keeps the newest notification and only parks this
            // lane; unrelated owners still get admission and scheduler turns.
            if let Err(error) = host.refresh(&mut self.endpoint, owner) {
                if let Some(index) = existing {
                    egress.tx[index].entry.as_mut().unwrap().blocked = Some(error);
                }
                return Ok(());
            }
        }
        let ethernet = self.ethernet_ports();
        let offset = self.link_offset();
        // A connection's segment is placed after the complete IP header of
        // its bound path (the base header, and an SR route's Segment
        // Routing Header); a stateless reply's path is known only once its
        // authority is, and its segment is moved there below.
        let bound = owner.and_then(|id| Some(self.host.as_ref()?.binding(id).ok()?.snapshot));
        let header = bound.map_or(crate::ip::header_len(self.local), |s| {
            s.ip_header_len() as usize
        });
        let length = self
            .output_packet_len()
            .min(egress.packet_capacity.saturating_sub(offset));
        if length < header + 20 {
            return Err(EINVAL);
        }
        let slot = &mut egress.tx[index];
        let bytes = &mut slot.bytes;
        bytes.resize(length + offset, 0);
        let now = self.now();
        let output = match owner {
            Some(id) if egress.shared_segments != 0 => {
                self.endpoint.poll_reserved_transmit_shared_for(
                    now,
                    id,
                    &mut bytes[offset + header..],
                    &mut slot.shared.payload,
                    BUDGET,
                )
            }
            Some(id) => self.endpoint.poll_reserved_transmit_for(
                now,
                id,
                &mut bytes[offset + header..],
                BUDGET,
            ),
            // A stateless reply is sized for the path the Host selects for
            // it now, not when it was queued.
            None => match &mut self.host {
                Some(host) => self.endpoint.poll_reserved_stateless_transmit_with_path_provider(
                    now,
                    &mut bytes[offset + header..],
                    BUDGET,
                    host,
                ),
                None => self.endpoint.poll_reserved_stateless_transmit(
                    now,
                    &mut bytes[offset + header..],
                    BUDGET,
                ),
            },
        };
        let (output, attempt) = match output {
            Ok(output) => output,
            Err(EndpointError::OutputReserved) => return Ok(()),
            // Candidate IDs are hints captured before this service pass. Core
            // cleanup can reclaim an unaccepted child while another lane is
            // serviced. Never turn that expired hint into a backend failure;
            // an existing reserved ticket still requires its exact owner.
            Err(EndpointError::InvalidHandle) if owner.is_some() && existing.is_none() => {
                return Ok(());
            }
            Err(EndpointError::ReservationMtuTooSmall) if existing.is_some() => {
                // An indivisible held SYN/TFO or option header cannot be
                // suffix-split. Fail only this certainly-unsubmitted owner;
                // never claim acceptance or roll back a submitted prefix.
                let attempt = egress.tx[index].entry.as_ref().unwrap().attempt;
                if !self.endpoint.abandon_transmit(attempt).map_err(engine)? {
                    return Err(EIO);
                }
                return egress.clear(index, &mut self.host);
            }
            Err(error) => return Err(engine(error)),
        };
        let Some(tx) = output.packet else {
            return Ok(());
        };
        let attempt = attempt.ok_or(EIO)?;
        let (context, blocked) = match &mut self.host {
            Some(host) => match host.egress_context(&mut self.endpoint, attempt) {
                Ok(context) => (Some(context), None),
                Err(error) => (None, Some(error)),
            },
            None => (None, None), // Explicit low-level Endpoint fixtures.
        };
        let shared_len: usize = slot.shared.payload.iter().map(ntcp_io::Payload::len).sum();
        // Native TCP refuses outgoing IPv4 options (its configuration rejects
        // ipv4_options_enabled), so no option is ever originated here and
        // this value is never written; it is marked nonstandard (RFC 791
        // section 3.1) and samples no clock. A packet held for retry keeps
        // these bytes.
        let timestamp = ntcp::Ipv4Timestamp::nonstandard((now / 1000) as u32).wire_value();
        let present = tx.len - shared_len;
        let key = context.map(|c| c.binding.snapshot.key()).or(bound.map(|s| s.key()));
        let plan = match (&self.host, key) {
            (Some(host), Some(key)) => host.header_plan(key).ok(),
            _ => None,
        };
        let (segments, placed) = plan.map_or((&[][..], header), |p| (p.segments, p.len));
        if tx.ip.source.is_ipv6() && placed != header {
            bytes.resize(bytes.len().max(offset + placed + present), 0);
            bytes.copy_within(offset + header..offset + header + present, offset + placed);
        }
        let ip_len = crate::ip::encode(&mut bytes[offset..], tx, segments, timestamp, present)
            .map_err(|_| EIO)?;
        // A packet identified at submission keeps its header open until then;
        // its timestamp copy is taken from the submitted header.
        if shared_len == 0 && !self.df_cleared(owner, attempt, context) {
            self.timestamp_packet(tx.tx_timestamp, &bytes[offset..offset + ip_len]);
        }
        bytes.truncate(offset + ip_len);
        if ethernet {
            // The frame header is the leaving port's (the only port of a
            // Host-less fixture), written again at submission for the path
            // current then.
            let port = context.and_then(|c| self.port_of(c.link)).unwrap_or(0);
            self.ports[port].frame_header(bytes, None);
            if shared_len == 0 {
                bytes.resize(bytes.len().max(60), 0);
            }
        }
        slot.shared.header.clear();
        if shared_len != 0 {
            // The buffer was reserved for the base header; an SR route's
            // Segment Routing Header can exceed it. Growth that fails is
            // backpressure: the certainly unsubmitted attempt is selected
            // again on a later pass.
            if slot.shared.header.try_reserve_exact(bytes.len()).is_err() {
                if !self.endpoint.reject_unsubmitted(attempt).map_err(engine)? {
                    return Err(EIO);
                }
                return Ok(());
            }
            slot.shared.header.extend_from_slice(bytes);
        }
        let wire_bytes = (bytes.len() + shared_len).max(if ethernet { 60 } else { 0 });
        self.drain_timestamps(ClockPair::sample(self));
        if existing.is_none() {
            let flow = egress.scheduler.open_flow(index as u64).map_err(|_| EIO)?;
            egress.tx[index].entry = Some(Entry {
                owner,
                flow,
                attempt,
                timestamp: tx.tx_timestamp,
                packet: None,
                deadline: None,
                not_before: now,
                waiting_mtu: false,
                mark: self.output_mark(owner),
                context,
                ip_len,
                blocked,
                ticket: None,
            });
        }
        let slot = &mut egress.tx[index];
        let entry = slot.entry.as_mut().unwrap();
        entry.attempt = attempt;
        entry.timestamp = tx.tx_timestamp;
        entry.context = context;
        entry.ip_len = ip_len;
        entry.blocked = blocked;
        entry.not_before = now;
        entry.packet = Some(
            egress
                .scheduler
                .enqueue(
                    entry.flow,
                    Metadata {
                        wire_bytes: wire_bytes as u64,
                        retained_bytes: egress.packet_capacity,
                        not_before: now,
                    },
                    index,
                )
                .map_err(|_| EIO)?,
        );
        Ok(())
    }
    pub(super) fn service_egress(&mut self) -> Result<()> {
        let mut egress = self.egress.take().unwrap();
        let result = (|| {
            let now = self.now();
            if let Some(host) = &mut self.host {
                // Publish connection results and apply every dirty
                // subscriber's budget even when it has no output. A failed
                // client stays dirty for the next pass; submission below
                // revalidates each physical packet regardless.
                let _ = host.service_changes(&mut self.endpoint, now);
            }
            // Echo Replies and errors the Host queued from input or expiry.
            self.drain_icmp_output()?;
            self.release_unresolved(&mut egress, now)?;
            egress.candidates.clear();
            egress.candidates.extend(self.endpoint.ready_connections());
            // Outstanding tickets are excluded from core readiness, but their
            // owners can become ready as soon as this call accepts a retry.
            for slot in &egress.tx {
                if let Some(owner) = slot.entry.as_ref().and_then(|entry| entry.owner)
                    && !egress.candidates.contains(&owner)
                {
                    egress.candidates.push(owner);
                }
            }
            // Rotate admission too: pacing/MTU-blocked candidates and stateless
            // traffic must not monopolize a full pool, even at capacity one.
            let lanes = egress.candidates.len() + 1;
            // Bound both submission count and scheduler slot visits. Sparse pools
            // need a full slot rotation between refills of the same flow.
            let mut visits = BUDGET * egress.tx.len();
            for submitted in 0..=BUDGET {
                // One bounded admission scan per submission, plus one lookahead.
                // Keep the cursor after the admitted lane so refill cannot jump
                // ahead of another connection or the stateless lane.
                for scanned in 0..lanes {
                    let at = egress.cursor % lanes;
                    egress.cursor = (at + 1) % lanes;
                    let owner = egress.candidates.get(at).copied();
                    let packets = egress.scheduler.usage().packets;
                    self.select_egress(&mut egress, owner)?;
                    if egress.scheduler.usage().packets > packets {
                        break;
                    }
                    if scanned + 1 == lanes {
                        egress.cursor = (egress.cursor + 1) % lanes;
                    }
                }
                // Actually select the lookahead: ready_connections is only a
                // candidate hint (pacing may veto it). wait sees queued EDTs,
                // including immediately eligible work after either budget ends.
                if submitted == BUDGET {
                    break;
                }
                let now = self.now();
                let (token, index) = match egress
                    .scheduler
                    .poll_ready(now, &mut visits)
                    .map_err(|_| EIO)?
                {
                    Poll::Ready(attempt) => (attempt.token, *attempt.payload),
                    Poll::Idle | Poll::BudgetExhausted => break,
                };
                let slot = &mut egress.tx[index];
                let entry = slot.entry.as_mut().ok_or(EIO)?;
                let offset = self.link_offset();
                let shared_len: usize = slot.shared.payload.iter().map(ntcp_io::Payload::len).sum();
                if entry.context.is_none()
                    && let Some(host) = &mut self.host
                {
                    entry.context = host.egress_context(&mut self.endpoint, entry.attempt).ok();
                }
                if self.df_cleared(entry.owner, entry.attempt, entry.context) {
                    let header = &mut slot.bytes[offset..offset + entry.ip_len];
                    match self.lease_dont_identification(now, header) {
                        Ok(()) => {
                            if shared_len != 0 {
                                // The zero-copy header is a copy of the
                                // resident bytes: it carries the rewrite too.
                                slot.shared.header[offset..offset + entry.ip_len]
                                    .copy_from_slice(&slot.bytes[offset..offset + entry.ip_len]);
                            }
                            if shared_len == 0 {
                                self.timestamp_packet(
                                    entry.timestamp,
                                    &slot.bytes[offset..offset + entry.ip_len],
                                );
                            }
                        }
                        Err(backpressure) => {
                            // Certainly not submitted: the reservation is
                            // held (bounded by the reservation timeout) and
                            // retried once an identifier can be issued.
                            entry.blocked = Some(ntcp_host::Error::Capacity);
                            entry
                                .deadline
                                .get_or_insert(now.saturating_add(self.reservation_timeout_us));
                            entry.not_before = match backpressure {
                                ntcp_host::IdentifierBackpressure::Exhausted { retry_at }
                                | ntcp_host::IdentifierBackpressure::Unavailable {
                                    until: Some(retry_at),
                                } => retry_at.max(now.saturating_add(1)),
                                _ => now.saturating_add(1000),
                            };
                            egress
                                .scheduler
                                .resolve(
                                    token,
                                    Outcome::Retry {
                                        not_before: entry.not_before,
                                    },
                                )
                                .map_err(|_| EIO)?;
                            continue;
                        }
                    }
                } else if ntcp_host::Host::restore_atomic_header(
                    &mut slot.bytes[offset..offset + entry.ip_len],
                ) {
                    // The final bytes follow the current decision: a packet
                    // rewritten DF clear for an earlier attempt that did not
                    // leave (WouldBlock) no longer needs it after the owner
                    // re-enabled discovery and its socket does not ask for
                    // IP_PMTUDISC_DONT, so it leaves with the atomic header
                    // (DF set, Identification 0) like any packet of the
                    // enabled path.
                    if shared_len != 0 {
                        slot.shared.header[offset..offset + entry.ip_len]
                            .copy_from_slice(&slot.bytes[offset..offset + entry.ip_len]);
                    } else {
                        self.timestamp_packet(
                            entry.timestamp,
                            &slot.bytes[offset..offset + entry.ip_len],
                        );
                    }
                }
                let sources = entry
                    .timestamp
                    .map(|t| self.backend_sources(t))
                    .unwrap_or_default();
                self.set_backend_mark(entry.mark)
                    .map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
                if !slot.shared.payload.is_empty() {
                    if sources != (false, false) {
                        return Err(EOPNOTSUPP);
                    }
                    if !self.ethernet_ports() {
                        return Err(EIO);
                    }
                }
                let mut link = Link {
                    ports: &mut self.ports,
                    #[cfg(feature = "packet-test")]
                    packets: &mut self.packets,
                };
                // Ok: the backend was called and this is its own result.
                // Err: certainly no backend call happened.
                let (called, accepted) = match &mut self.host {
                    // Explicit low-level Endpoint fixtures: no Host authority.
                    None => (
                        Ok(link.transmit(0, &slot.bytes, &slot.shared, entry.timestamp, sources)),
                        false,
                    ),
                    // The Owner is serialized through the Host transaction:
                    // exact revalidation at every retry, evidence reservation
                    // and acceptance preflight, then the one synchronous
                    // physical call (including timestamp fallback), then its
                    // finalization. Every software-GSO segment is its own
                    // attempt with its own ticket.
                    Some(host) => {
                        let prepared = match entry.context {
                            Some(context) => Ok(context),
                            None => host.egress_context(&mut self.endpoint, entry.attempt),
                        }
                        .and_then(|context| {
                            let port = link.attached(context.link, context.next_hop)?;
                            let owner = entry.owner.map_or(ntcp_host::Owner::Stateless, ntcp_host::Owner::Tcp);
                            let Some(destination) =
                                link.destination(port, host, context, owner, now)?
                            else {
                                return Ok(None);
                            };
                            let ticket = match entry.ticket.take() {
                                Some(ticket) => ticket,
                                None => host.submission_ticket(&mut self.endpoint, context)?,
                            };
                            Ok(Some((context, port, ticket, destination)))
                        });
                        match prepared {
                            Err(error) => (Err(error), false),
                            Ok(None) => {
                                // Held while its next hop is resolved: not a
                                // transmission and no backend call, so no
                                // reservation deadline either (resolution
                                // ends in success or Address Unreachable,
                                // `release_unresolved`). Polled again at the
                                // owner's cadence.
                                entry.blocked = None;
                                entry.not_before = now.saturating_add(1000);
                                egress
                                    .scheduler
                                    .resolve(
                                        token,
                                        Outcome::Retry {
                                            not_before: entry.not_before,
                                        },
                                    )
                                    .map_err(|_| EIO)?;
                                continue;
                            }
                            Ok(Some((context, port, ticket, destination))) => {
                                // This port's frame header, to the next hop
                                // just resolved, also on the zero-copy
                                // header copy.
                                link.ports[port].frame_header(&mut slot.bytes, destination);
                                if shared_len != 0 {
                                    link.ports[port]
                                        .frame_header(&mut slot.shared.header, destination);
                                }
                                let mut live = None;
                                let mut physical = None;
                                let submission = host.submit(
                                    &mut self.endpoint,
                                    now,
                                    ticket,
                                    context,
                                    &slot.bytes[offset..offset + entry.ip_len],
                                    shared_len,
                                    |current| {
                                        live = Some(current);
                                        // A path now leaving another way
                                        // (another port or next hop)
                                        // retries with that frame.
                                        if link.attached(current.link, current.next_hop) != Ok(port)
                                            || current.next_hop != context.next_hop
                                        {
                                            return ntcp_host::BackendOutcome::WouldBlock;
                                        }
                                        let result = link.transmit(
                                            port,
                                            &slot.bytes,
                                            &slot.shared,
                                            entry.timestamp,
                                            sources,
                                        );
                                        let outcome = backend_outcome(&result);
                                        physical = Some(result);
                                        outcome
                                    },
                                );
                                if let Some(live) = live {
                                    entry.context = Some(live);
                                    entry.blocked = None;
                                }
                                match submission {
                                    Err(refused) => {
                                        entry.ticket = Some(refused.ticket);
                                        (Err(refused.error), false)
                                    }
                                    Ok(
                                        ntcp_host::Submission::Blocked(ticket)
                                        | ntcp_host::Submission::Rejected(ticket),
                                    ) => {
                                        entry.ticket = Some(ticket);
                                        (physical.ok_or(ntcp_host::Error::Unsupported), false)
                                    }
                                    Ok(ntcp_host::Submission::Submitted) => {
                                        (physical.ok_or(ntcp_host::Error::Obsolete), true)
                                    }
                                    Ok(ntcp_host::Submission::PossiblySubmitted) => {
                                        (physical.ok_or(ntcp_host::Error::Obsolete), false)
                                    }
                                    // backend_outcome never certifies NotSubmitted.
                                    Ok(ntcp_host::Submission::Cancelled) => return Err(EIO),
                                }
                            }
                        }
                    }
                };
                for backend in self.ports.iter_mut().filter_map(|p| p.ethernet.as_mut()) {
                    backend.finish_cancellations(&mut self.endpoint);
                }
                let submitted = match called {
                    Ok(submitted) => submitted,
                    Err(ntcp_host::Error::Obsolete) => {
                        // No backend call occurred: this is a synchronous
                        // nonsubmission certificate, including after an
                        // immutable accepted GSO/shared prefix. The retained
                        // reservation's next attempt reuses this ticket.
                        if !self
                            .endpoint
                            .reject_unsubmitted(entry.attempt)
                            .map_err(engine)?
                        {
                            return Err(EIO);
                        }
                        egress
                            .scheduler
                            .resolve(token, Outcome::Dropped)
                            .map_err(|_| EIO)?;
                        entry.packet = None;
                        entry.context = None;
                        if entry.owner.is_none() {
                            egress.clear(index, &mut self.host)?;
                        }
                        continue;
                    }
                    Err(error) => {
                        entry.blocked = Some(error);
                        entry
                            .deadline
                            .get_or_insert(now.saturating_add(self.reservation_timeout_us));
                        entry.not_before = now.saturating_add(1000);
                        egress
                            .scheduler
                            .resolve(
                                token,
                                Outcome::Retry {
                                    not_before: entry.not_before,
                                },
                            )
                            .map_err(|_| EIO)?;
                        continue;
                    }
                };
                match submitted {
                    Ok(TxOutcome::Submitted) => {
                        // The Host transaction sealed the evidence and accepted
                        // the attempt with its preflighted time.
                        if !accepted
                            && !self
                                .endpoint
                                .accept_transmit(self.now(), entry.attempt)
                                .map_err(engine)?
                        {
                            return Err(EIO);
                        }
                        if self.ports.iter().any(|p| p.tun.is_some()) || self.packet_backend() {
                            self.software_transmitted(entry.timestamp, timestamps::realtime());
                        }
                        egress
                            .scheduler
                            .resolve(token, Outcome::Accepted)
                            .map_err(|_| EIO)?;
                        entry.packet = None;
                        if entry
                            .owner
                            .is_none_or(|id| !self.endpoint.is_output_reserved(id))
                        {
                            egress.clear(index, &mut self.host)?;
                        }
                    }
                    Ok(TxOutcome::Rejected)
                        if self
                            .endpoint
                            .reject_local_output(self.now(), entry.attempt)
                            .map_err(engine)? =>
                    {
                        egress
                            .scheduler
                            .resolve(token, Outcome::Dropped)
                            .map_err(|_| EIO)?;
                        entry.packet = None;
                        egress.clear(index, &mut self.host)?;
                        // Yield to RX before retrying this still-lost repair.
                        // output_wait retains the owner's bounded 1ms cadence.
                        break;
                    }
                    Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => {
                        let now = self.now();
                        entry
                            .deadline
                            .get_or_insert(now.saturating_add(self.reservation_timeout_us));
                        entry.not_before = now.saturating_add(1000);
                        egress
                            .scheduler
                            .resolve(
                                token,
                                Outcome::Retry {
                                    not_before: entry.not_before,
                                },
                            )
                            .map_err(|_| EIO)?;
                    }
                    Err(error) if error.raw_os_error() == Some(EMSGSIZE) => {
                        entry
                            .deadline
                            .get_or_insert(self.now().saturating_add(self.reservation_timeout_us));
                        if !self
                            .endpoint
                            .reject_unsubmitted(entry.attempt)
                            .map_err(engine)?
                        {
                            return Err(EIO);
                        }
                        egress
                            .scheduler
                            .resolve(token, Outcome::Dropped)
                            .map_err(|_| EIO)?;
                        entry.packet = None;
                        entry.waiting_mtu = true;
                        self.request_mtu_refresh();
                        if entry.owner.is_none() {
                            egress.clear(index, &mut self.host)?;
                        }
                    }
                    Err(error) => {
                        // No not-sent certificate: the Host sealed the evidence
                        // as possibly submitted. Quarantine the scheduler lease,
                        // terminate the runtime, never retry or abandon this ticket.
                        egress
                            .scheduler
                            .resolve(token, Outcome::Unknown)
                            .map_err(|_| EIO)?;
                        entry.packet = None;
                        return Err(error.raw_os_error().unwrap_or(EIO));
                    }
                }
                self.drain_timestamps(ClockPair::sample(self));
                self.cancel_unused_backend_timestamps();
            }
            if let Some(host) = &mut self.host {
                host.collect(&self.endpoint).map_err(host_error)?;
            }
            Ok(())
        })();
        self.egress = Some(egress);
        result
    }
    // The connection a TCP segment addressed to this owner belongs to.
    // `arrival` is the link it arrived on; None for a Host-less fixture.
    fn tcp_owner(
        &self,
        arrival: Option<ntcp_host::path::LinkId>,
        ip: ntcp::IpMetadata,
        protocol: u8,
        payload: &[u8],
    ) -> Option<ConnectionId> {
        if protocol != 6 || !self.owns(ip.destination) {
            return None;
        }
        let tcp = ntcp::wire::parse(ip, payload).ok()?;
        self.arrival_connection(
            ntcp::Tuple {
                local: SocketAddr::new(ip.destination, tcp.header.destination_port),
                remote: SocketAddr::new(ip.source, tcp.header.source_port),
            },
            arrival,
        )
    }
    // The owner of a processed datagram, from its processed metadata rather
    // than a fresh parse. TCP only: the Host dispatcher decides ICMP
    // ownership after correlation.
    fn processed_owner(&self, datagram: ntcp_host::Processed) -> Option<ConnectionId> {
        let packet = self.host.as_ref()?.decode_datagram(datagram).ok()?;
        self.tcp_owner(
            Some(datagram.context().link()),
            packet.ip,
            packet.protocol,
            packet.payload,
        )
    }
    // Explicit host-less Endpoint fixtures: the frame itself, with the
    // legacy ICMP mapping.
    fn ingress_owner(&self, bytes: &[u8]) -> Option<ConnectionId> {
        let packet = crate::ip::parse(bytes).ok()?;
        if !self.owns(packet.ip.destination) {
            return None;
        }
        if packet.protocol == 6 {
            return self.tcp_owner(None, packet.ip, packet.protocol, packet.payload);
        }
        let feedback = ntcp_icmp::decode_icmp(bytes).ok()?;
        // Even nonterminal errors must wait for the exact reserved owner;
        // Source Quench needs no connection state and is discarded directly.
        if feedback.kind == ntcp_icmp::FeedbackKind::SourceQuench {
            return None;
        }
        let q = feedback.quoted;
        self.endpoint.connection_id(ntcp::Tuple {
            local: SocketAddr::new(q.ip.source, q.source_port),
            remote: SocketAddr::new(q.ip.destination, q.destination_port),
        })
    }
    pub(super) fn receive_scheduled(&mut self, input: &mut [u8]) -> std::io::Result<()> {
        let mut egress = self.egress.take().unwrap();
        let result = (|| {
            for _ in 0..egress.received.len() {
                let index = egress.received.pop_front().unwrap();
                let slot = &mut egress.rx[index];
                let owner = slot.owner.unwrap();
                if self.endpoint.is_output_reserved(owner) {
                    egress.received.push_back(index);
                    continue;
                }
                if let Some(deferred) = slot.icmp.take() {
                    // The token carries the validated report for this exact
                    // generation; the Host discards it as stale otherwise.
                    let now = self.now();
                    if let Some(host) = &mut self.host
                        && let Ok(ntcp_host::IcmpDispatch::Deferred(again)) =
                            host.replay_icmp(&mut self.endpoint, deferred, now)
                    {
                        slot.icmp = Some(again);
                        slot.owner = Some(again.owner());
                        egress.received.push_back(index);
                        continue;
                    }
                } else if let Some(envelope) = slot.envelope {
                    // A retained generation never migrates to a tuple's new
                    // owner. The processed metadata is dispatched as
                    // retained: nothing is processed or recorded again.
                    if let Some(datagram) = envelope.datagram(&slot.bytes)
                        && self.processed_owner(datagram) == Some(owner)
                    {
                        self.input_datagram(datagram, slot.stamps, slot.segment_size);
                    }
                } else if self.ingress_owner(&slot.bytes) == Some(owner) {
                    self.input_ip_metadata(&slot.bytes, slot.stamps, slot.segment_size);
                }
                slot.owner = None;
                slot.envelope = None;
                slot.bytes.clear();
            }
            for _ in 0..BUDGET {
                let Some(index) = egress.rx.iter().position(|slot| slot.owner.is_none()) else {
                    // Full shared retention queue necessarily backpressures all RX.
                    break;
                };
                let (port, bytes, stamps, segment_size, link_multicast) =
                    match self.receive_ip_packet(input)? {
                        backend::BackendReceive::Packet {
                            port,
                            bytes,
                            stamps,
                            segment_size,
                            link_multicast,
                        } => (port, bytes, stamps, segment_size, link_multicast),
                        backend::BackendReceive::Skipped => continue,
                        backend::BackendReceive::Empty => break,
                    };
                if self.host.is_none() {
                    // Explicit host-less Endpoint fixtures: the frame itself.
                    if let Some(owner) = self.ingress_owner(bytes)
                        && self.endpoint.is_output_reserved(owner)
                    {
                        let slot = &mut egress.rx[index];
                        if bytes.len() > egress.rx_capacity {
                            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                        }
                        slot.bytes.extend_from_slice(bytes);
                        slot.owner = Some(owner);
                        slot.stamps = stamps;
                        slot.segment_size = segment_size;
                        egress.received.push_back(index);
                    } else {
                        self.input_ip_metadata(bytes, stamps, segment_size);
                    }
                    continue;
                }
                // Reassembly precedes classification: retention concerns a
                // completed datagram (or its deferred ICMP token), never a
                // fragment.
                let mut completed = std::mem::take(&mut self.completed);
                let outcome = (|| {
                    let Some(datagram) =
                        self.receive_datagram(port, bytes, link_multicast, &mut completed)
                    else {
                        return Ok(());
                    };
                    // Destination processing precedes classification and
                    // retention; a retained datagram keeps its result.
                    let Some(datagram) = self.process_datagram(datagram) else {
                        return Ok(());
                    };
                    let packet = datagram.packet();
                    let retained = if let Some(owner) = self.processed_owner(datagram)
                        && self.endpoint.is_output_reserved(owner)
                    {
                        Some((owner, None))
                    } else if packet.protocol == if packet.ip.source.is_ipv4() { 1 } else { 58 } {
                        // The single Host dispatcher classifies, correlates and
                        // applies the report (or answers an Echo Request); one
                        // about a reserved owner comes back unapplied, bound
                        // to that owner generation.
                        self.input_icmp(datagram).map(|d| (d.owner(), Some(d)))
                    } else {
                        self.input_datagram(datagram, stamps, segment_size);
                        None
                    };
                    if let Some((owner, deferred)) = retained {
                        let slot = &mut egress.rx[index];
                        if datagram.bytes().len() > egress.rx_capacity {
                            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                        }
                        // A deferred report needs only its token; the slot still
                        // bounds retention.
                        if deferred.is_none() {
                            slot.bytes.extend_from_slice(datagram.bytes());
                            slot.envelope = Some(datagram.envelope());
                        }
                        slot.owner = Some(owner);
                        slot.icmp = deferred;
                        slot.stamps = stamps;
                        slot.segment_size = segment_size;
                        egress.received.push_back(index);
                    }
                    Ok(())
                })();
                self.completed = completed;
                outcome?;
            }
            Ok(())
        })();
        self.egress = Some(egress);
        result
    }
}

impl Owner {
    // Held attempts whose Neighbor Discovery ended. A resolved one is
    // retried by its entry at the next poll, through the ordinary egress
    // revalidation of path, link, MTU and mapping. A failed one (RFC 4861
    // section 7.2.2) was certainly never submitted: the Endpoint withdraws
    // it without a departure, records the Address Unreachable advice as
    // the connection's soft error (RFC 1122 section 4.2.3.9) and retries
    // retransmittable output on its local-failure clock, no earlier than
    // the RTO; that next attempt resolves the neighbor again (RFC 4861
    // section 7.3.3). A selection it cannot restore exactly is released as
    // unsent output for the connection's own loss recovery on that clock:
    // never held again at once, and never under the reservation deadline
    // that abandons the connection.
    fn release_unresolved(&mut self, egress: &mut Egress, now: u64) -> Result<()> {
        for _ in 0..BUDGET {
            let Some(wake) = self.host.as_mut().and_then(|h| h.neighbor_wake()) else {
                return Ok(());
            };
            let ntcp_host::NeighborWake::Unreachable { advice, attempt, .. } = wake else {
                continue;
            };
            let Some(index) = egress
                .tx
                .iter()
                .position(|s| s.entry.as_ref().is_some_and(|e| e.attempt == attempt))
            else {
                continue;
            };
            let error = match advice {
                ntcp_host::Advice::NetworkError(error) => Some(error),
                ntcp_host::Advice::PacketTooBig { .. } => None,
            };
            if !self
                .endpoint
                .discard_unsubmitted(now, attempt, error)
                .map_err(engine)?
            {
                return Err(EIO);
            }
            egress.clear(index, &mut self.host)?;
        }
        Ok(())
    }
    /// Neighbor Discovery's caller-time work on the owner thread: due
    /// timers (reachability, probes, resolution failure, DAD), then each
    /// port's control output (answers, DAD probes, solicitations) through
    /// its one physical call, independently of blocked data output. A
    /// blocked or refusing backend ends that port's pass, keeping the
    /// message due, and leaves the other ports' passes alone.
    pub(super) fn service_discovery(&mut self) {
        let now = self.now();
        let Self {
            host,
            ports,
            icmp_wire,
            ..
        } = self;
        let Some(host) = host.as_mut() else {
            return;
        };
        if host.next_neighbor_deadline().is_none_or(|at| at > now) {
            return;
        }
        let _ = host.service_neighbors(now);
        for port in ports.iter_mut() {
            let Some(link) = port.link() else {
                continue;
            };
            for _ in 0..BUDGET {
                let Some(frame) = icmp_wire.get_mut(..) else {
                    return;
                };
                let Some(body) = frame.get_mut(14..) else {
                    return;
                };
                let Ok(Some(transmit)) = host.neighbor_output(link, now, body) else {
                    break;
                };
                let len = (14 + transmit.len).max(60);
                let outcome = match (&mut port.ethernet, frame.get_mut(..len)) {
                    (Some(backend), Some(frame)) => {
                        frame[14 + transmit.len..].fill(0);
                        backend.frame_header(frame, port.address, Some(transmit.destination));
                        backend_outcome(&backend.transmit_frame(None, (false, false), frame))
                    }
                    _ => ntcp_host::BackendOutcome::NotSubmitted,
                };
                let _ = host.complete_neighbor_output(transmit.ticket, outcome, now);
                if matches!(
                    outcome,
                    ntcp_host::BackendOutcome::WouldBlock | ntcp_host::BackendOutcome::Rejected
                ) {
                    break;
                }
            }
        }
    }
    /// Drain the Host's Echo Replies, reassembly errors and due Echo adjunct
    /// probes (one unfragmented packet each): each message is
    /// one unfragmented packet or, for a reply beyond the connectionless
    /// effective size, its source fragments, each through the attached
    /// port's one physical call, without a connection's packet mark. A
    /// blocked or refusing backend before any packet left keeps the message
    /// queued for the next pass; any other outcome consumes it (an ICMP
    /// message carries no transport state to repair).
    pub(super) fn drain_icmp_output(&mut self) -> Result<()> {
        let now = self.now();
        // Queued messages, or a due Echo adjunct probe.
        if self
            .host
            .as_ref()
            .is_none_or(|host| host.icmp_output_pending() == 0 && !host.adjunct_due(now))
        {
            return Ok(());
        }
        self.set_backend_mark(0)
            .map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
        let Self {
            host,
            ports,
            #[cfg(feature = "packet-test")]
            packets,
            icmp_packet,
            icmp_wire,
            ..
        } = self;
        let host = host.as_mut().ok_or(EIO)?;
        let link = Link {
            ports,
            #[cfg(feature = "packet-test")]
            packets,
        };
        for _ in 0..BUDGET {
            let result = host.icmp_output(now, icmp_packet, |egress, packet| {
                let Ok(port) = link.attached(egress.link, egress.next_hop) else {
                    return ntcp_host::BackendOutcome::NotSubmitted;
                };
                // A fixed or static next hop, or on a Neighbor Discovery
                // port the mapping the Host resolved (it holds the message
                // while resolving and never submits it without one).
                let destination = match (&link.ports[port].resolution, egress.next_hop) {
                    (backend::Resolution::Fixed, _) => None,
                    (backend::Resolution::Discovery, _) => match egress.link_layer {
                        Some(mac) => Some(mac),
                        None => return ntcp_host::BackendOutcome::NotSubmitted,
                    },
                    (backend::Resolution::Static(_), ntcp_host::path::ResolvedNextHop::Address(a)) => {
                        match link.ports[port].static_neighbor(a.address()) {
                            Some(mac) => Some(mac),
                            None => return ntcp_host::BackendOutcome::NotSubmitted,
                        }
                    }
                    _ => return ntcp_host::BackendOutcome::NotSubmitted,
                };
                let family = link.ports[port].address;
                let result = if let Some(backend) = &mut link.ports[port].ethernet {
                    let len = (14 + packet.len()).max(60);
                    let Some(frame) = icmp_wire.get_mut(..len) else {
                        return ntcp_host::BackendOutcome::NotSubmitted;
                    };
                    frame.fill(0);
                    backend.frame_header(frame, family, destination);
                    frame[14..14 + packet.len()].copy_from_slice(packet);
                    backend.transmit_frame(None, (false, false), frame)
                } else {
                    #[cfg(feature = "packet-test")]
                    if let Some(packets) = link.packets {
                        return backend_outcome(&packets.transmit(packet));
                    }
                    match &mut link.ports[port].tun {
                        Some(tun) => tun.transmit(packet),
                        None => return ntcp_host::BackendOutcome::NotSubmitted,
                    }
                };
                backend_outcome(&result)
            });
            match result {
                Ok(None)
                | Ok(Some(
                    ntcp_host::BackendOutcome::WouldBlock | ntcp_host::BackendOutcome::Rejected,
                )) => break,
                // Sent, possibly sent or consumed unsent (counted by the
                // Host): a reply beyond the path budget that may not be
                // fragmented, or one with no identifier available.
                Ok(Some(_)) | Err(_) => {}
            }
        }
        Ok(())
    }
}

// The attached ports, borrowed apart from the Host and the Endpoint so a
// port's one physical call can run inside the Host submission transaction.
struct Link<'a> {
    ports: &'a mut [backend::Port],
    #[cfg(feature = "packet-test")]
    packets: &'a mut Option<PacketBackend>,
}
impl Link<'_> {
    // The port a path leaves through: an actual attached port whose fixed
    // MAC/L3 endpoint implements the explicitly assigned forwarder, or a
    // port resolving the IP next hop the path names. A legacy port
    // supplies no IP-neighbor resolution, so a path whose next hop is an IP
    // address is refused there, never sent to a guessed MAC.
    fn attached(
        &self,
        link: ntcp_host::path::LinkId,
        next_hop: ntcp_host::path::ResolvedNextHop,
    ) -> core::result::Result<usize, ntcp_host::Error> {
        use ntcp_host::path::ResolvedNextHop;
        let port = self
            .ports
            .iter()
            .position(|port| port.link() == Some(link))
            .ok_or(ntcp_host::Error::Unsupported)?;
        let fixed = self.ports[port].resolution == backend::Resolution::Fixed;
        match next_hop {
            ResolvedNextHop::Forwarder(f) if fixed && f == backend::FORWARDER => Ok(port),
            ResolvedNextHop::Address(_) if !fixed => Ok(port),
            _ => Err(ntcp_host::Error::Unsupported),
        }
    }
    // The Ethernet destination of `context`'s attempt through `port`: None
    // inside Some for the fixed next hop, a static neighbor's or the
    // Neighbor Discovery cache's MAC, or None while Neighbor Discovery
    // resolves it (the attempt is then held for `owner`). An IPv4 next hop
    // without a static neighbor is unavailable (there is no ARP).
    fn destination(
        &self,
        port: usize,
        host: &mut ntcp_host::Host,
        context: ntcp_host::EgressContext,
        owner: ntcp_host::Owner,
        now: u64,
    ) -> core::result::Result<Option<Option<[u8; 6]>>, ntcp_host::Error> {
        use ntcp_host::path::ResolvedNextHop;
        let port = &self.ports[port];
        match (&port.resolution, context.next_hop) {
            (backend::Resolution::Fixed, _) => Ok(Some(None)),
            (backend::Resolution::Static(_), ResolvedNextHop::Address(next_hop)) => port
                .static_neighbor(next_hop.address())
                .map(|mac| Some(Some(mac)))
                .ok_or(ntcp_host::Error::Unsupported),
            (backend::Resolution::Discovery, _) => {
                Ok(match host.resolve_neighbor(context, owner, now)? {
                    ntcp_host::NeighborHop::Resolved(mac) => Some(Some(mac)),
                    ntcp_host::NeighborHop::Held => None,
                })
            }
            _ => Err(ntcp_host::Error::Unsupported),
        }
    }
    // Scalar or zero-copy shared header/payload through `port`; Ethernet
    // timestamp fallback happens inside this one call.
    fn transmit(
        &mut self,
        port: usize,
        bytes: &[u8],
        shared: &ntcp_io::OwnedPacket,
        timestamp: Option<ntcp::TxTimestampToken>,
        sources: (bool, bool),
    ) -> std::io::Result<TxOutcome> {
        let port = &mut self.ports[port];
        if !shared.payload.is_empty() {
            return match &mut port.ethernet {
                Some(backend) => backend.io.transmit_zero_copy(shared),
                None => Err(std::io::Error::from_raw_os_error(EIO)),
            };
        }
        if let Some(backend) = &mut port.ethernet {
            return backend.transmit_frame(timestamp, sources, bytes);
        }
        #[cfg(feature = "packet-test")]
        if let Some(packets) = self.packets {
            return packets.transmit(bytes);
        }
        match &mut port.tun {
            Some(tun) => tun.transmit(bytes),
            None => Err(std::io::Error::from_raw_os_error(EIO)),
        }
    }
}
// The backend's own statement mapped to the Host's outcome vocabulary. A
// local rejection and EMSGSIZE certainly did not submit; the caller then
// resolves the Endpoint side (reject_local_output or a retained
// reject_unsubmitted) and keeps the ticket while the attempt may be retried.
// Any other error carries no not-sent certificate.
fn backend_outcome(result: &std::io::Result<TxOutcome>) -> ntcp_host::BackendOutcome {
    match result {
        Ok(TxOutcome::Submitted) => ntcp_host::BackendOutcome::Submitted,
        Ok(TxOutcome::WouldBlock) => ntcp_host::BackendOutcome::WouldBlock,
        Ok(TxOutcome::Rejected) => ntcp_host::BackendOutcome::Rejected,
        Err(error) if error.raw_os_error() == Some(EMSGSIZE) => ntcp_host::BackendOutcome::Rejected,
        Err(_) => ntcp_host::BackendOutcome::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_gso_pool_storage_is_separate_and_budgeted() {
        let local = Ipv4Addr::new(10, 73, 0, 2);
        let config = SocketConfig::new("test", local).tcp;
        let budget = config.max_buffer_bytes;
        let mut owner = Owner::with_config(local, (local, 24), [1; 32], None, config).unwrap();
        assert_eq!(
            owner.enable_egress(
                1,
                Some(ntcp::GsoLimits {
                    max_bytes: budget,
                    max_segments: 2,
                })
            ),
            Err(ENOMEM)
        );
        assert!(owner.egress.is_none());
        // Failed core allocation leaves the pool configurable. Aggregate bounds
        // neither raise the IP MTU nor change the runtime's scalar buffer size.
        let packet_len = owner.output_packet_len();
        owner
            .enable_egress(
                1,
                Some(ntcp::GsoLimits {
                    max_bytes: 65536,
                    max_segments: 16,
                }),
            )
            .unwrap();
        assert_eq!(owner.output_packet_len(), packet_len);
        let egress = owner.egress.as_ref().unwrap();
        assert_eq!(egress.packet_capacity, 65535);
        assert_eq!(egress.tx[0].bytes.capacity(), 65535);
        assert_eq!(egress.rx[0].bytes.capacity(), 65535);
    }

    #[test]
    fn fixed_pool_accounting_and_reused_slot_reject_stale_attempts() {
        let local = Ipv4Addr::new(10, 73, 0, 2);
        let config = SocketConfig::new("test", local).tcp;
        let mut owner = Owner::with_config(local, (local, 24), [1; 32], None, config).unwrap();
        owner.test_now = Some(1000);
        owner.enable_egress(2, None).unwrap();
        let mut egress = owner.egress.take().unwrap();
        assert_eq!(egress.tx.len(), 2);
        assert_eq!(egress.rx.len(), 2);
        assert_eq!(
            egress.tx.iter().map(|s| s.bytes.capacity()).sum::<usize>(),
            2 * 65535
        );
        assert_eq!(
            egress.rx.iter().map(|s| s.bytes.capacity()).sum::<usize>(),
            2 * 65535
        );
        let one = owner
            .endpoint
            .connect(
                owner.now(),
                "10.73.0.2:1".parse().unwrap(),
                "10.73.0.3:2".parse().unwrap(),
            )
            .unwrap();
        owner.select_egress(&mut egress, Some(one)).unwrap();
        let old = egress.tx[0].entry.as_ref().unwrap().attempt;
        let mut budget = BUDGET;
        let Poll::Ready(lease) = egress
            .scheduler
            .poll_ready(owner.now(), &mut budget)
            .unwrap()
        else {
            panic!()
        };
        let token = lease.token;
        assert_eq!(lease.metadata.wire_bytes, egress.tx[0].bytes.len() as u64);
        assert_eq!(lease.metadata.retained_bytes, 65535);
        assert!(owner.endpoint.accept_transmit(owner.now(), old).unwrap());
        egress.scheduler.resolve(token, Outcome::Accepted).unwrap();
        egress.tx[0].entry.as_mut().unwrap().packet = None;
        egress.clear(0, &mut owner.host).unwrap();
        let two = owner
            .endpoint
            .connect(
                owner.now(),
                "10.73.0.2:3".parse().unwrap(),
                "10.73.0.3:2".parse().unwrap(),
            )
            .unwrap();
        owner.select_egress(&mut egress, Some(two)).unwrap();
        let current = egress.tx[0].entry.as_ref().unwrap().attempt;
        assert_ne!(old, current);
        assert!(!owner.endpoint.accept_transmit(owner.now(), old).unwrap());
        assert!(!owner.endpoint.reject_unsubmitted(old).unwrap());
        assert!(!owner.endpoint.abandon_transmit(old).unwrap());
        assert!(egress.scheduler.resolve(token, Outcome::Accepted).is_err());
        assert_eq!(egress.tx[0].entry.as_ref().unwrap().attempt, current);
        assert!(owner.endpoint.is_output_reserved(two));
        assert_eq!(egress.scheduler.usage().packets, 1);
    }
}
