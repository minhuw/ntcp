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
}
struct TxSlot {
    bytes: Vec<u8>,
    entry: Option<Entry>,
}
struct RxSlot {
    bytes: Vec<u8>,
    owner: Option<ConnectionId>,
    stamps: ntcp::RxPacketTimestamps,
}
pub(super) struct Egress {
    scheduler: Scheduler<usize>,
    tx: Vec<TxSlot>,
    rx: Vec<RxSlot>,
    received: VecDeque<usize>,
    candidates: Vec<ConnectionId>,
    packet_capacity: usize,
    cursor: usize,
    #[cfg(test)]
    pub(super) selected_ranges: usize,
}
fn buffer(size: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| ENOMEM)?;
    Ok(bytes)
}
impl Egress {
    fn new(capacity: usize, packet_capacity: usize, connections: usize) -> Result<Self> {
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
            });
            rx.push(RxSlot {
                bytes: buffer(packet_capacity)?,
                owner: None,
                stamps: ntcp::RxPacketTimestamps::default(),
            });
        }
        Ok(Self {
            scheduler,
            tx,
            rx,
            received,
            candidates,
            packet_capacity,
            cursor: 0,
            #[cfg(test)]
            selected_ranges: 0,
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
    fn clear(&mut self, index: usize) -> Result<()> {
        let slot = &mut self.tx[index];
        let entry = slot.entry.take().ok_or(EIO)?;
        if let Some(packet) = entry.packet {
            self.scheduler.cancel(packet).map_err(|_| EIO)?;
        }
        self.scheduler.disable_flow(entry.flow).map_err(|_| EIO)?;
        slot.bytes.clear();
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
        let packet_capacity = if let Some(backend) = &self.ethernet {
            backend.io.max_packet_len().unwrap_or(65535 + 14)
        } else {
            self.tun
                .as_ref()
                .and_then(|io| io.max_packet_len())
                .unwrap_or(65535)
        };
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
        self.egress = Some(Egress::new(
            capacity,
            packet_capacity,
            self.defaults.max_connections,
        )?);
        Ok(())
    }
    pub(super) fn command_held(&self, id: u64, op: &Op) -> bool {
        // This policy-only command cannot rewrite a held packet or its owner.
        if matches!(op, Op::SetFastOpenClientEnabled(_)) {
            return false;
        }
        if self.reservation.is_some() {
            return true;
        } // Explicit legacy test path only.
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
                        egress.clear(index)?;
                    } else if entry.deadline.is_some_and(|at| at <= now) {
                        if !self
                            .endpoint
                            .abandon_transmit(entry.attempt)
                            .map_err(engine)?
                        {
                            return Err(EIO);
                        }
                        egress.clear(index)?;
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
        let ethernet = self.ethernet.is_some();
        let offset = if ethernet { 14 } else { 0 };
        let length = self
            .output_packet_len()
            .min(egress.packet_capacity.saturating_sub(offset));
        if length < 40 {
            return Err(EINVAL);
        }
        let bytes = &mut egress.tx[index].bytes;
        bytes.resize(length + offset, 0);
        let now = self.now();
        let output = match owner {
            Some(id) => {
                self.endpoint
                    .poll_reserved_transmit_for(now, id, &mut bytes[offset + 20..], BUDGET)
            }
            None => self.endpoint.poll_reserved_stateless_transmit(
                now,
                &mut bytes[offset + 20..],
                BUDGET,
            ),
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
                let attempt = egress.tx[index].entry.as_ref().unwrap().attempt;
                if !self.endpoint.abandon_transmit(attempt).map_err(engine)? {
                    return Err(EIO);
                }
                return egress.clear(index);
            }
            Err(error) => return Err(engine(error)),
        };
        let Some(tx) = output.packet else {
            return Ok(());
        };
        let attempt = attempt.ok_or(EIO)?;
        let ip_len =
            ntcp_ip::encode(&mut bytes[offset..], tx, (now / 1000) as u32).map_err(|_| EIO)?;
        if owner
            .and_then(|cid| self.connection_options.iter().find(|p| p.0 == cid))
            .is_some_and(|p| p.2 == IP_PMTUDISC_DONT)
        {
            let ip = &mut bytes[offset..];
            ip[6] = 0;
            ip[10..12].fill(0);
            let checksum = ntcp_ip_common::checksum(&ip[..20]);
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        self.timestamp_packet(tx.tx_timestamp, &bytes[offset..offset + ip_len]);
        bytes.truncate(offset + ip_len);
        if let Some(backend) = &self.ethernet {
            bytes[..6].copy_from_slice(&backend.next_hop);
            bytes[6..12].copy_from_slice(&backend.local);
            bytes[12..14].copy_from_slice(&ntcp_ethernet::ETHERTYPE_IPV4.to_be_bytes());
            bytes.resize(bytes.len().max(60), 0);
        }
        self.drain_timestamps(ClockPair::sample(self));
        if existing.is_none() {
            #[cfg(test)]
            {
                egress.selected_ranges += 1;
            }
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
            });
        }
        let slot = &mut egress.tx[index];
        let entry = slot.entry.as_mut().unwrap();
        entry.attempt = attempt;
        entry.timestamp = tx.tx_timestamp;
        entry.not_before = now;
        entry.packet = Some(
            egress
                .scheduler
                .enqueue(
                    entry.flow,
                    Metadata {
                        wire_bytes: slot.bytes.len() as u64,
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
                let sources = entry
                    .timestamp
                    .map(|t| self.backend_sources(t))
                    .unwrap_or_default();
                self.set_backend_mark(entry.mark)
                    .map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
                let submitted = if let Some(backend) = &mut self.ethernet {
                    backend.transmit_frame(
                        &mut self.endpoint,
                        entry.timestamp,
                        sources,
                        &slot.bytes,
                    )
                } else {
                    self.transmit_ip_backend(&slot.bytes)
                };
                match submitted {
                    Ok(TxOutcome::Submitted) => {
                        if !self
                            .endpoint
                            .accept_transmit(self.now(), entry.attempt)
                            .map_err(engine)?
                        {
                            return Err(EIO);
                        }
                        if self.tun.is_some() || self.packet_backend() {
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
                            egress.clear(index)?;
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
                        egress.clear(index)?;
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
                        if let Some(refresh) = &mut self.mtu_refresh {
                            refresh.request();
                        }
                        if entry.owner.is_none() {
                            egress.clear(index)?;
                        }
                    }
                    Err(error) => {
                        // No not-sent certificate: quarantine the scheduler lease,
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
            Ok(())
        })();
        self.egress = Some(egress);
        result
    }
    fn ingress_owner(&self, bytes: &[u8]) -> Option<ConnectionId> {
        let packet = ntcp_ip::parse(bytes, false).ok()?;
        if packet.ip.destination != IpAddr::V4(self.local) {
            return None;
        }
        let tuple = if packet.protocol == 6 {
            let tcp = ntcp::wire::parse(packet.ip, packet.payload).ok()?;
            ntcp::Tuple {
                local: SocketAddr::new(packet.ip.destination, tcp.header.destination_port),
                remote: SocketAddr::new(packet.ip.source, tcp.header.source_port),
            }
        } else {
            let feedback = ntcp_icmp::decode_icmp(bytes).ok()?;
            // Even nonterminal errors must wait for the exact reserved owner;
            // Source Quench needs no connection state and is discarded directly.
            if feedback.kind == ntcp_icmp::FeedbackKind::SourceQuench {
                return None;
            }
            let q = feedback.quoted;
            ntcp::Tuple {
                local: SocketAddr::new(q.ip.source, q.source_port),
                remote: SocketAddr::new(q.ip.destination, q.destination_port),
            }
        };
        self.endpoint.connection_id(tuple)
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
                // A retained generation never migrates to a tuple's new owner.
                if self.ingress_owner(&slot.bytes) == Some(owner) {
                    self.input_ip(&slot.bytes, slot.stamps);
                }
                slot.owner = None;
                slot.bytes.clear();
            }
            for _ in 0..BUDGET {
                let Some(index) = egress.rx.iter().position(|slot| slot.owner.is_none()) else {
                    // Full shared retention queue necessarily backpressures all RX.
                    break;
                };
                let received = match self.receive_backend(input) {
                    Ok(Some(received)) => received,
                    Ok(None) => break,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::InvalidData
                                | std::io::ErrorKind::Unsupported
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let bytes = &input[..received.len];
                let bytes = if self.ethernet.is_some() {
                    let Ok(frame) = ntcp_ethernet::parse_ethernet(bytes) else {
                        continue;
                    };
                    frame.payload
                } else {
                    bytes
                };
                let stamps = backend::core_stamps(received.timestamps);
                if let Some(owner) = self.ingress_owner(bytes)
                    && self.endpoint.is_output_reserved(owner)
                {
                    let slot = &mut egress.rx[index];
                    if bytes.len() > egress.packet_capacity {
                        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                    }
                    slot.bytes.extend_from_slice(bytes);
                    slot.owner = Some(owner);
                    slot.stamps = stamps;
                    egress.received.push_back(index);
                } else {
                    self.input_ip(bytes, stamps);
                }
            }
            Ok(())
        })();
        self.egress = Some(egress);
        result
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
        egress.clear(0).unwrap();
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
