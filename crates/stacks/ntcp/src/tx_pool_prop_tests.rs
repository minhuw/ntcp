//! D3 endpoint-level randomized property tests for `TxPool` / `ChunkArena`
//! `ChunkRef` lifecycle invariants under debug builds.
//!
//! Because `ChunkArena`'s generation check is `debug_assert!`-only, this test
//! drives pairs of real `Endpoint`s through randomized mixes of `write`,
//! `write_shared`, `offer_fresh_transmit` (submitted & retained),
//! `poll_transmit_attempt` (`prepare_transmit_submission`, `accept_transmit`,
//! `reject_unsubmitted`, `discard_unsubmitted`, `abandon_transmit`),
//! `prepare_transmit_group` (`with_transmit_group_parts`,
//! `accept_transmit_group`, `reject_unsubmitted_group`,
//! `abandon_transmit_group`), packet drops/reordering/retransmissions,
//! graceful close (`FIN` -> `TIME-WAIT` -> expire/reuse), peer `RST`, local
//! `abort`, connection `release`/reclaim, and `Endpoint` drop with live queued
//! data and live output reservations.

use alloc::{boxed::Box, collections::VecDeque, vec, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use ntcp_buffer::{HeapChunkSource, Payload};

use crate::{
    ConnectionId, DropReason, Endpoint, EndpointConfig, EndpointError, FreshPoll, GsoLimits,
    Instant, IpMetadata, PhysicalReceipt, State, TransmitAttempt, TransmitGroup,
    TransmitGroupLimits, wire,
};

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn usize(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }

    fn percent(&mut self, pct: usize) -> bool {
        self.usize(100) < pct
    }
}

#[derive(Clone)]
struct WireSeg {
    ip: IpMetadata,
    bytes: Vec<u8>,
}

struct PendingAttempt {
    attempt: TransmitAttempt,
    ip: IpMetadata,
    bytes: Vec<u8>,
    payload: Vec<u8>,
}

struct PendingGroup {
    group: TransmitGroup,
    segments: Vec<WireSeg>,
}

struct SideState {
    ep: Endpoint,
    baseline_bytes: usize,
    pending_attempt: Option<PendingAttempt>,
    pending_group: Option<PendingGroup>,
}

struct Flow {
    port: u16,
    a_id: Option<ConnectionId>,
    b_id: Option<ConnectionId>,
    a_sent: Vec<u8>,
    b_recv: Vec<u8>,
    b_sent: Vec<u8>,
    a_recv: Vec<u8>,
    a_closed: bool,
    b_closed: bool,
    aborted: bool,
    last_ack_from_a: Option<u32>,
    last_ack_from_b: Option<u32>,
}

impl Flow {
    fn new(port: u16) -> Self {
        Self {
            port,
            a_id: None,
            b_id: None,
            a_sent: Vec::new(),
            b_recv: Vec::new(),
            b_sent: Vec::new(),
            a_recv: Vec::new(),
            a_closed: false,
            b_closed: false,
            aborted: false,
            last_ack_from_a: None,
            last_ack_from_b: None,
        }
    }

    fn verify_streams(&self) {
        assert!(
            self.b_recv.len() <= self.a_sent.len(),
            "peer B received more bytes ({}) than A wrote ({})",
            self.b_recv.len(),
            self.a_sent.len()
        );
        assert_eq!(
            self.b_recv.as_slice(),
            &self.a_sent[..self.b_recv.len()],
            "stream corruption A->B on port {}",
            self.port
        );
        assert!(
            self.a_recv.len() <= self.b_sent.len(),
            "peer A received more bytes ({}) than B wrote ({})",
            self.a_recv.len(),
            self.b_sent.len()
        );
        assert_eq!(
            self.a_recv.as_slice(),
            &self.b_sent[..self.a_recv.len()],
            "stream corruption B->A on port {}",
            self.port
        );
    }
}

#[derive(Default)]
struct Stats {
    writes: usize,
    shared_writes: usize,
    multi_chunk_writes: usize,
    fresh_submitted: usize,
    fresh_retained: usize,
    attempt_prepared_submitted: usize,
    attempt_accepted: usize,
    attempt_rejected: usize,
    attempt_discarded: usize,
    attempt_abandoned: usize,
    group_accepted: usize,
    group_rejected: usize,
    group_abandoned: usize,
    packets_dropped: usize,
    graceful_closes: usize,
    aborts: usize,
    injected_rsts: usize,
    reclaimed: usize,
    total_bytes_verified: usize,
}

const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
const SERVER_PORT: u16 = 8080;

fn make_endpoint(secret: [u8; 32], chunk_size: usize) -> SideState {
    let mut cfg = EndpointConfig::default();
    cfg.max_connections = 16;
    cfg.reuse_time_wait = true;
    cfg.connection.sack = true;
    cfg.connection.rack = true;
    cfg.connection.timestamps = true;
    cfg.connection.nagle = false;
    cfg.connection.time_wait_us = 200_000;
    cfg.connection.send_capacity = 64 * 1024;
    cfg.connection.receive_capacity = 64 * 1024;
    cfg.max_buffer_bytes = 64 * 1024 * 1024;

    let mut ep = Endpoint::new(cfg, secret, 0, |_| true).unwrap();
    ep.enable_tx_chunk_source(Box::new(HeapChunkSource::new(chunk_size)))
        .unwrap();
    let gso = Some(GsoLimits {
        max_bytes: 16 * 1448,
        max_segments: 16,
    });
    ep.enable_output_reservations_with_packet_bytes(8, 1480, gso)
        .unwrap();
    let baseline_bytes = ep.buffer_bytes();
    assert_eq!(ep.tx_pool_live(), 0);
    assert_eq!(ep.tx_pool_bytes(), 0);
    SideState {
        ep,
        baseline_bytes,
        pending_attempt: None,
        pending_group: None,
    }
}

fn fill_pattern(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = rng.next_u64();
    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.push((state >> 56) as u8);
    }
    out
}

fn receipt_for(tcp_len: usize) -> PhysicalReceipt {
    PhysicalReceipt {
        ip_packet_len: (20 + tcp_len) as u32,
        dont_fragment: true,
    }
}

fn gso_group_limits() -> TransmitGroupLimits {
    TransmitGroupLimits {
        max_bytes: 16 * 1448,
        max_segments: 16,
        allow_psh: true,
        allow_cwr: true,
        allow_options: true,
    }
}

fn segment_group(ep: &Endpoint, group: TransmitGroup) -> Vec<WireSeg> {
    let view = ep.transmit_group(group).expect("valid group view");
    let payload = ep
        .with_transmit_group_parts(group, |parts| {
            let mut flat = Vec::with_capacity(view.payload_len);
            for part in parts {
                flat.extend_from_slice(part.bytes());
            }
            flat
        })
        .expect("valid group parts");
    assert_eq!(payload.len(), view.payload_len);

    let mss = view.segment_payload_len;
    let mut segments = Vec::with_capacity(view.segment_count);
    let mut off = 0usize;
    let mut idx = 0usize;
    while off < payload.len() {
        let end = (off + mss).min(payload.len());
        let is_last = end == payload.len();
        let mut hdr = view.header;
        hdr.sequence = view.header.sequence.wrapping_add(off as u32);
        if !is_last {
            hdr.flags &= !(wire::PSH | wire::FIN);
        }
        if idx != 0 {
            hdr.flags &= !wire::CWR;
        }
        let mut buf = vec![0u8; 64 + (end - off)];
        let n = wire::encode(view.packet.ip, hdr, view.options, &payload[off..end], &mut buf)
            .expect("encode split GSO segment");
        buf.truncate(n);
        segments.push(WireSeg {
            ip: view.packet.ip,
            bytes: buf,
        });
        off = end;
        idx += 1;
    }
    assert_eq!(segments.len(), view.segment_count);
    segments
}

fn resolve_pending_group(
    side: &mut SideState,
    now: Instant,
    wire_out: &mut VecDeque<WireSeg>,
    rng: &mut Rng,
    stats: &mut Stats,
    force_accept: bool,
) {
    let Some(pending) = side.pending_group.take() else {
        return;
    };
    let roll = if force_accept { 0 } else { rng.usize(10) };
    if roll < 7 {
        match side.ep.accept_transmit_group(now, pending.group) {
            Ok(true) => {
                wire_out.extend(pending.segments);
                stats.group_accepted += 1;
            }
            Ok(false) | Err(_) => {
                let _ = side.ep.abandon_transmit_group(pending.group);
                stats.group_abandoned += 1;
            }
        }
    } else if roll < 9 {
        if side.ep.reject_unsubmitted_group(pending.group).unwrap_or(false) {
            stats.group_rejected += 1;
        }
    } else if side.ep.abandon_transmit_group(pending.group).unwrap_or(false) {
        stats.group_abandoned += 1;
    }
}

fn resolve_pending_attempt(
    side: &mut SideState,
    now: Instant,
    wire_out: &mut VecDeque<WireSeg>,
    rng: &mut Rng,
    stats: &mut Stats,
    force_accept: bool,
) {
    let Some(pending) = side.pending_attempt.take() else {
        return;
    };
    let roll = if force_accept { 0 } else { rng.usize(20) };
    if roll < 8 {
        match side.ep.prepare_transmit_submission(now, pending.attempt) {
            Ok(Some(prepared)) => {
                let parts_bytes = prepared.with_tx_parts(|parts| {
                    let mut v = Vec::new();
                    for p in parts {
                        v.extend_from_slice(p.bytes());
                    }
                    v
                });
                assert_eq!(parts_bytes, pending.payload);
                prepared.submitted(receipt_for(pending.bytes.len()));
                wire_out.push_back(WireSeg {
                    ip: pending.ip,
                    bytes: pending.bytes,
                });
                stats.attempt_prepared_submitted += 1;
            }
            Ok(None) | Err(_) => {
                let _ = side.ep.abandon_transmit(pending.attempt);
                stats.attempt_abandoned += 1;
            }
        }
    } else if roll < 13 {
        match side.ep.accept_transmit(now, pending.attempt) {
            Ok(true) => {
                wire_out.push_back(WireSeg {
                    ip: pending.ip,
                    bytes: pending.bytes,
                });
                stats.attempt_accepted += 1;
            }
            Ok(false) | Err(_) => {
                let _ = side.ep.abandon_transmit(pending.attempt);
                stats.attempt_abandoned += 1;
            }
        }
    } else if roll < 16 {
        if side.ep.reject_unsubmitted(pending.attempt).unwrap_or(false) {
            stats.attempt_rejected += 1;
        }
    } else if roll < 19 {
        if side
            .ep
            .discard_unsubmitted(now, pending.attempt, None, DropReason::NotSpecified)
            .unwrap_or(false)
        {
            stats.attempt_discarded += 1;
        }
    } else if side.ep.abandon_transmit(pending.attempt).unwrap_or(false) {
        stats.attempt_abandoned += 1;
    }
}

fn poll_one_tx(
    side: &mut SideState,
    now: Instant,
    target_conn: Option<ConnectionId>,
    wire_out: &mut VecDeque<WireSeg>,
    rng: &mut Rng,
    stats: &mut Stats,
) {
    // First possibly resolve any already held group/attempt so we don't starve.
    if side.pending_group.is_some() {
        resolve_pending_group(side, now, wire_out, rng, stats, false);
        return;
    }
    if side.pending_attempt.is_some() {
        resolve_pending_attempt(side, now, wire_out, rng, stats, false);
        return;
    }

    // 45% of the time when we have a specific connection, try offer_fresh_transmit!
    if let Some(id) = target_conn
        && rng.percent(45)
    {
        let mut buf = [0u8; 160];
        let submit_now = rng.percent(55);
        let mut captured_seg: Option<(IpMetadata, Vec<u8>, Vec<u8>)> = None;
        let offered = side.ep.offer_fresh_transmit(now, id, &mut buf, 14, false, |frame| {
            let ip = frame.packet().ip;
            let hdr_len = frame.header_len();
            let mut seg = Vec::with_capacity(frame.packet().len);
            let mut payload = Vec::with_capacity(frame.payload_len());
            frame
                .with_tx_packet(0, |tx| {
                    assert_eq!(tx.header.len(), 14 + hdr_len);
                    seg.extend_from_slice(&tx.header[14..]);
                    for part in tx.payload {
                        payload.extend_from_slice(part.bytes());
                        seg.extend_from_slice(part.bytes());
                    }
                })
                .expect("offer_fresh_transmit with_tx_packet");
            assert_eq!(seg.len(), frame.packet().len);
            captured_seg = Some((ip, seg, payload));
            submit_now.then(|| receipt_for(frame.packet().len))
        });
        match offered {
            Ok(FreshPoll::Submitted { .. }) => {
                let (ip, bytes, _) = captured_seg.expect("submitted segment captured");
                wire_out.push_back(WireSeg { ip, bytes });
                stats.fresh_submitted += 1;
                return;
            }
            Ok(FreshPoll::Reserved { attempt, .. }) => {
                let (ip, bytes, payload) = if let Some(cap) = captured_seg {
                    cap
                } else {
                    let pkt = *side.ep.transmit_attempt_packet_ref(attempt).unwrap();
                    let res_len = side.ep.transmit_attempt_resident_len(attempt).unwrap();
                    match side.ep.prepare_transmit_submission(now, attempt) {
                        Ok(Some(prepared)) => {
                            let mut seg = Vec::with_capacity(pkt.len);
                            seg.extend_from_slice(&buf[14..14 + res_len]);
                            let payload = prepared.with_tx_parts(|parts| {
                                let mut p = Vec::new();
                                for part in parts {
                                    p.extend_from_slice(part.bytes());
                                    seg.extend_from_slice(part.bytes());
                                }
                                p
                            });
                            assert_eq!(seg.len(), pkt.len);
                            drop(prepared);
                            (pkt.ip, seg, payload)
                        }
                        Ok(None) | Err(_) => {
                            let _ = side.ep.abandon_transmit(attempt);
                            return;
                        }
                    }
                };
                stats.fresh_retained += 1;
                side.pending_attempt = Some(PendingAttempt {
                    attempt,
                    ip,
                    bytes,
                    payload,
                });
                // Sometimes resolve immediately, sometimes hold across steps.
                if rng.percent(50) {
                    resolve_pending_attempt(side, now, wire_out, rng, stats, false);
                }
                return;
            }
            Ok(FreshPoll::Empty { .. } | FreshPoll::Unavailable) | Err(_) => {}
        }
    }

    // Otherwise poll via poll_transmit_attempt (either directed or undirected).
    let mut hdr_buf = [0u8; 160];
    let owner = if rng.percent(50) { target_conn } else { None };
    let Ok((_, Some(attempt))) = side.ep.poll_transmit_attempt(now, &mut hdr_buf, 8, owner) else {
        return;
    };

    // Prefer trying prepare_transmit_group most of the time so GSO paths are hit heavily!
    if rng.percent(80)
        && let Ok(Some(group)) = side.ep.prepare_transmit_group(attempt, gso_group_limits())
    {
        let segments = segment_group(&side.ep, group);
        side.pending_group = Some(PendingGroup { group, segments });
        if rng.percent(65) {
            resolve_pending_group(side, now, wire_out, rng, stats, false);
        }
        return;
    }

    let pkt = *side.ep.transmit_attempt_packet_ref(attempt).unwrap();
    let res_len = side.ep.transmit_attempt_resident_len(attempt).unwrap();
    let (bytes, payload) = match side.ep.prepare_transmit_submission(now, attempt) {
        Ok(Some(prepared)) => {
            let mut seg = Vec::with_capacity(pkt.len);
            seg.extend_from_slice(&hdr_buf[..res_len]);
            let payload = prepared.with_tx_parts(|parts| {
                let mut p = Vec::new();
                for part in parts {
                    p.extend_from_slice(part.bytes());
                    seg.extend_from_slice(part.bytes());
                }
                p
            });
            assert_eq!(seg.len(), pkt.len);
            drop(prepared);
            (seg, payload)
        }
        Ok(None) | Err(_) => {
            let _ = side.ep.abandon_transmit(attempt);
            return;
        }
    };
    side.pending_attempt = Some(PendingAttempt {
        attempt,
        ip: pkt.ip,
        bytes,
        payload,
    });
    if rng.percent(65) {
        resolve_pending_attempt(side, now, wire_out, rng, stats, false);
    }
}

fn deliver_wire(
    queue: &mut VecDeque<WireSeg>,
    receiver: &mut SideState,
    flows: &mut [Flow],
    from_a: bool,
    now: Instant,
    rng: &mut Rng,
    stats: &mut Stats,
    allow_faults: bool,
) {
    let budget = queue.len().min(8);
    for _ in 0..budget {
        if allow_faults && queue.len() >= 2 && rng.percent(10) {
            queue.swap(0, 1);
        }
        let Some(seg) = queue.pop_front() else {
            break;
        };
        if let Ok(parsed) = wire::parse_unchecked(seg.ip, &seg.bytes)
            && parsed.header.flags & wire::ACK != 0
        {
            let client_port = if from_a {
                parsed.header.source_port
            } else {
                parsed.header.destination_port
            };
            if let Some(flow) = flows.iter_mut().find(|f| f.port == client_port) {
                if from_a {
                    flow.last_ack_from_a = Some(parsed.header.acknowledgment);
                } else {
                    flow.last_ack_from_b = Some(parsed.header.acknowledgment);
                }
            }
        }
        if allow_faults && rng.percent(8) {
            stats.packets_dropped += 1;
            continue;
        }
        match receiver.ep.input(now, seg.ip, &seg.bytes) {
            Ok(_) => {}
            Err(EndpointError::OutputReserved) => {
                // Connection currently holds a reservation; requeue for after reservation clears.
                queue.push_back(seg);
            }
            Err(_) => {}
        }
    }
}

fn drain_reads_and_reclaim(
    a: &mut SideState,
    b: &mut SideState,
    flows: &mut [Flow],
    stats: &mut Stats,
) {
    let mut buf = [0u8; 8192];
    for flow in flows.iter_mut() {
        if let Some(id) = flow.b_id {
            loop {
                match b.ep.read(id, &mut buf) {
                    Ok(n) if n > 0 => {
                        flow.b_recv.extend_from_slice(&buf[..n]);
                        stats.total_bytes_verified += n;
                    }
                    _ => break,
                }
            }
            if matches!(b.ep.state(id), Ok(State::Closed)) {
                loop {
                    match b.ep.read_terminal(id, &mut buf) {
                        Ok(n) if n > 0 => {
                            flow.b_recv.extend_from_slice(&buf[..n]);
                            stats.total_bytes_verified += n;
                        }
                        _ => break,
                    }
                }
            }
        }
        if let Some(id) = flow.a_id {
            loop {
                match a.ep.read(id, &mut buf) {
                    Ok(n) if n > 0 => {
                        flow.a_recv.extend_from_slice(&buf[..n]);
                        stats.total_bytes_verified += n;
                    }
                    _ => break,
                }
            }
            if matches!(a.ep.state(id), Ok(State::Closed)) {
                loop {
                    match a.ep.read_terminal(id, &mut buf) {
                        Ok(n) if n > 0 => {
                            flow.a_recv.extend_from_slice(&buf[..n]);
                            stats.total_bytes_verified += n;
                        }
                        _ => break,
                    }
                }
            }
        }
        flow.verify_streams();

        if let Some(id) = flow.a_id
            && matches!(a.ep.state(id), Ok(State::Closed))
            && a.ep.release(id).is_ok()
        {
            flow.a_id = None;
            stats.reclaimed += 1;
        }
        if let Some(id) = flow.b_id
            && matches!(b.ep.state(id), Ok(State::Closed))
            && b.ep.release(id).is_ok()
        {
            flow.b_id = None;
            stats.reclaimed += 1;
        }
    }
}

fn try_inject_rst(
    sender_id: ConnectionId,
    receiver: &mut SideState,
    target_id: ConnectionId,
    sender: &SideState,
    exact_seq: Option<u32>,
    now: Instant,
) -> bool {
    let Some(seq) = exact_seq else {
        return false;
    };
    let Ok(target_state) = receiver.ep.state(target_id) else {
        return false;
    };
    let Ok(sender_tuple) = sender.ep.tuple(sender_id) else {
        return false;
    };
    if matches!(target_state, State::Closed) {
        return false;
    }
    let ip = IpMetadata {
        source: sender_tuple.local.ip(),
        destination: sender_tuple.remote.ip(),
    };
    let hdr = wire::Header {
        source_port: sender_tuple.local.port(),
        destination_port: sender_tuple.remote.port(),
        sequence: seq,
        acknowledgment: 0,
        flags: wire::RST,
        window: 0,
        urgent_pointer: 0,
    };
    let mut seg = [0u8; 64];
    let n = wire::encode(ip, hdr, &[], &[], &mut seg).expect("encode RST");
    receiver.ep.input(now, ip, &seg[..n]).is_ok()
}

fn run_seed(seed: u64) {
    let mut rng = Rng::new(seed);
    // Use 4 KiB chunks on A and 16 KiB chunks on B so both frequent chunk
    // rollover / arena slot reuse AND >16 KiB multi-chunk writes are stressed.
    let mut a = make_endpoint([seed as u8; 32], 4096);
    let mut b = make_endpoint([(seed.wrapping_add(1)) as u8; 32], 16 * 1024);

    let remote = SocketAddr::new(IP_B, SERVER_PORT);
    let listener = b.ep.listen(remote, 16).unwrap();

    const SLOTS: usize = 5;
    let mut flows: Vec<Flow> = (0..SLOTS)
        .map(|i| Flow::new(44_000 + (seed as u16) * 16 + i as u16))
        .collect();
    let mut wire_a_to_b = VecDeque::new();
    let mut wire_b_to_a = VecDeque::new();
    let mut stats = Stats::default();
    let mut now: Instant = 1_000;

    let write_sizes: &[usize] = &[1, 7, 64, 512, 1448, 4096, 5000, 20_000];
    let shared_sizes: &[usize] = &[13, 300, 1448, 4200];

    for step in 0..380usize {
        now += 1_000 + (rng.next_u64() % 15_000);
        if step % 40 == 39 {
            // Periodic jump to trigger RTOs and TIME-WAIT expiry.
            now += 250_000;
        }

        // 1. Open new connections on empty slots (reusing the slot's port to
        //    exercise TIME-WAIT expiry and reuse).
        for flow in flows.iter_mut() {
            if flow.a_id.is_none() && flow.b_id.is_none() && rng.percent(40) {
                let local = SocketAddr::new(IP_A, flow.port);
                if let Ok(id) = a.ep.connect(now, local, remote) {
                    flow.a_id = Some(id);
                    flow.a_sent.clear();
                    flow.b_recv.clear();
                    flow.b_sent.clear();
                    flow.a_recv.clear();
                    flow.a_closed = false;
                    flow.b_closed = false;
                    flow.aborted = false;
                    flow.last_ack_from_a = None;
                    flow.last_ack_from_b = None;
                }
            }
        }

        // Accept any incoming connections on B and match by peer port.
        while let Ok(srv) = b.ep.accept(listener) {
            let peer_port = b.ep.tuple(srv).unwrap().remote.port();
            if let Some(flow) = flows.iter_mut().find(|f| f.port == peer_port && f.b_id.is_none()) {
                flow.b_id = Some(srv);
            } else {
                let _ = b.ep.abort(srv);
                let _ = b.ep.release(srv);
            }
        }

        // 2. Random writes (`write` and `write_shared`) in both directions.
        for flow in flows.iter_mut() {
            if let Some(id) = flow.a_id
                && !flow.a_closed
                && matches!(a.ep.state(id), Ok(State::Established | State::CloseWait))
                && rng.percent(45)
            {
                if rng.percent(30) {
                    let len = shared_sizes[rng.usize(shared_sizes.len())];
                    let data = fill_pattern(&mut rng, len);
                    let offset = rng.usize(16);
                    let mut backing = vec![0xAA; offset];
                    backing.extend_from_slice(&data);
                    backing.extend_from_slice(&[0xBB; 8]);
                    let payload = Payload::from_vec(backing)
                        .slice(offset..offset + len)
                        .unwrap();
                    if let Ok(n) = a.ep.write_shared(id, payload, false, false, None) {
                        flow.a_sent.extend_from_slice(&data[..n]);
                        stats.shared_writes += 1;
                    }
                } else {
                    let len = write_sizes[rng.usize(write_sizes.len())];
                    let data = fill_pattern(&mut rng, len);
                    if let Ok(n) = a.ep.write(id, &data) {
                        flow.a_sent.extend_from_slice(&data[..n]);
                        stats.writes += 1;
                        if n > 16 * 1024 {
                            stats.multi_chunk_writes += 1;
                        }
                    }
                }
            }

            if let Some(id) = flow.b_id
                && !flow.b_closed
                && matches!(b.ep.state(id), Ok(State::Established | State::CloseWait))
                && rng.percent(30)
            {
                if rng.percent(35) {
                    let len = shared_sizes[rng.usize(shared_sizes.len())];
                    let data = fill_pattern(&mut rng, len);
                    let payload = Payload::from_vec(data.clone());
                    if let Ok(n) = b.ep.write_shared(id, payload, false, false, None) {
                        flow.b_sent.extend_from_slice(&data[..n]);
                        stats.shared_writes += 1;
                    }
                } else {
                    let len = write_sizes[rng.usize(write_sizes.len())];
                    let data = fill_pattern(&mut rng, len);
                    if let Ok(n) = b.ep.write(id, &data) {
                        flow.b_sent.extend_from_slice(&data[..n]);
                        stats.writes += 1;
                        if n > 16 * 1024 {
                            stats.multi_chunk_writes += 1;
                        }
                    }
                }
            }
        }

        // 3. Random lifecycle transitions: graceful close, abort, injected peer RST.
        if step > 20 && step % 12 == 0 {
            let n = flows.len();
            let start = rng.usize(n);
            let action = rng.usize(3);
            for offset in 0..n {
                let flow = &mut flows[(start + offset) % n];
                match action {
                    0 => {
                        // Graceful close (FIN -> TIME-WAIT -> expire/reuse).
                        let mut did = false;
                        if let Some(id) = flow.a_id
                            && !flow.a_closed
                            && a.ep.close(id).is_ok()
                        {
                            flow.a_closed = true;
                            stats.graceful_closes += 1;
                            did = true;
                        }
                        if let Some(id) = flow.b_id
                            && !flow.b_closed
                            && b.ep.close(id).is_ok()
                        {
                            flow.b_closed = true;
                            stats.graceful_closes += 1;
                            did = true;
                        }
                        if did {
                            break;
                        }
                    }
                    1 => {
                        // Local abort on A or B.
                        if rng.percent(50) {
                            if let Some(id) = flow.a_id
                                && a.ep.abort(id).is_ok()
                            {
                                flow.aborted = true;
                                stats.aborts += 1;
                                break;
                            }
                        } else if let Some(id) = flow.b_id
                            && b.ep.abort(id).is_ok()
                        {
                            flow.aborted = true;
                            stats.aborts += 1;
                            break;
                        }
                    }
                    _ => {
                        // Peer RST injected directly into A or B.
                        if let (Some(a_id), Some(b_id)) = (flow.a_id, flow.b_id) {
                            if rng.percent(50) {
                                if try_inject_rst(b_id, &mut a, a_id, &b, flow.last_ack_from_a, now)
                                {
                                    flow.aborted = true;
                                    stats.injected_rsts += 1;
                                    break;
                                }
                            } else if try_inject_rst(
                                a_id,
                                &mut b,
                                b_id,
                                &a,
                                flow.last_ack_from_b,
                                now,
                            ) {
                                flow.aborted = true;
                                stats.injected_rsts += 1;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 4. Poll transmissions across both endpoints (multiple ops per step).
        for _ in 0..6 {
            let pick_a = flows[rng.usize(flows.len())].a_id;
            poll_one_tx(&mut a, now, pick_a, &mut wire_a_to_b, &mut rng, &mut stats);
            let pick_b = flows[rng.usize(flows.len())].b_id;
            poll_one_tx(&mut b, now, pick_b, &mut wire_b_to_a, &mut rng, &mut stats);
        }

        // 5. Deliver wire segments with occasional drops/reordering.
        deliver_wire(
            &mut wire_a_to_b,
            &mut b,
            &mut flows,
            true,
            now,
            &mut rng,
            &mut stats,
            true,
        );
        deliver_wire(
            &mut wire_b_to_a,
            &mut a,
            &mut flows,
            false,
            now,
            &mut rng,
            &mut stats,
            true,
        );

        // 6. Service timers on both sides.
        let _ = a.ep.on_timeout(now, 16);
        let _ = b.ep.on_timeout(now, 16);

        // 7. Read & verify every stream byte-for-byte, and reclaim closed slots.
        drain_reads_and_reclaim(&mut a, &mut b, &mut flows, &mut stats);
    }

    // Drain any held reservations, close/abort all remaining connections, and
    // verify `tx_pool_live() == 0` and `buffer_bytes()` returns to baseline!
    now += 1_000;
    resolve_pending_group(&mut a, now, &mut wire_a_to_b, &mut rng, &mut stats, true);
    resolve_pending_attempt(&mut a, now, &mut wire_a_to_b, &mut rng, &mut stats, true);
    resolve_pending_group(&mut b, now, &mut wire_b_to_a, &mut rng, &mut stats, true);
    resolve_pending_attempt(&mut b, now, &mut wire_b_to_a, &mut rng, &mut stats, true);

    for flow in flows.iter_mut() {
        if let Some(id) = flow.a_id {
            let _ = a.ep.close(id);
        }
        if let Some(id) = flow.b_id {
            let _ = b.ep.close(id);
        }
    }
    for _ in 0..60 {
        now += 50_000;
        for _ in 0..8 {
            poll_one_tx(&mut a, now, None, &mut wire_a_to_b, &mut rng, &mut stats);
            poll_one_tx(&mut b, now, None, &mut wire_b_to_a, &mut rng, &mut stats);
            resolve_pending_group(&mut a, now, &mut wire_a_to_b, &mut rng, &mut stats, true);
            resolve_pending_attempt(&mut a, now, &mut wire_a_to_b, &mut rng, &mut stats, true);
            resolve_pending_group(&mut b, now, &mut wire_b_to_a, &mut rng, &mut stats, true);
            resolve_pending_attempt(&mut b, now, &mut wire_b_to_a, &mut rng, &mut stats, true);
        }
        deliver_wire(
            &mut wire_a_to_b,
            &mut b,
            &mut flows,
            true,
            now,
            &mut rng,
            &mut stats,
            false,
        );
        deliver_wire(
            &mut wire_b_to_a,
            &mut a,
            &mut flows,
            false,
            now,
            &mut rng,
            &mut stats,
            false,
        );
        let _ = a.ep.on_timeout(now, 32);
        let _ = b.ep.on_timeout(now, 32);
        drain_reads_and_reclaim(&mut a, &mut b, &mut flows, &mut stats);
    }

    // Force-abort any lingering connections (e.g. half-open or SYN-SENT).
    for flow in flows.iter_mut() {
        if let Some(id) = flow.a_id.take() {
            let _ = a.ep.abort(id);
            let _ = a.ep.release(id);
            stats.reclaimed += 1;
        }
        if let Some(id) = flow.b_id.take() {
            let _ = b.ep.abort(id);
            let _ = b.ep.release(id);
            stats.reclaimed += 1;
        }
    }
    while let Ok(srv) = b.ep.accept(listener) {
        let _ = b.ep.abort(srv);
        let _ = b.ep.release(srv);
    }
    // Drain any final stateless RSTs/reservations and expire TIME-WAIT.
    now += 5_000_000;
    let _ = a.ep.on_timeout(now, 64);
    let _ = b.ep.on_timeout(now, 64);
    let mut drain_buf = [0u8; 256];
    while let Ok((_, Some(att))) = a.ep.poll_transmit_attempt(now, &mut drain_buf, 16, None) {
        let _ = a.ep.accept_transmit(now, att);
    }
    while let Ok((_, Some(att))) = b.ep.poll_transmit_attempt(now, &mut drain_buf, 16, None) {
        let _ = b.ep.accept_transmit(now, att);
    }

    assert_eq!(a.ep.tx_pool_live(), 0, "seed {seed}: A leaked tx_pool chunks");
    assert_eq!(b.ep.tx_pool_live(), 0, "seed {seed}: B leaked tx_pool chunks");
    assert_eq!(a.ep.tx_pool_bytes(), 0, "seed {seed}: A tx_pool_bytes != 0");
    assert_eq!(b.ep.tx_pool_bytes(), 0, "seed {seed}: B tx_pool_bytes != 0");
    assert_eq!(
        a.ep.buffer_bytes(),
        a.baseline_bytes,
        "seed {seed}: A buffer_bytes did not return to baseline"
    );
    assert_eq!(
        b.ep.buffer_bytes(),
        b.baseline_bytes,
        "seed {seed}: B buffer_bytes did not return to baseline"
    );

    // Non-vacuous coverage assertions across every exercised path.
    assert!(stats.writes > 0, "seed {seed}: no copy writes");
    assert!(stats.shared_writes > 0, "seed {seed}: no shared writes");
    assert!(
        stats.multi_chunk_writes > 0,
        "seed {seed}: no >16KiB multi-chunk writes"
    );
    assert!(stats.fresh_submitted > 0, "seed {seed}: no fresh submitted");
    assert!(stats.fresh_retained > 0, "seed {seed}: no fresh retained");
    assert!(
        stats.attempt_prepared_submitted > 0,
        "seed {seed}: no prepared attempts submitted"
    );
    assert!(stats.attempt_accepted > 0, "seed {seed}: no attempts accepted");
    assert!(stats.attempt_rejected > 0, "seed {seed}: no attempts rejected");
    assert!(
        stats.attempt_discarded > 0,
        "seed {seed}: no attempts discarded"
    );
    assert!(stats.group_accepted > 0, "seed {seed}: no GSO groups accepted");
    assert!(stats.group_rejected > 0, "seed {seed}: no GSO groups rejected");
    assert!(stats.packets_dropped > 0, "seed {seed}: no packet drops");
    assert!(stats.graceful_closes > 0, "seed {seed}: no graceful closes");
    assert!(stats.aborts > 0, "seed {seed}: no local aborts");
    assert!(stats.injected_rsts > 0, "seed {seed}: no peer RSTs injected");
    assert!(stats.reclaimed > 0, "seed {seed}: no connections reclaimed");
    assert!(
        stats.total_bytes_verified > 20_000,
        "seed {seed}: too few verified stream bytes ({})",
        stats.total_bytes_verified
    );
}

fn run_drop_with_live_data_and_reservations(seed: u64) {
    let mut rng = Rng::new(seed ^ 0xdead_beef);
    let mut a = make_endpoint([0x11; 32], 4096);
    let mut b = make_endpoint([0x22; 32], 4096);
    let remote = SocketAddr::new(IP_B, SERVER_PORT + 1);
    let listener = b.ep.listen(remote, 8).unwrap();

    let mut clients = Vec::new();
    for i in 0..3u16 {
        let local = SocketAddr::new(IP_A, 46_000 + i);
        clients.push(a.ep.connect(10, local, remote).unwrap());
    }
    // Complete handshakes cleanly.
    let mut wire = [0u8; 2048];
    for step in 0..16u64 {
        let t = 20 + step * 10;
        let mut moved = false;
        while let Some(p) = a.ep.poll_transmit(t, &mut wire, 16).unwrap().packet {
            b.ep.input(t, p.ip, &wire[..p.len]).unwrap();
            moved = true;
        }
        while let Some(p) = b.ep.poll_transmit(t, &mut wire, 16).unwrap().packet {
            a.ep.input(t, p.ip, &wire[..p.len]).unwrap();
            moved = true;
        }
        if !moved {
            break;
        }
    }
    for _ in 0..3 {
        let _ = b.ep.accept(listener).unwrap();
    }

    // Queue multi-chunk data + shared payloads on all 3 connections.
    for &c in &clients {
        let big = fill_pattern(&mut rng, 20_000);
        assert!(a.ep.write(c, &big).unwrap() > 16 * 1024);
        let shared = Payload::from_vec(fill_pattern(&mut rng, 4096));
        assert_eq!(a.ep.write_shared(c, shared, false, false, None).unwrap(), 4096);
    }

    // Hold 3 distinct kinds of live output reservations simultaneously:
    // 1. Live prepared GSO TransmitGroup on clients[0]
    let mut hdr0 = [0u8; 160];
    let (_, att0) = a
        .ep
        .poll_transmit_attempt(1000, &mut hdr0, 8, Some(clients[0]))
        .unwrap();
    let att0 = att0.expect("attempt on client 0");
    let grp0 = a
        .ep
        .prepare_transmit_group(att0, gso_group_limits())
        .unwrap()
        .expect("GSO group on client 0");
    let _ = segment_group(&a.ep, grp0);

    // 2. Live scalar TransmitAttempt on clients[1]
    let mut hdr1 = [0u8; 160];
    let (_, att1) = a
        .ep
        .poll_transmit_attempt(1000, &mut hdr1, 8, Some(clients[1]))
        .unwrap();
    assert!(att1.is_some());

    // 3. Live retained `offer_fresh_transmit` reservation on clients[2]
    //    (callback returns `None`, exercising `FreshTransmit::drop` capture
    //    right before `Endpoint::drop`).
    let mut fresh_buf = [0u8; 160];
    let mut fresh_hit = false;
    let offered = a
        .ep
        .offer_fresh_transmit(1000, clients[2], &mut fresh_buf, 14, false, |frame| {
            let _ = frame.with_tx_packet(60, |_| {
                fresh_hit = true;
            });
            None
        })
        .unwrap();
    if matches!(offered, FreshPoll::Unavailable) {
        // When GSO is enabled and multi-MSS data is queued, fall back to a
        // reserved scalar poll so clients[2] still holds a live reservation.
        let mut hdr2 = [0u8; 160];
        let (_, att2) = a
            .ep
            .poll_transmit_attempt(1000, &mut hdr2, 8, Some(clients[2]))
            .unwrap();
        assert!(att2.is_some());
    } else {
        assert!(matches!(offered, FreshPoll::Reserved { .. }));
    }

    assert!(a.ep.tx_pool_live() > 0);
    // Drop both endpoints directly while live chunks AND live output
    // reservations exist: Endpoint::drop's `debug_assert_eq!(tx_pool.live(), 0)`
    // and ChunkArena's generation checks must pass with zero panics.
    drop(a);
    drop(b);
}

#[test]
fn d3_endpoint_randomized_tx_pool_and_chunk_ref_lifecycle() {
    for seed in [1u64, 2, 3] {
        run_seed(seed);
        run_drop_with_live_data_and_reservations(seed);
    }
}
