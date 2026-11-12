use ntcp::{
    ActiveOpenOptions, ConnectionConfig, ConnectionId, Endpoint, EndpointConfig, EndpointError,
    Error, FastOpenClientPolicy, FastOpenEarlyDataPolicy, GsoLimits, InitialWindow, Payload,
    PmtudConfig, PmtudPolicy, RoutePolicy, State, TransmitAttempt, TransmitSegmentation,
    wire::{self, ACK, FIN, SYN},
};
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Output {
    Scalar,
    Reserved,
    Shared,
    Gso,
    SharedGso,
}
const OUTPUTS: [Output; 5] = [
    Output::Scalar,
    Output::Reserved,
    Output::Shared,
    Output::Gso,
    Output::SharedGso,
];
impl Output {
    fn enable(self, e: &mut Endpoint) {
        match self {
            Self::Scalar => return,
            Self::Gso | Self::SharedGso => e
                .enable_output_reservations_with_gso(
                    1,
                    GsoLimits {
                        max_bytes: 16000,
                        max_segments: 8,
                    },
                )
                .unwrap(),
            _ => e.enable_output_reservations().unwrap(),
        }
        if matches!(self, Self::Shared | Self::SharedGso) {
            e.enable_shared_output(8).unwrap();
        }
    }
    fn shared(self) -> bool {
        matches!(self, Self::Shared | Self::SharedGso)
    }
}

fn config(timestamps: bool, send_limit: u16) -> ConnectionConfig {
    ConnectionConfig {
        mss: 4096,
        send_capacity: 65536,
        receive_capacity: 32768,
        receive_ip_payload_limit: 6020,
        send_ip_payload_limit: send_limit,
        timestamps,
        sack: true,
        nagle: false,
        delayed_ack_us: 0,
        initial_window: InitialWindow::Iw10,
        ..Default::default()
    }
}
fn endpoint(c: ConnectionConfig, secret: u8) -> Endpoint {
    endpoint_with_reuse(c, secret, false)
}
fn endpoint_with_reuse(c: ConnectionConfig, secret: u8, reuse_time_wait: bool) -> Endpoint {
    Endpoint::new(
        EndpointConfig {
            max_connections: 16,
            max_listeners: 2,
            connection: c,
            reuse_time_wait,
            ..Default::default()
        },
        [secret; 32],
        0,
        |_| true,
    )
    .unwrap()
}
fn addresses(port: u16) -> (SocketAddr, SocketAddr) {
    (
        SocketAddr::new("2001:db8::1".parse().unwrap(), port),
        "[2001:db8::2]:8080".parse().unwrap(),
    )
}

struct Frame {
    bytes: Vec<u8>,
    token: Option<TransmitAttempt>,
    segmentation: Option<TransmitSegmentation>,
}
impl Frame {
    fn tcp(&self) -> wire::Segment<'_> {
        let p = ntcp_ip6::parse(&self.bytes).unwrap();
        assert_eq!(wire::checksum(p.ip, p.payload).unwrap(), 0);
        wire::parse(p.ip, p.payload).unwrap()
    }
    fn deliver(&self, peer: &mut Endpoint, now: u64) {
        let p = ntcp_ip6::parse(&self.bytes).unwrap();
        self.tcp();
        peer.input(now, p.ip, p.payload).unwrap();
    }
    fn accept(&self, e: &mut Endpoint, now: u64) {
        if let Some(token) = self.token {
            assert!(e.accept_transmit(now, token).unwrap());
            assert!(!e.accept_transmit(now, token).unwrap());
        }
    }
}
// Both ordinary and scatter/gather output use the real IP codec. Every returned
// frame is a physical packet, even when the reservation spans several packets.
fn poll(e: &mut Endpoint, id: ConnectionId, now: u64, mode: Output, bound: usize) -> Option<Frame> {
    let mut tcp = vec![0xa5; 16384];
    let mut payload = Vec::with_capacity(8);
    let (out, token) = match mode {
        Output::Scalar => (e.poll_transmit(now, &mut tcp, 64).unwrap(), None),
        _ if mode.shared() => e
            .poll_reserved_transmit_shared_for(now, id, &mut tcp, &mut payload, 64)
            .unwrap(),
        _ => e.poll_reserved_transmit_for(now, id, &mut tcp, 64).unwrap(),
    };
    let tx = out.packet?;
    let segmentation = token.and_then(|t| e.transmit_segmentation(t));
    let external = payload.iter().map(Payload::len).sum::<usize>();
    let resident = tx.len - external;
    let mut bytes = vec![0; 40 + tx.len];
    bytes[40..40 + resident].copy_from_slice(&tcp[..resident]);
    if external != 0 {
        assert!(tcp[resident..].iter().all(|&b| b == 0xa5));
        assert_eq!(
            ntcp_ip6::encode_shared_header(&mut bytes[..40 + resident], tx, resident).unwrap(),
            40 + resident
        );
        let mut cursor = 40 + resident;
        for p in &payload {
            bytes[cursor..cursor + p.len()].copy_from_slice(p.as_slice());
            cursor += p.len();
        }
    } else {
        assert_eq!(ntcp_ip6::encode(&mut bytes, tx).unwrap(), bytes.len());
    }
    assert!(
        bytes.len() <= bound,
        "{:?}: {} > {}",
        mode,
        bytes.len(),
        bound
    );
    let frame = Frame {
        bytes,
        token,
        segmentation,
    };
    frame.tcp();
    Some(frame)
}
fn take(e: &mut Endpoint, id: ConnectionId, now: u64, mode: Output, bound: usize) -> Frame {
    let f = poll(e, id, now, mode, bound).expect("packet");
    f.accept(e, now);
    f
}
fn pump(
    a: &mut Endpoint,
    b: &mut Endpoint,
    ids: (ConnectionId, ConnectionId),
    now: u64,
    mode: Output,
    bound: usize,
) -> Vec<Frame> {
    let mut frames = Vec::new();
    for _ in 0..200 {
        let mut progress = false;
        let mut outbound = [Vec::new(), Vec::new()];
        for direction in 0..2 {
            let (src, id) = if direction == 0 {
                (&mut *a, ids.0)
            } else {
                (&mut *b, ids.1)
            };
            loop {
                if let Some(f) = poll(src, id, now, mode, bound) {
                    f.accept(src, now);
                    outbound[direction].push(f);
                    progress = true;
                }
                if !src.is_output_reserved(id) {
                    break;
                }
            }
        }
        for (direction, batch) in outbound.into_iter().enumerate() {
            for f in batch {
                f.deliver(if direction == 0 { &mut *b } else { &mut *a }, now);
                frames.push(f);
            }
        }
        if !progress {
            return frames;
        }
    }
    panic!("output did not drain");
}
fn pair(c: ConnectionConfig, mode: Output) -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let mut a = endpoint(c.clone(), 1);
    let mut b = endpoint(c, 2);
    mode.enable(&mut a);
    mode.enable(&mut b);
    let (local, remote) = addresses(40000);
    let listener = b.listen(remote, 8).unwrap();
    // Listener override must not bypass the normalized passive send budget.
    b.set_listener_user_mss(listener, Some(5000)).unwrap();
    let id = a.connect(0, local, remote).unwrap();
    let bound = 1280;
    let syn = take(&mut a, id, 1, mode, bound);
    assert_eq!(syn.tcp().options.mss, Some(4096));
    syn.deliver(&mut b, 1);
    let peer = b
        .connection_id(ntcp::Tuple {
            local: remote,
            remote: local,
        })
        .unwrap();
    let synack = take(&mut b, peer, 2, mode, bound);
    assert_eq!(synack.tcp().options.mss, Some(4096));
    synack.deliver(&mut a, 2);
    take(&mut a, id, 3, mode, bound).deliver(&mut b, 3);
    assert_eq!(b.accept(listener).unwrap(), peer);
    assert_eq!(a.buffer_capacities(id).unwrap(), (65536, 32768));
    assert_eq!(b.buffer_capacities(peer).unwrap(), (65536, 32768));
    assert_eq!(a.path_mtu_info(id).unwrap(), None);
    assert_eq!(b.path_mtu_info(peer).unwrap(), None);
    (a, b, id, peer)
}

//= https://www.rfc-editor.org/rfc/rfc8201#section-1
//= type=test
//= reason=Shared active/passive construction caps only the disabled IPv6 send IP-payload budget at the minimum link MTU minus the supported base header, preserving smaller caller limits, receive capability and configured storage. Actual codec/peer tests cover boundary-sized scalar, reserved, shared and coalesced output, options, RTO repair, Fast Open, live MSS updates and TIME-WAIT reopening; enabled discovery retains larger packets and validated growth. Smaller packets can cost throughput; discovery defaults are unchanged.
//# Nodes not implementing Path MTU Discovery must use the IPv6 minimum link MTU
//# defined in [RFC8200] as the maximum packet size. In most cases, this will result
//# in the use of smaller packets than necessary, because most paths have a PMTU
//# greater than the IPv6 minimum link MTU. A node sending packets much smaller than
//# the Path MTU allows is wasting network resources and probably getting
//# suboptimal throughput.
#[test]
fn disabled_ipv6_codec_peer_boundaries_options_loss_and_output_modes() {
    for mode in OUTPUTS {
        for timestamps in [false, true] {
            for limit in [u16::MAX, 1000] {
                let bound = 40 + usize::from(limit.min(1240));
                let (mut a, mut b, id, peer) = pair(config(timestamps, limit), mode);
                let data: Vec<_> = (0..20000).map(|n| n as u8).collect();
                if mode.shared() {
                    assert_eq!(
                        a.write_shared(id, Payload::from_vec(data.clone()), false, false, None)
                            .unwrap(),
                        data.len()
                    );
                } else {
                    assert_eq!(a.write(id, &data).unwrap(), data.len());
                }
                let lost = take(&mut a, id, 10, mode, bound);
                assert_eq!(lost.bytes.len(), bound); // Positive boundary, not a tiny-packet witness.
                assert_eq!(lost.tcp().options.timestamps.is_some(), timestamps);
                if mode == Output::SharedGso {
                    assert!(lost.segmentation.is_none()); // Shared polling deliberately emits scalar references.
                }
                if mode == Output::Gso {
                    let group = lost.segmentation.expect("actual coalesced reservation");
                    assert!(group.payload_len > group.segment_payload_len);
                    assert!(group.payload_len + group.tcp_header_len + 40 > bound);
                    // Accept a prefix, then model a backend short submission:
                    // the following physical frame was not submitted and must
                    // be retried without changing the selected stream range.
                    let short = poll(&mut a, id, 10, mode, bound).unwrap();
                    let token = short.token.unwrap();
                    let progress = a.send_progress(id).unwrap();
                    assert!(a.reject_unsubmitted(token).unwrap());
                    assert!(!a.accept_transmit(10, token).unwrap());
                    let retry = take(&mut a, id, 10, mode, bound);
                    assert_eq!(retry.tcp().header.sequence, short.tcp().header.sequence);
                    assert_eq!(retry.tcp().payload, short.tcp().payload);
                    assert_eq!(a.send_progress(id).unwrap(), progress);
                    // Finish physically submitting this group, but lose it on the path.
                    while a.is_output_reserved(id) {
                        take(&mut a, id, 10, mode, bound);
                    }
                }
                let deadline = 10 + a.transport_info(id).unwrap().rto_us;
                a.on_timeout(deadline, 64).unwrap();
                let repair = take(&mut a, id, deadline, mode, bound);
                assert_eq!(repair.bytes.len(), bound);
                assert_eq!(repair.tcp().header.sequence, lost.tcp().header.sequence);
                assert_eq!(repair.tcp().payload, lost.tcp().payload);
                repair.deliver(&mut b, deadline);
                let frames = pump(&mut a, &mut b, (id, peer), deadline, mode, bound);
                assert!(frames.iter().any(|f| f.bytes.len() == bound));
                let mut received = vec![0; data.len()];
                assert_eq!(b.read(peer, &mut received).unwrap(), data.len());
                assert_eq!(received, data);
                assert_eq!(a.acknowledged(id).unwrap(), data.len() as u64);
                b.write(peer, &data[..8000]).unwrap();
                a.shutdown(id).unwrap();
                b.shutdown(peer).unwrap();
                let closing = pump(&mut a, &mut b, (id, peer), deadline + 1, mode, bound);
                assert!(closing.iter().any(|f| f.tcp().header.flags & FIN != 0));
                for f in &closing {
                    assert_eq!(f.tcp().options.timestamps.is_some(), timestamps);
                }
                assert_eq!(a.read(id, &mut received).unwrap(), 8000);
                assert_eq!(&received[..8000], &data[..8000]);
            }
        }
    }
}

#[test]
fn disabled_ipv6_full_option_data_and_ack_with_three_sack_blocks() {
    for mode in OUTPUTS {
        let (mut a, mut b, id, peer) = pair(config(true, u16::MAX), mode);
        b.write(peer, &[9; 10000]).unwrap();
        let mut sent = Vec::new();
        for _ in 0..6 {
            sent.push(take(&mut b, peer, 10, mode, 1280));
        }
        while b.is_output_reserved(peer) {
            sent.push(take(&mut b, peer, 10, mode, 1280));
        }
        // Three disjoint receive ranges create the largest TS+SACK TCP header.
        for i in [1, 3, 5] {
            sent[i].deliver(&mut a, 10);
        }
        a.write(id, &[7; 8000]).unwrap();
        let f = take(&mut a, id, 11, mode, 1280);
        assert_eq!(f.bytes.len(), 1280);
        assert_eq!(f.tcp().options.sack_blocks.iter().flatten().count(), 3);
        assert!(f.tcp().options.timestamps.is_some());
        assert_eq!(f.tcp().payload.len(), 1180); // 40 IPv6 + 60 TCP + data.
        f.deliver(&mut b, 11);
        // Like the peer's flight above, a GSO range is submitted whole before
        // its owner takes input; each segment repeats the SACK blocks.
        while a.is_output_reserved(id) {
            let next = take(&mut a, id, 11, mode, 1280);
            assert_eq!(next.tcp().options.sack_blocks, f.tcp().options.sack_blocks);
            next.deliver(&mut b, 11);
        }
        for (i, frame) in sent.iter().enumerate() {
            if ![1, 3, 5].contains(&i) {
                frame.deliver(&mut a, 11);
            }
        }
        pump(&mut a, &mut b, (id, peer), 12, mode, 1280);
        assert_eq!(a.read(id, &mut [0; 10000]).unwrap(), 10000);
        assert_eq!(b.read(peer, &mut [0; 8000]).unwrap(), 8000);
        // DSACK alone on a genuine repeated packet also survives output.
        sent[0].deliver(&mut a, 13);
        let ack = take(&mut a, id, 13, mode, 1280);
        assert_eq!(ack.tcp().header.flags & ACK, ACK);
        assert!(ack.tcp().payload.is_empty());
        assert!(ack.tcp().options.sack_blocks[0].is_some());
        ack.deliver(&mut b, 13);
    }
}

#[test]
fn disabled_ipv6_live_mss_and_failed_reserved_submission_keep_ceiling() {
    for mode in OUTPUTS {
        let (mut a, mut b, id, peer) = pair(config(true, u16::MAX), mode);
        for (step, (mss, expected)) in [(Some(800), 860), (None, 1280), (Some(6000), 1280)]
            .into_iter()
            .enumerate()
        {
            let now = 10 + step as u64 * 2;
            // An MSS change allocates nothing; the first write allocates the
            // send ring.
            let allocation = a.buffer_bytes();
            a.set_user_mss(id, mss).unwrap();
            assert_eq!(a.buffer_bytes(), allocation);
            a.write(id, &[5; 4000]).unwrap();
            if mode == Output::Scalar {
                let before = (a.send_progress(id).unwrap(), a.next_deadline());
                assert_eq!(
                    a.poll_transmit(now, &mut [0; 19], 64),
                    Err(EndpointError::Connection(Error::OutputTooSmall))
                );
                assert_eq!((a.send_progress(id).unwrap(), a.next_deadline()), before);
            }
            let f = poll(&mut a, id, now, mode, 1280).unwrap();
            assert_eq!(f.bytes.len(), expected);
            if let Some(token) = f.token {
                let before = (
                    a.send_progress(id).unwrap(),
                    a.next_deadline(),
                    a.buffer_bytes(),
                );
                assert_eq!(a.set_user_mss(id, None), Err(EndpointError::OutputReserved));
                assert_eq!(a.lower_mss(id, 700), Err(EndpointError::OutputReserved));
                assert!(a.reject_unsubmitted(token).unwrap());
                assert!(!a.accept_transmit(now, token).unwrap());
                let retry = take(&mut a, id, now, mode, 1280);
                assert_eq!(retry.bytes.len(), f.bytes.len());
                assert_eq!(retry.tcp().header, f.tcp().header);
                assert_eq!(retry.tcp().options, f.tcp().options);
                assert_eq!(retry.tcp().payload, f.tcp().payload);
                assert_eq!(a.send_progress(id).unwrap(), before.0);
                assert_eq!(a.buffer_bytes(), before.2);
                retry.deliver(&mut b, now);
            } else {
                f.deliver(&mut b, now);
            }
            pump(&mut a, &mut b, (id, peer), now + 1, mode, 1280);
            assert_eq!(b.read(peer, &mut [0; 4000]).unwrap(), 4000);
        }
        a.lower_mss(id, 700).unwrap();
        a.set_user_mss(id, None).unwrap();
        a.write(id, &[8; 4000]).unwrap();
        let lower = take(&mut a, id, 20, mode, 1280);
        assert_eq!(lower.bytes.len(), 760);
        lower.deliver(&mut b, 20);
        pump(&mut a, &mut b, (id, peer), 20, mode, 1280);
        assert_eq!(b.read(peer, &mut [0; 4000]).unwrap(), 4000);
        a.write(id, &[9; 4000]).unwrap();
        let before = (
            a.send_progress(id).unwrap(),
            a.next_deadline(),
            a.buffer_bytes(),
            a.transport_info(id).unwrap(),
        );
        for result in [
            a.set_route_mtu(1000, id, Some(9000)),
            a.set_first_hop_mtu(1000, id, 9000),
            a.set_pmtud_policy(1000, id, PmtudPolicy::default()),
            a.set_endpoint_first_hop_mtu(1000, 9000),
        ] {
            assert_eq!(
                result,
                Err(EndpointError::Connection(Error::InvalidArgument))
            );
        }
        assert_eq!(
            (
                a.send_progress(id).unwrap(),
                a.next_deadline(),
                a.buffer_bytes(),
                a.transport_info(id).unwrap()
            ),
            before
        );
        assert_eq!(a.path_mtu_info(id).unwrap(), None);
        assert_eq!(
            a.set_destination_route(
                1000,
                addresses(40000).1.ip(),
                Some(RoutePolicy {
                    mtu: Some(9000),
                    ..Default::default()
                })
            ),
            Err(EndpointError::Connection(Error::InvalidArgument))
        );
        // A valid earlier time proves rejected updates did not advance the clock.
        poll(&mut a, id, 20, mode, 1280);
    }
}

#[test]
fn disabled_ipv6_fast_open_cold_warm_supplied_protected_and_rejected() {
    for mode in OUTPUTS {
        for limit in [u16::MAX, 1000] {
            let bound = 40 + usize::from(limit.min(1240));
            let c = config(true, limit);
            let mut a = endpoint(c.clone(), 1);
            let mut b = endpoint(
                ConnectionConfig {
                    fast_open_early_response: true,
                    ..c.clone()
                },
                2,
            );
            a.enable_fast_open().unwrap();
            b.enable_fast_open().unwrap();
            mode.enable(&mut a);
            mode.enable(&mut b);
            let (local, remote) = addresses(41000);
            let listener = b.listen(remote, 8).unwrap();
            b.set_listener_fast_open(listener, 8).unwrap();
            let initial = vec![3; 10000];
            let (cold, n) = a.connect_fast_open(0, local, remote, &initial).unwrap();
            assert_eq!(n, 0);
            let syn = take(&mut a, cold, 1, mode, bound);
            assert!(syn.tcp().payload.is_empty());
            assert_eq!(
                syn.tcp().options.fast_open,
                Some(wire::FastOpenCookie::request())
            );
            syn.deliver(&mut b, 1);
            let cold_peer = b
                .connection_id(ntcp::Tuple {
                    local: remote,
                    remote: local,
                })
                .unwrap();
            let reply = take(&mut b, cold_peer, 2, mode, bound);
            let cookie = reply.tcp().options.fast_open.unwrap();
            assert!(!cookie.as_bytes().is_empty());
            assert_eq!(reply.tcp().options.mss, Some(4096));
            reply.deliver(&mut a, 2);
            pump(&mut a, &mut b, (cold, cold_peer), 3, mode, bound);
            assert_eq!(b.accept(listener).unwrap(), cold_peer);
            assert!(a.has_fast_open_cookie(3, local.ip(), remote.ip()).unwrap());

            for attempt in 0..5 {
                // learned cookie, supplied valid cookie, maximum-length invalid
                // cookie (rejection/repair), protected omitted option, agreed zero cookie.
                let (local, _) = addresses(41001 + attempt);
                let now = 10 + u64::from(attempt) * 10;
                if attempt >= 3 {
                    b.set_listener_fast_open_early_data_policy(
                        listener,
                        FastOpenEarlyDataPolicy::ApplicationProtected,
                    )
                    .unwrap();
                }
                let options = ActiveOpenOptions::from(&c);
                let (id, n) = match attempt {
                    0 => a.connect_fast_open(now, local, remote, &initial),
                    1 | 2 | 4 => a.connect_fast_open_with_server_cookie(
                        now,
                        local,
                        remote,
                        &initial,
                        options,
                        Some(match attempt {
                            1 => cookie,
                            2 => wire::FastOpenCookie::new(&[0xa5; 16]).unwrap(),
                            _ => wire::FastOpenCookie::request(),
                        }),
                    ),
                    _ => a.connect_fast_open_with_policy(
                        now,
                        local,
                        remote,
                        &initial,
                        options,
                        FastOpenClientPolicy::ApplicationProtected,
                    ),
                }
                .unwrap();
                // A rejected cookie suppresses subsequent early attempts at that
                // service; use the existing explicit cache clear for the next case.
                let expected = if attempt == 0 {
                    usize::from(limit.min(1240)) - 60 // Validated learned MSS, path limited.
                } else {
                    496 // Cold admission after explicit cache clear, including IPv6.
                };
                assert_eq!(n, expected);
                let syn = poll(&mut a, id, now, mode, bound).unwrap();
                assert_eq!(syn.tcp().header.flags & SYN, SYN);
                assert_eq!(syn.tcp().options.mss, Some(4096));
                assert_eq!(syn.tcp().payload, &initial[..n]);
                assert!(syn.tcp().options.timestamps.is_some());
                assert_eq!(syn.tcp().options.fast_open.is_none(), attempt == 3);
                if attempt == 2 {
                    assert_eq!(syn.tcp().raw_options.len(), 40);
                    assert_eq!(syn.bytes.len(), 596); // Full options plus conservative cold data.
                }
                if let Some(token) = syn.token {
                    assert!(a.reject_unsubmitted(token).unwrap());
                    let retry = take(&mut a, id, now, mode, bound);
                    assert_eq!(retry.tcp().header.sequence, syn.tcp().header.sequence);
                    assert_eq!(retry.tcp().payload, syn.tcp().payload);
                    retry.deliver(&mut b, now);
                } else {
                    syn.deliver(&mut b, now);
                }
                let peer = b
                    .connection_id(ntcp::Tuple {
                        local: remote,
                        remote: local,
                    })
                    .unwrap();
                let authorized = attempt != 2;
                assert_eq!(
                    b.readable_bytes(peer).unwrap(),
                    if authorized { n } else { 0 }
                );
                // The supported passive path sends its option-bearing SYN-ACK
                // first, then permits early response data before the final ACK.
                if authorized {
                    b.write(peer, &initial).unwrap();
                }
                let reply = take(&mut b, peer, now + 1, mode, bound);
                assert_eq!(reply.tcp().header.flags & (SYN | ACK), SYN | ACK);
                assert_eq!(
                    reply.tcp().header.acknowledgment,
                    syn.tcp()
                        .header
                        .sequence
                        .wrapping_add(1 + if authorized { n as u32 } else { 0 })
                );
                assert!(reply.tcp().payload.is_empty());
                reply.deliver(&mut a, now + 1);
                if authorized {
                    assert_eq!(b.state(peer).unwrap(), State::SynReceived);
                    let early = take(&mut b, peer, now + 1, mode, bound);
                    assert_eq!(early.bytes.len(), bound);
                    assert_eq!(early.tcp().header.flags & SYN, 0);
                    early.deliver(&mut a, now + 1);
                }
                if !authorized {
                    let repair = take(&mut a, id, now + 2, mode, bound);
                    assert_eq!(repair.tcp().header.flags & SYN, 0);
                    assert_eq!(
                        repair.tcp().header.sequence,
                        syn.tcp().header.sequence.wrapping_add(1)
                    );
                    assert_eq!(repair.tcp().payload, &initial[..repair.tcp().payload.len()]);
                    repair.deliver(&mut b, now + 2);
                }
                pump(&mut a, &mut b, (id, peer), now + 3, mode, bound);
                let accepted = b.accept(listener).unwrap();
                assert_eq!(accepted, peer);
                let mut received = vec![0; initial.len()];
                assert_eq!(b.read(peer, &mut received).unwrap(), n);
                assert_eq!(&received[..n], &initial[..n]);
                if authorized {
                    assert_eq!(a.read(id, &mut received).unwrap(), initial.len());
                    assert_eq!(received, initial);
                }
                assert_eq!(a.acknowledged(id).unwrap(), n as u64);
                assert_eq!(a.transport_info(id).unwrap().advertised_mss, 4096);
                a.clear_fast_open_client_cache();
                // Explicit supplied and protected cases below do not need the
                // credential cache; conservative cold admission remains separate
                // from the actual IPv6 peer MSS and ordinary send ceiling.
            }
        }
    }
}

#[test]
fn disabled_ipv6_presyn_mss_reset_frozen_offer_and_large_receive_capability() {
    let mut a = endpoint(config(true, u16::MAX), 1);
    let mut c = config(true, u16::MAX);
    c.pmtud = Some(PmtudConfig::new(4156));
    let mut b = endpoint(c, 2);
    let (local, remote) = addresses(42000);
    let listener = b.listen(remote, 8).unwrap();
    let id = a.connect(0, local, remote).unwrap();
    let allocation = a.buffer_bytes();
    a.set_user_mss(id, Some(800)).unwrap();
    assert!(a.poll_transmit(0, &mut [0; 19], 64).is_err());
    a.set_user_mss(id, None).unwrap();
    let syn = take(&mut a, id, 1, Output::Scalar, 1280);
    assert_eq!(syn.tcp().options.mss, Some(4096));
    assert_eq!(a.buffer_bytes(), allocation);
    a.set_user_mss(id, Some(700)).unwrap();
    let expiry = a.next_deadline().unwrap();
    a.on_timeout(expiry, 64).unwrap();
    let retry = take(&mut a, id, expiry, Output::Scalar, 1280);
    assert_eq!(retry.tcp().options.mss, Some(4096)); // Frozen receive offer.
    a.set_user_mss(id, Some(6000)).unwrap();
    retry.deliver(&mut b, expiry);
    let peer = b
        .connection_id(ntcp::Tuple {
            local: remote,
            remote: local,
        })
        .unwrap();
    take(&mut b, peer, expiry + 1, Output::Scalar, 4156).deliver(&mut a, expiry + 1);
    take(&mut a, id, expiry + 2, Output::Scalar, 1280).deliver(&mut b, expiry + 2);
    assert_eq!(b.accept(listener).unwrap(), peer);
    b.write(peer, &[0x5a; 12000]).unwrap();
    let big = take(&mut b, peer, expiry + 3, Output::Scalar, 4156);
    assert_eq!(big.bytes.len(), 4156);
    assert_eq!(big.tcp().payload.len(), 4084);
    big.deliver(&mut a, expiry + 3);
    assert_eq!(a.read(id, &mut [0; 5000]).unwrap(), 4084);
    let ack = take(&mut a, id, expiry + 3, Output::Scalar, 1280);
    ack.deliver(&mut b, expiry + 3);
    a.write(id, &[7; 10000]).unwrap();
    assert_eq!(
        take(&mut a, id, expiry + 4, Output::Scalar, 1280)
            .bytes
            .len(),
        1280
    );
    assert_eq!(a.transport_info(id).unwrap().advertised_mss, 4096);
    assert_eq!(a.buffer_capacities(id).unwrap(), (65536, 32768));
    assert_eq!(a.path_mtu_info(id).unwrap(), None);
}

#[test]
fn enabled_ipv6_codec_validated_ptb_and_ack_confirmed_growth_still_use_large_packets() {
    let mut c = config(true, u16::MAX);
    c.pmtud = Some(PmtudConfig {
        initial_search_low: Some(1500),
        ..PmtudConfig::new(1500)
    });
    let mut a = endpoint(c.clone(), 1);
    let mut b = endpoint(c, 2);
    let (local, remote) = addresses(43000);
    let listener = b.listen(remote, 8).unwrap();
    let id = a.connect(0, local, remote).unwrap();
    take(&mut a, id, 1, Output::Scalar, 1500).deliver(&mut b, 1);
    let peer = b
        .connection_id(ntcp::Tuple {
            local: remote,
            remote: local,
        })
        .unwrap();
    take(&mut b, peer, 2, Output::Scalar, 1500).deliver(&mut a, 2);
    take(&mut a, id, 3, Output::Scalar, 1500).deliver(&mut b, 3);
    b.accept(listener).unwrap();
    a.write(id, &[0x33; 20000]).unwrap();
    let lost = take(&mut a, id, 10, Output::Scalar, 1500);
    assert_eq!(lost.bytes.len(), 1500);
    let tuple = a.tuple(id).unwrap();
    let seq = lost.tcp().header.sequence;
    let before = a.path_mtu_info(id).unwrap();
    assert!(
        !a.pmtu_feedback(11, tuple, seq, lost.bytes.len() as u32, 40, 1279)
            .unwrap()
    );
    assert_eq!(a.path_mtu_info(id).unwrap(), before);
    assert!(
        !a.pmtu_feedback(
            11,
            tuple,
            seq.wrapping_sub(1),
            lost.bytes.len() as u32,
            40,
            1280
        )
        .unwrap()
    );
    assert!(
        a.pmtu_feedback(11, tuple, seq, lost.bytes.len() as u32, 40, 1280)
            .unwrap()
    );
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().current_mtu, 1280);
    let repair = take(&mut a, id, 12, Output::Scalar, 1280);
    assert_eq!(repair.bytes.len(), 1280);
    assert_eq!(repair.tcp().header.sequence, seq);
    repair.deliver(&mut b, 12);
    pump(&mut a, &mut b, (id, peer), 13, Output::Scalar, 1500);
    assert_eq!(b.read(peer, &mut [0; 20000]).unwrap(), 20000);
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().current_mtu, 1280);
    let now = 600_000_100;
    a.on_timeout(now, 64).unwrap();
    b.on_timeout(now, 64).unwrap();
    a.write(id, &[0x77; 20000]).unwrap();
    let probe = take(&mut a, id, now, Output::Scalar, 1500);
    assert!(probe.bytes.len() > 1280);
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().current_mtu, 1280);
    probe.deliver(&mut b, now);
    take(&mut b, peer, now + 1, Output::Scalar, 1500).deliver(&mut a, now + 1);
    assert_eq!(
        a.path_mtu_info(id).unwrap().unwrap().current_mtu,
        probe.bytes.len() as u32
    );
    pump(&mut a, &mut b, (id, peer), now + 2, Output::Scalar, 1500);
    assert_eq!(b.read(peer, &mut [0; 20000]).unwrap(), 20000);
}

#[test]
fn disabled_ipv6_time_wait_reopening_uses_the_same_passive_send_ceiling() {
    for mode in [Output::Scalar, Output::Reserved, Output::Shared] {
        // The old peer omits TS; the restarted peer offers it. This exercises
        // RFC6191's no-old-TS/new-TS branch through the real passive factory.
        let c = config(true, u16::MAX);
        let mut a = endpoint(config(false, u16::MAX), 1);
        let mut b = endpoint_with_reuse(c.clone(), 2, true);
        mode.enable(&mut a);
        mode.enable(&mut b);
        let (local, remote) = addresses(40000);
        let listener = b.listen(remote, 8).unwrap();
        let id = a.connect(0, local, remote).unwrap();
        take(&mut a, id, 1, mode, 1280).deliver(&mut b, 1);
        let peer = b
            .connection_id(ntcp::Tuple {
                local: remote,
                remote: local,
            })
            .unwrap();
        take(&mut b, peer, 2, mode, 1280).deliver(&mut a, 2);
        take(&mut a, id, 3, mode, 1280).deliver(&mut b, 3);
        assert_eq!(b.accept(listener).unwrap(), peer);
        assert!(!b.transport_info(peer).unwrap().timestamps_negotiated);
        b.shutdown(peer).unwrap();
        pump(&mut a, &mut b, (id, peer), 10, mode, 1280);
        a.shutdown(id).unwrap();
        pump(&mut a, &mut b, (id, peer), 11, mode, 1280);
        assert_eq!(b.state(peer).unwrap(), State::TimeWait);
        // A restarted active endpoint reuses the actual tuple and offers TS.
        let mut fresh = endpoint(c, 4);
        mode.enable(&mut fresh);
        let (local, remote) = addresses(40000);
        let child = fresh.connect(10000, local, remote).unwrap();
        take(&mut fresh, child, 10000, mode, 1280).deliver(&mut b, 10000);
        let reopened = b
            .connection_id(ntcp::Tuple {
                local: remote,
                remote: local,
            })
            .unwrap();
        assert_ne!(reopened, peer);
        take(&mut b, reopened, 10001, mode, 1280).deliver(&mut fresh, 10001);
        take(&mut fresh, child, 10002, mode, 1280).deliver(&mut b, 10002);
        b.write(reopened, &[4; 10000]).unwrap();
        let full = take(&mut b, reopened, 10003, mode, 1280);
        assert_eq!(full.bytes.len(), 1280);
        full.deliver(&mut fresh, 10003);
        pump(&mut fresh, &mut b, (child, reopened), 10004, mode, 1280);
        assert_eq!(fresh.read(child, &mut [0; 10000]).unwrap(), 10000);
        assert_eq!(b.path_mtu_info(reopened).unwrap(), None);
        assert_eq!(b.transport_info(reopened).unwrap().advertised_mss, 4096);
    }
}
