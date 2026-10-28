use super::*;
use ntcp_io::PacketLayer;
use std::cell::Cell;

struct Backend {
    mtu: Option<u32>,
    errno: Option<i32>,
    queries: Cell<usize>,
    blocked: bool,
    frames: Vec<Vec<u8>>,
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            mtu: Some(MTU as u32),
            errno: None,
            queries: Cell::new(0),
            blocked: false,
            frames: Vec::new(),
        }
    }
}

impl PacketIo for Backend {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        self.queries.set(self.queries.get() + 1);
        match self.errno {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => Ok(self.mtu),
        }
    }
    fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        if self.blocked {
            return Ok(TxOutcome::WouldBlock);
        }
        self.frames.push(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
}

fn addresses(v6: bool) -> (SocketAddr, SocketAddr) {
    let (a, b) = if v6 {
        ("[2001:db8::1]:1234", "[2001:db8::2]:8080")
    } else {
        ("192.0.2.1:1234", "192.0.2.2:8080")
    };
    (a.parse().unwrap(), b.parse().unwrap())
}

fn endpoint(local: IpAddr, timestamps: bool) -> Endpoint {
    let backend = Backend::default();
    let config = runtime_config(&backend, local, timestamps, true, false).unwrap();
    assert_eq!(backend.queries.get(), 1);
    let policy: Box<dyn Fn(AddressValidation) -> bool> = match local {
        IpAddr::V4(ip) => Box::new(tun_address_policy(ip, (ip, 24))),
        IpAddr::V6(ip) => Box::new(tun_v6_policy(ip)),
    };
    Endpoint::new(config, [7; 32], 0, policy).unwrap()
}

// These assertions use the same constructor, dispatcher and output loop as run.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
#[test]
fn runtime_mtu_and_option_selection() {
    for v6 in [false, true] {
        let local = addresses(v6).0.ip();
        for (timestamps, sack) in [(false, true), (true, false)] {
            let backend = Backend::default();
            let cfg = runtime_config(&backend, local, timestamps, sack, !v6).unwrap();
            assert_eq!(backend.queries.get(), 1);
            assert_eq!(cfg.connection.pmtud, Some(PmtudConfig::new(1500)));
            assert_eq!(cfg.connection.timestamps, timestamps);
            assert_eq!(cfg.connection.sack, sack);
            assert_eq!(cfg.ipv4_options_enabled, !v6);
            let payload = if v6 { 1460 } else { 1480 };
            assert_eq!(cfg.connection.send_ip_payload_limit, payload);
            assert_eq!(cfg.connection.receive_ip_payload_limit, payload);
            assert_eq!(cfg.connection.send_capacity, 65536);
            assert_eq!(cfg.connection.receive_capacity, 65536);
        }
        for mtu in [
            None,
            Some(0),
            Some(1280),
            Some(1499),
            Some(1501),
            Some(9000),
        ] {
            let backend = Backend {
                mtu,
                ..Default::default()
            };
            let error = runtime_config(&backend, local, true, false, false).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("1500"));
            assert_eq!(backend.queries.get(), 1);
        }
        let backend = Backend {
            errno: Some(libc::EIO),
            ..Default::default()
        };
        let error = runtime_config(&backend, local, false, false, false).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(backend.queries.get(), 1);
    }
}

fn header(frame: &[u8]) -> usize {
    if frame[0] >> 4 == 6 {
        IPV6_HEADER
    } else {
        usize::from(frame[0] & 15) * 4
    }
}

fn segment(frame: &[u8]) -> ntcp::wire::Segment<'_> {
    let (ip, tcp) = if frame[0] >> 4 == 6 {
        let p = ntcp_ip6::parse(frame).unwrap();
        (p.ip, p.payload)
    } else {
        let p = ntcp_ip::parse(frame, false).unwrap();
        assert_eq!(
            u16::from_be_bytes([frame[6], frame[7]]),
            0x4000,
            "DF on every control/data/probe/repair"
        );
        (p.ip, p.payload)
    };
    ntcp::wire::parse(ip, tcp).unwrap()
}

fn emit(endpoint: &mut Endpoint, time: u64, local: IpAddr) -> Vec<Vec<u8>> {
    let mut backend = Backend::default();
    let mut output = [0; MTU];
    let mut pending = 0;
    transmit_frames(
        endpoint,
        time,
        &mut output,
        &mut pending,
        if local.is_ipv4() {
            IP_HEADER
        } else {
            IPV6_HEADER
        },
        0x8000_0000 | (time / 1000) as u32,
        &mut backend,
    )
    .unwrap();
    assert_eq!(pending, 0);
    for frame in &backend.frames {
        segment(frame);
    }
    backend.frames
}

struct Pair {
    a: Endpoint,
    b: Endpoint,
    aid: ConnectionId,
    bid: ConnectionId,
    local: SocketAddr,
    remote: SocketAddr,
    time: u64,
}

impl Pair {
    fn new(v6: bool, timestamps: bool) -> Self {
        let (local, remote) = addresses(v6);
        let mut a = endpoint(local.ip(), timestamps);
        let mut b = endpoint(remote.ip(), timestamps);
        // Match run(): an active opener also retains its passive listener.
        a.listen(local, MAX_FLOWS).unwrap();
        let listener = b.listen(remote, MAX_FLOWS).unwrap();
        let aid = a.connect(0, local, remote).unwrap();
        for passive in [false, true] {
            let (from, to, destination, time, flags) = if passive {
                (
                    &mut b,
                    &mut a,
                    local.ip(),
                    2000,
                    ntcp::wire::SYN | ntcp::wire::ACK,
                )
            } else {
                (&mut a, &mut b, remote.ip(), 1000, ntcp::wire::SYN)
            };
            let frames = emit(from, time, destination);
            assert_eq!(frames.len(), 1);
            let syn = segment(&frames[0]);
            assert_eq!(
                syn.header.flags & (ntcp::wire::SYN | ntcp::wire::ACK),
                flags
            );
            assert_eq!(syn.options.timestamps.is_some(), timestamps);
            input_frame(to, time, &frames[0], destination, false, 0).unwrap();
        }
        for frame in emit(&mut a, 3000, local.ip()) {
            input_frame(&mut b, 3000, &frame, remote.ip(), false, 0).unwrap();
        }
        let bid = b.accept(listener).unwrap();
        for (e, id) in [(&a, aid), (&b, bid)] {
            assert_eq!(e.state(id).unwrap(), State::Established);
            assert_eq!(
                e.transport_info(id).unwrap().timestamps_negotiated,
                timestamps
            );
            assert_eq!(e.path_mtu_info(id).unwrap().unwrap().first_hop_mtu, 1500);
        }
        Self {
            a,
            b,
            aid,
            bid,
            local,
            remote,
            time: 3000,
        }
    }

    fn next_timeout(&mut self) {
        let deadline = [self.a.next_deadline(), self.b.next_deadline()]
            .into_iter()
            .flatten()
            .min()
            .expect("outstanding data needs a deadline");
        assert!(deadline >= self.time);
        self.time = deadline;
        self.a.on_timeout(self.time, BUDGET).unwrap();
        self.b.on_timeout(self.time, BUDGET).unwrap();
    }

    // Drop only packets larger than this path. No synthetic ACKs or private
    // transport controls: every byte and ACK traverses the runtime dispatcher.
    fn progress(&mut self, path: usize, expected: &[u8]) -> (usize, Vec<Vec<u8>>) {
        let mut received = Vec::new();
        let mut sent = Vec::new();
        let mut drops = 0;
        for _ in 0..200 {
            for frame in emit(&mut self.a, self.time, self.local.ip()) {
                let tcp = segment(&frame);
                if !tcp.payload.is_empty() {
                    assert!(tcp.options.timestamps.is_some());
                }
                if frame.len() > path {
                    drops += 1;
                } else {
                    input_frame(&mut self.b, self.time, &frame, self.remote.ip(), false, 0)
                        .unwrap();
                }
                sent.push(frame);
            }
            let mut bytes = [0; 65536];
            match self.b.read(self.bid, &mut bytes) {
                Ok(n) => received.extend_from_slice(&bytes[..n]),
                Err(EndpointError::Connection(Error::WouldBlock)) => {}
                other => panic!("receiver: {other:?}"),
            }
            for frame in emit(&mut self.b, self.time, self.remote.ip()) {
                input_frame(&mut self.a, self.time, &frame, self.local.ip(), false, 0).unwrap();
            }
            let info = self.a.transport_info(self.aid).unwrap();
            if received.len() == expected.len() && info.unacked == 0 && info.notsent_bytes == 0 {
                assert_eq!(
                    received, expected,
                    "ordered stream, no missing or duplicated bytes"
                );
                assert!(matches!(
                    self.b.read(self.bid, &mut bytes),
                    Err(EndpointError::Connection(Error::WouldBlock))
                ));
                return (drops, sent);
            }
            self.next_timeout();
        }
        panic!(
            "receiver stalled at {}/{}: {:?}",
            received.len(),
            expected.len(),
            self.a.transport_info(self.aid)
        );
    }
}

// Construct a checksummed PTB with a minimum quote of an actual emitted frame.
// The source is an intermediate router, deliberately distinct from either peer.
fn ptb(frame: &[u8], mtu: u32) -> Vec<u8> {
    let h = header(frame);
    let v6 = frame[0] >> 4 == 6;
    let mut packet = vec![0; h + 8 + h + 8];
    packet[..h].copy_from_slice(&frame[..h]);
    if v6 {
        packet[8..24].copy_from_slice(&"2001:db8::fe".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&frame[8..24]);
        packet[4..6].copy_from_slice(&((8 + h + 8) as u16).to_be_bytes());
        packet[6] = 58;
    } else {
        packet[12..16].copy_from_slice(&[192, 0, 2, 254]);
        packet[16..20].copy_from_slice(&frame[12..16]);
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[9] = 1;
    }
    packet[h] = if v6 { 2 } else { 3 };
    packet[h + 1] = if v6 { 0 } else { 4 };
    packet[h + 4..h + 8].copy_from_slice(&mtu.to_be_bytes());
    packet[h + 8..].copy_from_slice(&frame[..h + 8]);
    seal_feedback(&mut packet);
    packet
}

fn seal_ip(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let sum = checksum(&packet[..header(packet)]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
}

fn seal_feedback(packet: &mut [u8]) {
    let h = header(packet);
    packet[h + 2..h + 4].fill(0);
    let sum = if packet[0] >> 4 == 6 {
        ntcp_icmp::icmpv6_checksum(
            IpMetadata {
                source: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()).into(),
                destination: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()).into(),
            },
            &packet[h..],
        )
        .unwrap()
    } else {
        seal_ip(packet);
        checksum(&packet[h..])
    };
    packet[h + 2..h + 4].copy_from_slice(&sum.to_be_bytes());
}

#[test]
fn runtime_active_passive_without_timestamps_still_discovers() {
    for v6 in [false, true] {
        Pair::new(v6, false);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
#[test]
fn runtime_ptb_repairs_and_receiver_ack_progress() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let payload: Vec<u8> = (0..12000).map(|n| (n % 251) as u8).collect();
        assert_eq!(p.a.write(p.aid, &payload).unwrap(), payload.len());
        let frames = emit(&mut p.a, p.time, p.local.ip());
        let original = &frames[0];
        let path = if v6 { 1280 } else { 1006 };
        assert!(original.len() > path);
        assert!(segment(original).options.timestamps.is_some());
        let report = ptb(original, path as u32);
        assert_ne!(
            ntcp_icmp::decode_icmp(&report).unwrap().outer.source,
            p.remote.ip()
        );
        input_frame(&mut p.a, p.time, &report, p.local.ip(), false, 0).unwrap();
        assert_eq!(
            p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu,
            path as u32
        );
        let (_, repairs) = p.progress(path, &payload);
        assert!(!repairs.is_empty());
        assert!(
            repairs.iter().all(|frame| frame.len() <= path),
            "full IP budget including timestamp overhead"
        );
        assert!(
            repairs
                .iter()
                .any(|f| segment(f).header.sequence == segment(original).header.sequence)
        );
        let before = p.a.path_mtu_info(p.aid).unwrap();
        // An acknowledged original quote is stale, even with a lower candidate.
        let stale = ptb(original, if v6 { 1280 } else { 508 });
        input_frame(&mut p.a, p.time, &stale, p.local.ip(), false, 0).unwrap();
        assert_eq!(p.a.path_mtu_info(p.aid).unwrap(), before);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
#[test]
fn runtime_icmp_blackhole_falls_back_with_paws_and_congestion_response() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let payload: Vec<u8> = (0..12000).map(|n| (n % 239) as u8).collect();
        p.a.write(p.aid, &payload).unwrap();
        let original = emit(&mut p.a, p.time, p.local.ip());
        let path = if v6 { 1280 } else { 1024 };
        assert!(original.iter().any(|f| f.len() > path));
        let initial = p.a.transport_info(p.aid).unwrap();
        // Suppress all ICMP. Drive the real RTO deadlines to R1, checking the
        // ordinary timeout congestion response before allowing smaller repairs.
        for count in 1..=3 {
            let backoff = p.a.transport_info(p.aid).unwrap().rto_backoff;
            for _ in 0..16 {
                p.next_timeout();
                if p.a.transport_info(p.aid).unwrap().rto_backoff > backoff {
                    break;
                }
                // Tail-loss probes also disappear into the same black hole.
                emit(&mut p.a, p.time, p.local.ip());
            }
            let info = p.a.transport_info(p.aid).unwrap();
            assert!(info.rto_backoff > backoff);
            assert_eq!(info.cwnd, info.mss);
            assert!(info.ssthresh < initial.cwnd);
            let mtu = p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu;
            assert_eq!(mtu, if count < 3 { 1500 } else { path as u32 });
            if count < 3 {
                let retries = emit(&mut p.a, p.time, p.local.ip());
                assert!(retries.iter().any(|f| f.len() > path));
            }
        }
        let (drops, repairs) = p.progress(path, &payload);
        assert_eq!(drops, 0);
        assert!(repairs.iter().all(|f| f.len() <= path));
        assert!(
            repairs
                .iter()
                .any(|f| segment(f).header.sequence == segment(&original[0]).header.sequence)
        );
        // After the existing cooldown expires, a repaired path may grow again.
        // Admit this later flight on the restored 1500-byte path. Its first
        // larger packet is a real PLPMTUD probe, with DF checked by segment().
        p.next_timeout();
        let followup = vec![0x93; 60000];
        p.a.write(p.aid, &followup).unwrap();
        let probes = emit(&mut p.a, p.time, p.local.ip());
        let mut largest = probes.iter().map(Vec::len).max().unwrap_or(0);
        for frame in probes {
            assert!(segment(&frame).options.timestamps.is_some());
            input_frame(&mut p.b, p.time, &frame, p.remote.ip(), false, 0).unwrap();
        }
        let (_, later) = p.progress(MTU, &followup);
        largest = largest.max(later.iter().map(Vec::len).max().unwrap_or(0));
        assert!(
            largest > path && largest <= MTU,
            "ACK-driven congestion credit admits a larger probe"
        );
        assert!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu > path as u32);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
#[test]
fn runtime_dispatch_rejects_uncorrelated_or_malformed_feedback() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        p.a.write(p.aid, &[0x5a; 12000]).unwrap();
        let original = emit(&mut p.a, p.time, p.local.ip()).remove(0);
        let h = header(&original);
        let path = if v6 { 1280 } else { 1006 };
        let valid = ptb(&original, path);
        let mut cases = Vec::new();
        for cut in 0..valid.len() {
            cases.push(("truncated", valid[..cut].to_vec(), p.local.ip()));
        }
        let mut bad = valid.clone();
        bad[h + 2] ^= 1;
        cases.push(("ICMP checksum", bad, p.local.ip()));
        for (name, offset) in [
            ("quoted destination", if v6 { 24 } else { 16 }),
            ("quoted source", if v6 { 8 } else { 12 }),
            ("source port", h),
            ("destination port", h + 2),
            ("sequence", h + 7),
        ] {
            let mut quote = original.clone();
            quote[offset] ^= 1;
            if !v6 {
                seal_ip(&mut quote);
            }
            cases.push((name, ptb(&quote, path), p.local.ip()));
        }
        let mut quote = original.clone();
        let stale_sequence = segment(&original).header.sequence.wrapping_sub(1);
        quote[h + 4..h + 8].copy_from_slice(&stale_sequence.to_be_bytes());
        cases.push((
            "already acknowledged SYN sequence",
            ptb(&quote, path),
            p.local.ip(),
        ));
        let mut quote = original.clone();
        let len_offset = if v6 { 4 } else { 2 };
        let size = u16::from_be_bytes([quote[len_offset], quote[len_offset + 1]]) + 1;
        quote[len_offset..len_offset + 2].copy_from_slice(&size.to_be_bytes());
        if !v6 {
            seal_ip(&mut quote);
        }
        cases.push(("exact sent size", ptb(&quote, path), p.local.ip()));
        let mut bad = valid.clone();
        bad[h + 8] ^= 0x10;
        seal_feedback(&mut bad);
        cases.push(("inner version", bad, p.local.ip()));
        if !v6 {
            let mut bad = valid.clone();
            bad[h + 8 + 10] ^= 1;
            seal_feedback(&mut bad);
            cases.push(("inner checksum", bad, p.local.ip()));
        }
        let mut bad = valid.clone();
        let destination = if v6 { 39 } else { 19 };
        bad[destination] ^= 1;
        seal_feedback(&mut bad);
        cases.push(("outer destination", bad, p.local.ip()));
        let mut bad = valid.clone();
        bad[h] = if v6 { 1 } else { 11 };
        bad[h + 1] = 0;
        seal_feedback(&mut bad);
        cases.push(("non PTB", bad, p.local.ip()));
        for mtu in [1500, 2000] {
            cases.push(("nondecreasing", ptb(&original, mtu), p.local.ip()));
        }
        if v6 {
            cases.push(("below IPv6 floor", ptb(&original, 1279), p.local.ip()));
        }
        cases.push(("wrong configured destination", valid.clone(), p.remote.ip()));
        cases.push(("wrong configured family", valid, addresses(!v6).0.ip()));
        let before = p.a.path_mtu_info(p.aid).unwrap();
        let transport = p.a.transport_info(p.aid).unwrap();
        let buffers = p.a.buffer_bytes();
        let deadline = p.a.next_deadline();
        for (name, report, configured) in cases {
            input_frame(&mut p.a, p.time, &report, configured, false, 0).unwrap();
            assert_eq!(p.a.path_mtu_info(p.aid).unwrap(), before, "{v6}: {name}");
            assert_eq!(p.a.transport_info(p.aid).unwrap(), transport, "{name}");
            assert_eq!(p.a.buffer_bytes(), buffers, "{name}");
            assert_eq!(p.a.next_deadline(), deadline, "{name}");
            // Even a valid report cannot instantiate an unknown TCP connection.
            let mut empty = endpoint(p.local.ip(), true);
            empty.listen(p.local, 1).unwrap();
            input_frame(&mut empty, p.time, &report, configured, false, 0).unwrap();
            assert_eq!(empty.buffer_bytes(), 0, "{name}");
            assert_eq!(
                empty.connection_id(Tuple {
                    local: p.local,
                    remote: p.remote
                }),
                None
            );
            assert!(emit(&mut empty, p.time, p.local.ip()).is_empty());
        }
        // Positive control on the identical flight after every rejected report.
        input_frame(
            &mut p.a,
            p.time,
            &ptb(&original, path),
            p.local.ip(),
            false,
            0,
        )
        .unwrap();
        assert_eq!(p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu, path);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
//= type=test
//= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
//# Setting the DF bit implies the use of Path MTU Discovery as described
//# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
//# that implements PAWS MUST also implement Path MTU Discovery.
#[test]
fn runtime_ptb_does_not_overwrite_a_committed_blocked_frame() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let payload = [0x6d; 12000];
        p.a.write(p.aid, &payload).unwrap();
        let mut backend = Backend {
            blocked: true,
            ..Default::default()
        };
        let mut output = [0; MTU];
        let mut pending = 0;
        let h = if v6 { IPV6_HEADER } else { IP_HEADER };
        transmit_frames(
            &mut p.a,
            p.time,
            &mut output,
            &mut pending,
            h,
            0,
            &mut backend,
        )
        .unwrap();
        let committed = output[..pending].to_vec();
        let path = if v6 { 1280 } else { 1006 };
        assert!(committed.len() > path);
        segment(&committed);
        input_frame(
            &mut p.a,
            p.time,
            &ptb(&committed, path as u32),
            p.local.ip(),
            false,
            0,
        )
        .unwrap();
        assert_eq!(
            p.a.path_mtu_info(p.aid).unwrap().unwrap().current_mtu,
            path as u32
        );
        let transport = p.a.transport_info(p.aid).unwrap();
        for _ in 0..3 {
            transmit_frames(
                &mut p.a,
                p.time,
                &mut output,
                &mut pending,
                h,
                0,
                &mut backend,
            )
            .unwrap();
            assert_eq!(&output[..pending], committed);
            assert_eq!(
                p.a.transport_info(p.aid).unwrap(),
                transport,
                "blocked polls cannot commit more TCP bytes"
            );
            assert!(backend.frames.is_empty());
        }
        backend.blocked = false;
        transmit_frames(
            &mut p.a,
            p.time,
            &mut output,
            &mut pending,
            h,
            0,
            &mut backend,
        )
        .unwrap();
        assert_eq!(pending, 0);
        assert_eq!(backend.frames[0], committed);
        assert_eq!(
            backend.frames.iter().filter(|f| **f == committed).count(),
            1
        );
        // The already committed oversized packet is dropped by the path; admit
        // subsequent fitting output. Real ACKs must recover the entire stream.
        for frame in &backend.frames[1..] {
            assert!(frame.len() <= path);
            segment(frame);
            input_frame(&mut p.b, p.time, frame, p.remote.ip(), false, 0).unwrap();
        }
        p.progress(path, &payload);
    }
}
