// Correlation semantics: exact evidence is the only positive evidence, lossy
// history (summaries, merged covers, discarded summaries) only denies.
use super::*;
use crate::ledger::Ledger;
use path::PathId;

const H: u64 = 400;

// Six owner records: the randomized model's maximum of concurrent owners
// (the stateless lane, three TCP flows and two datagram flows), so no model
// submission is refused for capacity.
fn limits(datagram_evidence: usize) -> LedgerLimits {
    LedgerLimits {
        owners: 6,
        history_per_owner: 3,
        segment_bytes: 1460,
        concurrent_attempts: 4,
        datagram_evidence,
        feedback_horizon: H,
    }
}

struct Fixture {
    link: LinkId,
    paths: [PathId; 2],
    ids: Vec<ConnectionId>,
}

// Real path incarnations (two DSCP classes) and connection generations
// minted by an Endpoint, including slot reuse.
fn fixture() -> Fixture {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let (mut host, mut endpoint, ingress) = managed(local, 1200, cfg.clone());
    let connect = |host: &mut Host, endpoint: &mut Endpoint, port: u16, dscp| {
        endpoint
            .connect_with_path_provider(
                0,
                local,
                SocketAddr::new(remote.ip(), port),
                options(&cfg, dscp),
                host,
            )
            .unwrap_or_else(|e| panic!("port {port}: {e:?}"))
    };
    let a = connect(&mut host, &mut endpoint, 8080, 0);
    let b = connect(&mut host, &mut endpoint, 8081, 46);
    let (pa, pb) = (
        host.binding(a).unwrap().snapshot,
        host.binding(b).unwrap().snapshot,
    );
    assert_ne!(pa.path(), pb.path());
    let mut ids = vec![a, b];
    for port in 8082..8106 {
        let id = *ids.last().unwrap();
        endpoint.abort(id).unwrap();
        endpoint.release(id).unwrap();
        host.collect(&endpoint).unwrap();
        while emit(&mut host, &mut endpoint, 0).is_some() {}
        host.collect(&endpoint).unwrap();
        ids.push(connect(&mut host, &mut endpoint, port, 0));
    }
    Fixture {
        link: ingress.link(),
        paths: [pa.path(), pb.path()],
        ids,
    }
}

fn v4(n: u8) -> IpAddr {
    IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, n))
}

fn evidence(
    f: &Fixture,
    owner: Owner,
    path: PathId,
    packet_len: u32,
    transport: Selector,
) -> Evidence {
    let (destination, protocol) = match transport {
        Selector::Udp { .. } | Selector::UdpFirstFragment { .. } | Selector::Fragment { .. } => {
            (v4(2), 17)
        }
        _ => (v4(2), 6),
    };
    Evidence {
        link: f.link,
        path,
        owner,
        source: v4(1),
        destination,
        dscp: 0,
        header_len: 20,
        packet_len,
        protocol,
        transport,
    }
}

fn key(e: &Evidence) -> QuoteKey {
    QuoteKey {
        source: e.source,
        destination: e.destination,
        header_len: e.header_len,
        packet_len: e.packet_len,
        protocol: e.protocol,
        transport: match e.transport {
            Selector::Tcp {
                source_port,
                destination_port,
                start,
                ..
            } => QuotedSelector::Tcp {
                source_port,
                destination_port,
                sequence: start,
            },
            Selector::Udp {
                source_port,
                destination_port,
                length,
                checksum,
            } => QuotedSelector::Udp {
                source_port,
                destination_port,
                length,
                checksum,
            },
            Selector::UdpFirstFragment {
                source_port,
                destination_port,
                length,
                checksum,
            } => QuotedSelector::UdpFirstFragment {
                source_port,
                destination_port,
                length,
                checksum,
            },
            // A router's quote of a later fragment: its position, MF and the
            // leading data octets, never ports.
            Selector::Fragment {
                offset,
                more,
                prefix,
                ..
            } => QuotedSelector::Fragment {
                offset,
                more,
                prefix,
            },
            Selector::Other => QuotedSelector::Other,
        },
    }
}

fn commit(ledger: &mut Ledger, e: Evidence, now: u64) -> bool {
    let Ok(index) = ledger.admit(e.owner) else {
        return false;
    };
    let Ok(ticket) = ledger.reserve_group(index, &[e]) else {
        return false;
    };
    assert_eq!(ledger.seal(ticket, now, false), 1);
    true
}

fn datagram(f: &Fixture, generation: u64, path: PathId, length: u16, checksum: u16) -> Evidence {
    evidence(
        f,
        Owner::Datagram {
            flow: 0,
            generation,
        },
        path,
        20 + u32::from(length),
        Selector::Udp {
            source_port: 5000,
            destination_port: 7,
            length,
            checksum,
        },
    )
}

// An exact match agreeing with lossy history keeps path-level action but
// loses owner attribution; lossy history alone is no evidence at all, even
// when its widened cover admits a never-sent length and checksum.
#[test]
fn exact_match_with_agreeing_summary_allows_path_action_only() {
    let f = fixture();
    let mut ledger = Ledger::new(limits(0)).unwrap();
    let p = f.paths[0];
    assert!(commit(&mut ledger, datagram(&f, 1, p, 1308, 0x1111), 1));
    assert!(commit(&mut ledger, datagram(&f, 1, p, 1408, 0x2222), 2));
    let index = ledger.owner_index(datagram(&f, 1, p, 0, 0).owner).unwrap();
    assert!(ledger.release_owner(index, 3));
    let forged = key(&datagram(&f, 0, p, 1358, 0x1234));
    let lossy = ledger.correlate(4, &forged);
    assert_eq!(
        (lossy.matches, lossy.summarized, lossy.path, lossy.owner),
        (0, true, None, None),
        "a widened summary admits the forged quote but proves nothing"
    );
    let next = datagram(&f, 2, p, 1408, 0x2222);
    assert!(commit(&mut ledger, next, 5));
    let both = ledger.correlate(6, &key(&next));
    assert_eq!((both.matches, both.summarized), (1, true));
    assert_eq!(both.path, Some(p), "path-level action allowed");
    assert_eq!(both.owner, None, "owner advice denied");
    std::println!(
        "summary only: matches={} path={:?}; exact+agreeing summary: matches={} path={:?} owner={:?}",
        lossy.matches,
        lossy.path,
        both.matches,
        both.path.is_some(),
        both.owner
    );
}

#[test]
fn exact_match_with_summary_on_another_path_allows_no_path_action() {
    let f = fixture();
    let mut ledger = Ledger::new(limits(0)).unwrap();
    let old = datagram(&f, 1, f.paths[0], 1408, 0x2222);
    assert!(commit(&mut ledger, old, 1));
    let index = ledger.owner_index(old.owner).unwrap();
    assert!(ledger.release_owner(index, 2));
    let next = datagram(&f, 2, f.paths[1], 1408, 0x2222);
    assert!(commit(&mut ledger, next, 3));
    let c = ledger.correlate(4, &key(&next));
    assert_eq!(
        (c.matches, c.summarized, c.path, c.owner),
        (1, true, None, None)
    );
    // The zero-MTU alternative readings combine the same way: hits under
    // the other reading withdraw this reading's path agreement.
    let alone = commit(&mut ledger, datagram(&f, 2, f.paths[1], 1000, 0x3333), 5);
    assert!(alone);
    let fresh = ledger.correlate(6, &key(&datagram(&f, 2, f.paths[1], 1000, 0x3333)));
    assert_eq!(fresh.path, Some(f.paths[1]));
    let mut alias = key(&datagram(&f, 2, f.paths[1], 1000, 0x3333));
    alias.packet_len = key(&old).packet_len;
    alias.transport = key(&old).transport;
    let combined = fresh.either(ledger.correlate(6, &alias));
    assert_eq!((combined.path, combined.owner), (None, None));
    std::println!(
        "exact on path B + summary on path A: matches={} path={:?}",
        c.matches,
        c.path
    );
}

// Deterministic, dependency-free PRNG (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len() as u64) as usize]
    }
}

// Reference model: every physical submission, with its owner generation,
// path incarnation, selector and commit time. Nothing is ever evicted.
#[derive(Clone, Copy)]
struct Sent {
    e: Evidence,
    at: u64,
    retired: bool,
}

struct TcpFlow {
    id: Option<ConnectionId>,
    port: u16,
    remote: u8,
    nxt: u32,
    // Unretired spans; retransmissions repeat a span exactly. ACKs land on
    // span boundaries: TCP itself refuses quotes below SND.UNA, so a
    // partially acknowledged span is never feedback.
    spans: Vec<(u32, u32)>,
    path: usize,
}

struct Model {
    sent: Vec<Sent>,
    open: Vec<Owner>,
}

impl Model {
    // Whether a submission could still be the subject of a quote: outstanding
    // TCP data until delivery while its generation lives; everything else
    // (and closed generations' data) until the feedback horizon.
    fn valid(&self, s: &Sent, now: u64) -> bool {
        let data = matches!(
            (s.e.owner, s.e.transport),
            (Owner::Tcp(_), Selector::Tcp { start, end, .. }) if start != end
        );
        !s.retired && (s.at + H > now || data && self.open.contains(&s.e.owner))
    }
    // Exact matches no longer valid by time alone (not delivered).
    fn expired(&self, q: &QuoteKey, now: u64) -> bool {
        self.sent
            .iter()
            .any(|s| !s.retired && !self.valid(s, now) && exact(&s.e, q))
    }
    fn matching(&self, q: &QuoteKey, now: u64) -> Vec<Sent> {
        self.sent
            .iter()
            .filter(|s| self.valid(s, now) && exact(&s.e, q))
            .copied()
            .collect()
    }
}

// The ledger's exact-match rule, restated: every selector field, while
// TTL/hop limit, ECN, DSCP and IPv4 identification are never quoted here.
fn exact(e: &Evidence, q: &QuoteKey) -> bool {
    (
        e.source,
        e.destination,
        e.header_len,
        e.packet_len,
        e.protocol,
    ) == (
        q.source,
        q.destination,
        q.header_len,
        q.packet_len,
        q.protocol,
    ) && match (e.transport, q.transport) {
        (
            Selector::Tcp {
                source_port: a,
                destination_port: b,
                start,
                ..
            },
            QuotedSelector::Tcp {
                source_port: c,
                destination_port: d,
                sequence,
            },
        ) => (a, b, start) == (c, d, sequence),
        (
            Selector::Udp {
                source_port: a,
                destination_port: b,
                length: l,
                checksum: x,
            },
            QuotedSelector::Udp {
                source_port: c,
                destination_port: d,
                length: m,
                checksum: y,
            },
        ) => (a, b, l, x) == (c, d, m, y),
        (
            Selector::UdpFirstFragment {
                source_port: a,
                destination_port: b,
                length: l,
                checksum: x,
            },
            QuotedSelector::UdpFirstFragment {
                source_port: c,
                destination_port: d,
                length: m,
                checksum: y,
            },
        ) => (a, b, l, x) == (c, d, m, y),
        // Portless: position, MF and every recorded data octet present in
        // the quote; the flow's logical ports never take part.
        (
            Selector::Fragment {
                offset: a,
                more: b,
                prefix: recorded,
                ..
            },
            QuotedSelector::Fragment {
                offset: c,
                more: d,
                prefix: quoted,
            },
        ) => {
            (a, b) == (c, d)
                && quoted.as_slice().len() >= recorded.as_slice().len()
                && quoted.as_slice()[..recorded.as_slice().len()] == *recorded.as_slice()
        }
        (Selector::Other, QuotedSelector::Other) => true,
        _ => false,
    }
}

fn mutate(rng: &mut Rng, q: &mut QuoteKey) {
    match rng.below(8) {
        0 => q.packet_len = q.packet_len.wrapping_add(rng.pick(&[1, u32::MAX, 100, 8])),
        1 => q.header_len += 4,
        2 => {
            if let QuotedSelector::Udp {
                checksum, length, ..
            }
            | QuotedSelector::UdpFirstFragment {
                checksum, length, ..
            } = &mut q.transport
            {
                if rng.below(2) == 0 {
                    *checksum ^= 3;
                } else {
                    *length = length.wrapping_add(8);
                    q.packet_len += 8;
                }
            }
        }
        3 => match &mut q.transport {
            QuotedSelector::Tcp { source_port, .. }
            | QuotedSelector::Udp { source_port, .. }
            | QuotedSelector::UdpFirstFragment { source_port, .. } => *source_port ^= 1,
            QuotedSelector::Fragment { .. } | QuotedSelector::Other => {}
        },
        4 => {
            if let QuotedSelector::Tcp { sequence, .. } = &mut q.transport {
                *sequence = sequence.wrapping_add(rng.pick(&[1, 100, 200, u32::MAX]));
            }
        }
        5 => q.destination = v4(rng.pick(&[2, 3, 4])),
        6 => q.source = v4(9),
        // A later fragment's own evidence: another offset, the other MF, a
        // changed data octet, or a quote missing a recorded octet.
        _ => {
            if let QuotedSelector::Fragment {
                offset,
                more,
                prefix,
            } = &mut q.transport
            {
                let mut data = prefix.as_slice().to_vec();
                match rng.below(4) {
                    0 => *offset = offset.wrapping_add(rng.pick(&[8, 1000])),
                    1 => *more = !*more,
                    2 => {
                        let at = rng.below(data.len() as u64) as usize;
                        data[at] ^= 0x40
                    }
                    _ => {
                        data.pop();
                    }
                }
                *prefix = FragmentPrefix::new(&data);
            }
        }
    }
}

// Checks the three invariants for one (possibly two-reading) quote.
fn check(model: &Model, c: Correlation, readings: &[QuoteKey], now: u64) -> bool {
    let mut matching = Vec::new();
    for q in readings {
        matching.extend(model.matching(q, now));
    }
    if c.path.is_some() || c.owner.is_some() {
        assert!(
            !matching.is_empty(),
            "(1) action without exact evidence: {c:?}"
        );
    }
    if let Some(path) = c.path {
        assert!(
            matching.iter().all(|s| s.e.path == path),
            "(2) path action while a matching submission used another path: {c:?}"
        );
    }
    if let Some(record) = c.owner {
        assert!(
            matching.iter().all(|s| s.e.owner == record.evidence.owner),
            "(3) owner advice with another generation's submission matching: {c:?}"
        );
        match record.evidence.transport {
            Selector::Tcp { start, end, .. } => assert!(
                matching.iter().all(|s| matches!(s.e.transport,
                    Selector::Tcp { start: a, end: b, .. } if (a, b) == (start, end))),
                "(3) owner advice over two TCP ranges: {c:?}"
            ),
            _ => assert_eq!(
                matching.len(),
                1,
                "(3) owner advice over two datagrams: {c:?}"
            ),
        }
    }
    c.path.is_some() || c.owner.is_some()
}

#[test]
fn randomized_correlation_never_acts_beyond_the_reference_model() {
    let f = fixture();
    let seeds = 48u64;
    let steps = 500;
    let (mut quotes, mut actions, mut lossy, mut denied) = (0, 0, 0, 0);
    let (mut discards, mut signatures, mut shadowed, mut expired, mut both_readings) =
        (0, 0, 0, 0, 0);
    // Fragment coverage: sealed fragments, quotes of later fragments, their
    // owner advice, path-only actions, cross-flow aliases, portless lossy
    // hits, exact signatures and discard shadows, rejected near misses, and
    // owner advice for quoted first fragments.
    let mut fragments = 0;
    let (mut fragment_quotes, mut fragment_owner, mut fragment_path_only, mut cross_flow) =
        (0, 0, 0, 0);
    let (mut portless_lossy, mut fragment_signatures, mut fragment_shadowed) = (0, 0, 0);
    let (mut fragment_rejected, mut first_owner) = (0, 0);
    for seed in 1..=seeds {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        // Two exact signatures: datagram evictions overflow into summaries.
        let mut ledger = Ledger::new(limits(2)).unwrap();
        let mut model = Model {
            sent: Vec::new(),
            open: vec![Owner::Stateless],
        };
        let mut tcp: Vec<TcpFlow> = (0..3)
            .map(|i| TcpFlow {
                id: None,
                port: 1000 + i,
                remote: 2 + (i % 2) as u8,
                nxt: 0,
                spans: Vec::new(),
                path: 0,
            })
            .collect();
        let mut minted = 0;
        let mut udp: [(Option<u64>, usize); 2] = [(None, 0); 2];
        let mut generation = 0;
        let mut now = 1;
        for _ in 0..steps {
            now += rng.below(4);
            let op = rng.below(100);
            let record = |ledger: &mut Ledger, model: &mut Model, e: Evidence| {
                // Owner records cover the model's concurrency and every
                // commit seals at once: nothing is refused for capacity.
                assert!(commit(ledger, e, now), "capacity refused {e:?}");
                model.sent.push(Sent {
                    e,
                    at: now,
                    retired: false,
                });
            };
            if op < 30 {
                let t = &mut tcp[rng.below(3) as usize];
                let Some(id) = t.id else {
                    if minted == f.ids.len() {
                        continue;
                    }
                    t.id = Some(f.ids[minted]);
                    minted += 1;
                    // Reused generations sometimes reuse an ISS, and one
                    // starts just below the wrap.
                    t.nxt = rng.pick(&[0, 1_000_000, u32::MAX - 150]);
                    t.spans.clear();
                    t.path = rng.below(2) as usize;
                    model.open.push(Owner::Tcp(t.id.unwrap()));
                    continue;
                };
                if rng.below(10) == 0 {
                    t.path ^= 1;
                }
                let segment = |start: u32, end: u32| Selector::Tcp {
                    source_port: t.port,
                    destination_port: 80,
                    start,
                    end,
                };
                let path = f.paths[t.path];
                match rng.below(20) {
                    0..=9 => {
                        let len = rng.pick(&[100u32, 120, 200]);
                        let span = (t.nxt, t.nxt.wrapping_add(len));
                        let mut e =
                            evidence(&f, Owner::Tcp(id), path, 40 + len, segment(span.0, span.1));
                        e.destination = v4(t.remote);
                        record(&mut ledger, &mut model, e);
                        t.spans.push(span);
                        t.nxt = span.1;
                    }
                    10..=13 if !t.spans.is_empty() => {
                        let mut span = t.spans[rng.below(t.spans.len() as u64) as usize];
                        // Sometimes repacketized after a decrease: a shorter
                        // segment from the same sequence number, whose
                        // packet length is the RFC 1191 legacy reading of
                        // the original's quote.
                        if rng.below(2) == 0 {
                            span.1 = span.1.wrapping_sub(20);
                        }
                        let len = span.1.wrapping_sub(span.0);
                        let mut e =
                            evidence(&f, Owner::Tcp(id), path, 40 + len, segment(span.0, span.1));
                        e.destination = v4(t.remote);
                        record(&mut ledger, &mut model, e);
                    }
                    14..=16 => {
                        let mut e = evidence(&f, Owner::Tcp(id), path, 40, segment(t.nxt, t.nxt));
                        e.destination = v4(t.remote);
                        record(&mut ledger, &mut model, e);
                    }
                    17..=18 if !t.spans.is_empty() => {
                        let una = t.spans[rng.below(t.spans.len() as u64) as usize].1;
                        let delivered = |(_, end): (u32, u32)| una.wrapping_sub(end) < 1 << 31;
                        t.spans.retain(|s| !delivered(*s));
                        for s in &mut model.sent {
                            if let (Owner::Tcp(o), Selector::Tcp { start, end, .. }) =
                                (s.e.owner, s.e.transport)
                                && o == id
                                && start != end
                                && delivered((start, end))
                            {
                                s.retired = true;
                            }
                        }
                        ledger.retire_tcp(id, una, |_| {});
                    }
                    _ => {
                        if let Some(index) = ledger.owner_index(Owner::Tcp(id)) {
                            assert!(ledger.release_owner(index, now));
                        }
                        model.open.retain(|o| *o != Owner::Tcp(id));
                        t.id = None;
                    }
                }
            } else if op < 50 {
                let flow = rng.below(2) as usize;
                let Some(g) = udp[flow].0 else {
                    generation += 1;
                    udp[flow] = (Some(generation), rng.below(2) as usize);
                    model.open.push(Owner::Datagram { flow, generation });
                    continue;
                };
                let owner = Owner::Datagram {
                    flow,
                    generation: g,
                };
                if rng.below(6) == 0 {
                    if let Some(index) = ledger.owner_index(owner) {
                        assert!(ledger.release_owner(index, now));
                    }
                    model.open.retain(|o| *o != owner);
                    udp[flow].0 = None;
                    continue;
                }
                if rng.below(8) == 0 {
                    udp[flow].1 ^= 1;
                }
                if rng.below(3) == 0 {
                    // A source-fragmented datagram cut to 1000 data octets
                    // (1020-octet packets): fragment zero under the flow's UDP
                    // selector, later fragments portless with their leading
                    // data octets (four for a 2004-octet datagram's last
                    // one). Both flows send the same fills to the same
                    // remotes, so their later fragments are byte-identical
                    // cross-flow aliases. A transaction may stop after any
                    // fragment; only the submitted prefix is sealed.
                    let length = rng.pick(&[2004u16, 2400, 2408]);
                    let fill = rng.pick(&[0u8, 1]);
                    let checksum = rng.pick(&[1, 2]);
                    let destination = v4(rng.pick(&[2, 3, 4, 5, 6, 7]));
                    let sealed = 1 + rng.below(3) as usize;
                    let pieces = [
                        (0u16, 1000u32, true),
                        (1000, 1000, true),
                        (2000, u32::from(length) - 2000, false),
                    ];
                    for &(offset, len, more) in &pieces[..sealed] {
                        let ports = (5000 + flow as u16, 7);
                        let transport = if offset == 0 {
                            Selector::UdpFirstFragment {
                                source_port: ports.0,
                                destination_port: ports.1,
                                length,
                                checksum,
                            }
                        } else {
                            Selector::Fragment {
                                offset,
                                more,
                                prefix: FragmentPrefix::new(&vec![fill; len as usize]),
                                logical_ports: ports,
                            }
                        };
                        let mut e = evidence(&f, owner, f.paths[udp[flow].1], 20 + len, transport);
                        e.destination = destination;
                        record(&mut ledger, &mut model, e);
                        fragments += 1;
                    }
                    continue;
                }
                let length = rng.pick(&[100u16, 108]);
                let mut e = evidence(
                    &f,
                    owner,
                    f.paths[udp[flow].1],
                    20 + u32::from(length),
                    Selector::Udp {
                        source_port: 5000 + flow as u16,
                        destination_port: 7,
                        length,
                        checksum: rng.pick(&[1, 2]),
                    },
                );
                // Unconnected: any of six remotes, more keys than summary
                // slots, so `fold` discards.
                e.destination = v4(rng.pick(&[2, 3, 4, 5, 6, 7]));
                record(&mut ledger, &mut model, e);
            } else if op < 58 {
                // Stateless replies (RST points, cookie SYN-ACKs) on tuples no
                // connection uses: the ledger treats a byte-identical
                // stateless/connection segment as an RFC 6528 chance
                // collision, outside this model.
                let start = rng.pick(&[7u32, 9]);
                let (end, len) = if rng.below(2) == 0 {
                    (start, 40)
                } else {
                    (start + 1, 44)
                };
                let mut e = evidence(
                    &f,
                    Owner::Stateless,
                    f.paths[rng.below(2) as usize],
                    len,
                    Selector::Tcp {
                        source_port: 3000,
                        destination_port: 9000 + rng.below(2) as u16,
                        start,
                        end,
                    },
                );
                e.destination = v4(rng.pick(&[2, 3]));
                record(&mut ledger, &mut model, e);
            } else if op < 62 {
                ledger.expire(now);
            } else {
                if model.sent.is_empty() {
                    continue;
                }
                let base = model.sent[rng.below(model.sent.len() as u64) as usize];
                let mut q = key(&base.e);
                let mutated = rng.below(2) == 0;
                if mutated {
                    mutate(&mut rng, &mut q);
                }
                let c = ledger.correlate(now, &q);
                let (hits, shadow) = ledger.evicted_hits(now, &q);
                if let QuotedSelector::Fragment { .. } = q.transport {
                    let mut owners: Vec<Owner> =
                        model.matching(&q, now).iter().map(|s| s.e.owner).collect();
                    owners.sort_by_key(|o| match o {
                        Owner::Datagram { flow, generation } => (*flow, *generation),
                        _ => (usize::MAX, 0),
                    });
                    owners.dedup();
                    fragment_quotes += 1;
                    cross_flow += usize::from(owners.len() > 1);
                    fragment_owner += usize::from(c.owner.is_some());
                    fragment_path_only += usize::from(c.path.is_some() && c.owner.is_none());
                    portless_lossy += usize::from(c.summarized);
                    fragment_signatures += usize::from(hits != 0);
                    fragment_shadowed += usize::from(shadow);
                    fragment_rejected += usize::from(mutated && c.matches == 0);
                }
                if let QuotedSelector::UdpFirstFragment { .. } = q.transport {
                    first_owner += usize::from(c.owner.is_some());
                }
                signatures += usize::from(hits != 0);
                shadowed += usize::from(shadow);
                expired += usize::from(model.expired(&q, now));
                lossy += usize::from(c.summarized);
                denied += usize::from(c.matches != 0 && c.owner.is_none());
                actions += usize::from(check(&model, c, &[q], now));
                quotes += 1;
                // RFC 1191's legacy reading of the same quote.
                if q.packet_len >= 2 * q.header_len + 20 && rng.below(3) == 0 {
                    let shorter = QuoteKey {
                        packet_len: q.packet_len - q.header_len,
                        ..q
                    };
                    let other = ledger.correlate(now, &shorter);
                    let hit = |c: &Correlation| c.matches != 0 || c.summarized;
                    both_readings += usize::from(hit(&c) && hit(&other));
                    let both = c.either(other);
                    actions += usize::from(check(&model, both, &[q, shorter], now));
                    quotes += 1;
                }
            }
        }
        discards += ledger.discards();
    }
    std::println!(
        "CORRELATION_INVARIANT seeds={seeds} steps={steps} quotes_checked={quotes} \
         actions={actions} lossy_hits={lossy} exact_but_owner_denied={denied} \
         summary_discards={discards} discard_shadowed={shadowed} \
         signature_hits={signatures} expired_matches={expired} \
         either_hits_both={both_readings}"
    );
    // Every lossy mechanism was exercised, not only same-owner eviction.
    for (name, count) in [
        ("actions", actions),
        ("lossy hits", lossy),
        ("owner denials", denied),
        ("summary discards", discards),
        ("discard-shadowed quotes", shadowed),
        ("exact signature hits", signatures),
        ("expired-match quotes", expired),
        ("either hits under both readings", both_readings),
    ] {
        assert!(count > 0, "no {name}");
    }
    std::println!(
        "FRAGMENT_CORRELATION fragments_sealed={fragments} fragment_quotes={fragment_quotes} \
         fragment_owner_advice={fragment_owner} fragment_path_only={fragment_path_only} \
         cross_flow_aliases={cross_flow} portless_lossy_hits={portless_lossy} \
         fragment_signature_hits={fragment_signatures} \
         fragment_discard_shadowed={fragment_shadowed} \
         fragment_near_misses_rejected={fragment_rejected} first_fragment_owner_advice={first_owner}"
    );
    for (name, count) in [
        ("sealed fragments", fragments),
        ("later-fragment quotes", fragment_quotes),
        ("later-fragment owner advice", fragment_owner),
        ("later-fragment path-only actions", fragment_path_only),
        ("cross-flow fragment aliases", cross_flow),
        ("portless lossy hits", portless_lossy),
        ("portless exact signature hits", fragment_signatures),
        ("portless discard shadows", fragment_shadowed),
        ("rejected fragment near misses", fragment_rejected),
        ("first-fragment owner advice", first_owner),
    ] {
        assert!(count > 0, "no {name}");
    }
}

// The quote key of a quoted frame prefix (IP header plus eight UDP bytes),
// read the way the ledger compares it: TTL/hop limit, DSCP/ECN and IPv4
// identification are not part of it.
fn quoted_key(frame: &[u8]) -> QuoteKey {
    let h = super::dispatch::header(frame);
    let word = |at: usize| u16::from_be_bytes([frame[at], frame[at + 1]]);
    let (source, destination, packet_len, protocol): (IpAddr, IpAddr, u32, u8) = if frame[0] >> 4
        == 6
    {
        let address = |at: usize| IpAddr::from(<[u8; 16]>::try_from(&frame[at..at + 16]).unwrap());
        (address(8), address(24), 40 + u32::from(word(4)), frame[6])
    } else {
        let address = |at: usize| IpAddr::from(<[u8; 4]>::try_from(&frame[at..at + 4]).unwrap());
        (address(12), address(16), u32::from(word(2)), frame[9])
    };
    QuoteKey {
        source,
        destination,
        header_len: h as u32,
        packet_len,
        protocol,
        transport: QuotedSelector::Udp {
            source_port: word(h),
            destination_port: word(h + 2),
            length: word(h + 4),
            checksum: word(h + 6),
        },
    }
}

// The dispatcher's own consumers against the same reference model: real
// Host UDP flows submit through `udp_send` (unconnected, to three remotes,
// closed and reopened as new generations), and every quote, an exact copy
// of a sent frame or a near miss (R1's never-sent length and checksum
// included), enters `Host::input_icmp` as a router-originated PTB (zero-MTU
// legacy reports included) or unreachable. The ledger keeps three entries
// and one exact evicted signature per flow, so summaries and signatures
// carry most of the history.
#[test]
fn randomized_host_dispatch_never_acts_beyond_the_reference_model() {
    let cfg = config(1);
    let seeds = 8u64;
    let steps = 300;
    let mut quotes = 0;
    let (mut owner_advice, mut publications, mut denied, mut signatures, mut forged) =
        (0, 0, 0, 0, 0);
    for v6 in [false, true] {
        for seed in 1..=seeds {
            let mut rng = Rng((seed + 100 * u64::from(v6)).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let (local, _) = addresses(v6);
            let udp = UdpLimits {
                flows: 2,
                receive_datagrams: 1,
                max_payload: 1500,
                events: 2,
                evicted_signatures: 1,
                probe_receipts: 2,
            };
            let mut side = managed_limited(
                local,
                3000 + u128::from(seed) + 100 * u128::from(v6),
                cfg.clone(),
                false,
                None,
                None,
                |paths, limits| {
                    let (paths, mut limits) = managed_udp_limits(paths, limits, udp).unwrap();
                    limits.ledger.history_per_owner = 3;
                    (paths, limits, 1)
                },
            );
            let horizon = side.0.ledger.limits().feedback_horizon;
            let remote = |n: u8| -> IpAddr {
                if v6 {
                    IpAddr::V6(core::net::Ipv6Addr::new(
                        0x2001,
                        0xdb8,
                        0,
                        0,
                        0,
                        0,
                        0,
                        n.into(),
                    ))
                } else {
                    v4(n)
                }
            };
            // Model: quoted frame prefix, ledger evidence, commit time.
            let mut sent: Vec<(Vec<u8>, Evidence, u64)> = Vec::new();
            let mut flows: [Option<UdpFlowId>; 2] = [None; 2];
            let mut now = 1;
            for _ in 0..steps {
                now += rng.below(4) * horizon / 100;
                let op = rng.below(100);
                if op < 50 {
                    let flow = rng.below(2) as usize;
                    let Some(id) = flows[flow] else {
                        let bind = SocketAddr::new(local.ip(), 5000 + flow as u16);
                        let options = UdpOptions {
                            dscp: 0,
                            hop_limit: 64,
                        };
                        flows[flow] = Some(side.0.udp_open(&side.1, bind, None, options).unwrap());
                        continue;
                    };
                    if rng.below(8) == 0 {
                        side.0.udp_close(id).unwrap();
                        flows[flow] = None;
                        continue;
                    }
                    let to = SocketAddr::new(remote(rng.pick(&[2, 3, 4])), 7);
                    let payload = vec![rng.below(2) as u8; rng.pick(&[100, 108, 900, 1300, 1400])];
                    let mut packet = vec![0; 1500];
                    let mut frame = Vec::new();
                    let outcome = rng.pick(&[BackendOutcome::Submitted, BackendOutcome::Unknown]);
                    let result = side.0.udp_send(
                        &side.1,
                        now,
                        id,
                        Some(to),
                        &payload,
                        &mut packet,
                        |_, bytes| {
                            frame = bytes.to_vec();
                            outcome
                        },
                    );
                    match result {
                        Ok(_) => {
                            frame.truncate(super::dispatch::header(&frame) + 8);
                            let key = quoted_key(&frame);
                            let e = side
                                .0
                                .ledger
                                .records()
                                .find(|r| r.committed_at == now && exact(&r.evidence, &key))
                                .expect("sealed evidence of the submission")
                                .evidence;
                            sent.push((frame, e, now));
                        }
                        Err(UdpSendError::TooBig { .. }) => {}
                        Err(e) => panic!("{e:?}"),
                    }
                } else {
                    if sent.is_empty() {
                        continue;
                    }
                    let (base, _, _) = &sent[rng.below(sent.len() as u64) as usize];
                    let mut quoted = base.clone();
                    let h = super::dispatch::header(&quoted);
                    let length_field = if v6 { 4 } else { 2 };
                    let bump = |f: &mut Vec<u8>, at: usize, by: u16| {
                        let v = u16::from_be_bytes([f[at], f[at + 1]]).wrapping_add(by);
                        f[at..at + 2].copy_from_slice(&v.to_be_bytes());
                    };
                    let mut r1 = false;
                    if rng.below(2) == 0 {
                        match rng.below(6) {
                            0 => bump(&mut quoted, length_field, 8),
                            1 => {
                                // R1: a never-sent UDP/IP length and checksum.
                                bump(&mut quoted, length_field, 50);
                                bump(&mut quoted, h + 4, 50);
                                quoted[h + 6..h + 8].copy_from_slice(&0x1234u16.to_be_bytes());
                                r1 = true;
                            }
                            2 => quoted[h + 7] ^= 3,
                            3 => quoted[h + 1] ^= 1,
                            4 => {
                                let at = if v6 { 39 } else { 19 };
                                quoted[at] = rng.pick(&[2, 3, 4]);
                            }
                            // Ignored fields: TTL/hop limit, DSCP/ECN, IPv4 ID.
                            _ => {
                                quoted[if v6 { 7 } else { 8 }] ^= 0x10;
                                quoted[1] ^= 0x05;
                                if !v6 {
                                    quoted[4] ^= 0x5a;
                                }
                            }
                        }
                    }
                    super::dispatch::seal_ipv4(&mut quoted);
                    let key = quoted_key(&quoted);
                    let (report, mut readings) = match rng.below(4) {
                        0 => (
                            super::dispatch::icmp(&quoted, if v6 { (1, 3) } else { (3, 1) }, 0),
                            vec![key],
                        ),
                        _ => {
                            let mtu = if v6 {
                                rng.pick(&[1280, 1300])
                            } else {
                                rng.pick(&[0, 1006, 1200])
                            };
                            (super::dispatch::ptb(&quoted, mtu), vec![key])
                        }
                    };
                    // RFC 1191's legacy reading of a zero-MTU IPv4 report.
                    let zero = !v6 && report[20] == 3 && report[20 + 6..20 + 8] == [0, 0];
                    if zero && key.packet_len >= 2 * key.header_len + 20 {
                        readings.push(QuoteKey {
                            packet_len: key.packet_len - key.header_len,
                            ..key
                        });
                    }
                    let matching: Vec<Evidence> = sent
                        .iter()
                        .filter(|(_, e, at)| {
                            at + horizon > now && readings.iter().any(|q| exact(e, q))
                        })
                        .map(|(_, e, _)| *e)
                        .collect();
                    signatures += usize::from(side.0.ledger.evicted_hits(now, &key).0 != 0);
                    quotes += 1;
                    let context = side.2;
                    match side.0.input_icmp(&mut side.1, context, now, &report, None) {
                        Ok(IcmpDispatch::Completed(IcmpOutcome::Advice {
                            owner,
                            published,
                            ..
                        })) => {
                            assert!(!matching.is_empty(), "(1) advice without evidence");
                            if published.is_some() {
                                publications += 1;
                                assert!(
                                    matching.iter().all(|e| e.path == matching[0].path),
                                    "(2) publication across path incarnations"
                                );
                            }
                            if let Some(owner) = owner {
                                owner_advice += 1;
                                assert_eq!(matching.len(), 1, "(3) advice over two datagrams");
                                assert_eq!(matching[0].owner, owner, "(3) wrong generation");
                            }
                        }
                        Ok(IcmpDispatch::Completed(IcmpOutcome::Discarded(reason))) => {
                            denied += usize::from(
                                !matching.is_empty() && reason == IcmpDiscard::Ambiguous,
                            );
                            forged += usize::from(r1 && matching.is_empty());
                        }
                        Err(_) => {}
                        other => panic!("{other:?}"),
                    }
                }
            }
        }
    }
    std::println!(
        "HOST_DISPATCH_INVARIANT families=2 seeds={seeds} steps={steps} quotes_checked={quotes} \
         owner_advice={owner_advice} publications={publications} ambiguous_denied={denied} \
         signature_hits={signatures} r1_forged_discarded={forged}"
    );
    for (name, count) in [
        ("owner advice", owner_advice),
        ("publications", publications),
        ("ambiguous denials", denied),
        ("signature hits", signatures),
        ("discarded R1 forgeries", forged),
    ] {
        assert!(count > 0, "no {name}");
    }
}
