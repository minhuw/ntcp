// The reassembly engine and the ICMP errors it originates, driven with
// engine-level inputs: targeted cases for every rule, then a seeded
// reference model with asserted coverage counters.
use super::*;
use crate::icmp_error::{ErrorLimiter, ReassemblyError, originate};
use crate::reassembly::{Arrival, Discard, Input, Piece, Reassembly, ecn_result};
use std::{collections::BTreeMap, vec};

const SECOND: u64 = 1_000_000;
const V4_SOURCE: [u8; 4] = [192, 0, 2, 1];
const V4_LOCAL: [u8; 4] = [192, 0, 2, 2];

fn v6_source() -> [u8; 16] {
    "2001:db8::1"
        .parse::<core::net::Ipv6Addr>()
        .unwrap()
        .octets()
}
fn v6_local() -> [u8; 16] {
    "2001:db8::2"
        .parse::<core::net::Ipv6Addr>()
        .unwrap()
        .octets()
}

struct Fixture {
    paths: PathService,
    link: LinkId,
    local4: path::SourceId,
    local6: path::SourceId,
}
fn fixture() -> Fixture {
    let mut paths = PathService::new(
        ContextId::new(7),
        path::Limits {
            links: 2,
            sources: 4,
            source_owners: 4,
            routes: 1,
            paths: 1,
            clients: 1,
        },
    )
    .unwrap();
    let link = paths.register_link(InterfaceKey(1), 1500).unwrap();
    let local = |paths: &mut PathService, a: IpAddr| {
        paths
            .register_source(ScopedAddress::new(a, None).unwrap(), link)
            .unwrap()
    };
    let local4 = local(&mut paths, IpAddr::from(V4_LOCAL));
    let local6 = local(&mut paths, IpAddr::from(v6_local()));
    Fixture {
        paths,
        link,
        local4,
        local6,
    }
}
impl Fixture {
    fn arrival(&self, v6: bool) -> Arrival {
        Arrival {
            link: self.link,
            local: if v6 { self.local6 } else { self.local4 },
            link_multicast: false,
        }
    }
}

fn limits() -> ReassemblyLimits {
    ReassemblyLimits {
        assemblies: 4,
        fragments: 200,
        buffered_bytes: 8192,
        ipv4_datagram: 4096,
        ipv6_datagram: 4096,
        ipv4_timeout_seconds: 60,
    }
}

// One fragment of a datagram from the test peer to this host. IPv4
// carries `options` in its header; protocol 17 unless stated.
#[derive(Clone, Copy)]
struct Frag<'a> {
    v6: bool,
    id: u32,
    protocol: u8,
    offset: u32,
    more: bool,
    ecn: u8,
    options: &'a [u8],
    data: &'a [u8],
}
fn frag<'a>(v6: bool, id: u32, offset: u32, more: bool, data: &'a [u8]) -> Frag<'a> {
    Frag {
        v6,
        id,
        protocol: 17,
        offset,
        more,
        ecn: 0,
        options: &[],
        data,
    }
}
impl Frag<'_> {
    fn encode(&self) -> Vec<u8> {
        if self.v6 {
            let mut b = vec![0; 48 + self.data.len()];
            b[0] = 0x60 | (10 >> 2);
            b[1] = ((10 & 3) << 6) | (self.ecn << 4);
            b[4..6].copy_from_slice(&((8 + self.data.len()) as u16).to_be_bytes());
            b[6] = 44;
            b[7] = 64;
            b[8..24].copy_from_slice(&v6_source());
            b[24..40].copy_from_slice(&v6_local());
            b[40] = self.protocol;
            let field = self.offset as u16 | u16::from(self.more);
            b[42..44].copy_from_slice(&field.to_be_bytes());
            b[44..48].copy_from_slice(&self.id.to_be_bytes());
            b[48..].copy_from_slice(self.data);
            b
        } else {
            let header = 20 + self.options.len();
            assert_eq!(header % 4, 0);
            let mut b = vec![0; header + self.data.len()];
            b[0] = 0x40 | (header / 4) as u8;
            b[1] = (10 << 2) | self.ecn;
            let total = b.len() as u16;
            b[2..4].copy_from_slice(&total.to_be_bytes());
            b[4..6].copy_from_slice(&(self.id as u16).to_be_bytes());
            let flags = if self.more { 0x2000 } else { 0 } | (self.offset / 8) as u16;
            b[6..8].copy_from_slice(&flags.to_be_bytes());
            b[8] = 64;
            b[9] = self.protocol;
            b[12..16].copy_from_slice(&V4_SOURCE);
            b[16..20].copy_from_slice(&V4_LOCAL);
            b[20..header].copy_from_slice(self.options);
            let sum = ntcp_ip_common::checksum(&b[..header]);
            b[10..12].copy_from_slice(&sum.to_be_bytes());
            b[header..].copy_from_slice(self.data);
            b
        }
    }
}

#[derive(Debug, PartialEq)]
enum Out {
    Whole,
    Held,
    Duplicate,
    Complete(Vec<u8>),
    Discarded(Discard),
}
fn feed_frame(r: &mut Reassembly, now: Instant, arrival: Arrival, frame: &[u8]) -> Out {
    let piece = if frame[0] >> 4 == 6 {
        let packet = ntcp_ip6::parse_fragment(frame).unwrap();
        match Piece::ipv6(&packet) {
            Some(piece) => piece,
            None => return Out::Whole,
        }
    } else {
        Piece::ipv4(&ntcp_ip::parse_fragment(frame, true).unwrap())
    };
    match r.input(now, arrival, piece) {
        Input::Whole => Out::Whole,
        Input::Held => Out::Held,
        Input::Duplicate => Out::Duplicate,
        Input::Complete(done) => {
            // Fragment zero's header is kept exactly as it arrived, with
            // the length of its data, and the arrival it came with.
            assert_eq!(done.arrival, arrival);
            let (header, addresses) = if frame[0] >> 4 == 6 {
                (40, 8..40)
            } else {
                (done.first_header_len, 12..20)
            };
            let first = done.first_header();
            assert_eq!(first[0] >> 4, frame[0] >> 4);
            assert_eq!(first[addresses.clone()], done.packet[addresses]);
            assert!(done.first_data > 0 && done.first_data <= done.packet.len() - header);
            Out::Complete(done.packet.to_vec())
        }
        Input::Discarded(discard) => Out::Discarded(discard),
    }
}
fn feed(r: &mut Reassembly, f: &Fixture, now: Instant, fragment: Frag) -> Out {
    feed_frame(r, now, f.arrival(fragment.v6), &fragment.encode())
}
fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}
fn engine() -> Reassembly {
    Reassembly::new(limits(), SECOND).unwrap()
}
fn expire_all(r: &mut Reassembly, now: Instant) -> Vec<Vec<u8>> {
    let mut expired = Vec::new();
    r.expire(
        now,
        |_, _| true,
        |e| {
            assert!(!e.arrival.link_multicast);
            expired.push(e.first_fragment.to_vec())
        },
    );
    expired
}
// The reconstructed packet parses as one atomic datagram carrying `data`.
fn check_complete(packet: &[u8], v6: bool, data: &[u8], ecn: u8) {
    if v6 {
        let p = ntcp_ip6::parse(packet).unwrap();
        assert_eq!(
            (p.payload, p.traffic_class & 3, p.protocol),
            (data, ecn, 17)
        );
    } else {
        let p = ntcp_ip::parse(packet, true).unwrap();
        assert_eq!(
            (p.payload, p.traffic_class & 3, p.protocol),
            (data, ecn, 17)
        );
    }
}

#[test]
fn limits_are_validated_and_capacity_is_backed_by_storage() {
    assert_eq!(ReassemblyLimits::default().datagram_capacity(false), None);
    assert!(Reassembly::new(ReassemblyLimits::default(), SECOND).is_ok());
    let good = limits();
    // 200 descriptors of 8 octets bound both families below their maxima.
    assert_eq!(good.datagram_capacity(false), Some(1620));
    assert_eq!(good.datagram_capacity(true), Some(1640));
    let bad = [
        ReassemblyLimits {
            ipv4_datagram: 575,
            ..good
        },
        ReassemblyLimits {
            ipv6_datagram: 1499,
            ..good
        },
        ReassemblyLimits {
            ipv4_datagram: 65536,
            ..good
        },
        ReassemblyLimits {
            ipv6_datagram: 65576,
            ..good
        },
        ReassemblyLimits {
            ipv4_timeout_seconds: 59,
            ..good
        },
        ReassemblyLimits {
            ipv4_timeout_seconds: 121,
            ..good
        },
        // IPv6 1500 octets in 8-octet fragments needs 183 descriptors.
        ReassemblyLimits {
            fragments: 182,
            ..good
        },
        // The first IPv6 fragment also stores its Fragment header.
        ReassemblyLimits {
            buffered_bytes: 1507,
            ..good
        },
        ReassemblyLimits {
            buffered_bytes: usize::MAX,
            ..good
        },
        ReassemblyLimits {
            assemblies: usize::MAX,
            ..good
        },
    ];
    for limits in bad {
        assert!(
            matches!(Reassembly::new(limits, SECOND), Err(Error::Capacity)),
            "{limits:?}"
        );
    }
    let minimal = ReassemblyLimits {
        fragments: 183,
        buffered_bytes: 1508,
        ..good
    };
    assert_eq!(minimal.datagram_capacity(true), Some(1500));
    assert_eq!(minimal.datagram_capacity(false), Some(1484));
    // Both 60 and 120 seconds are within RFC 1122 section 3.3.2's range.
    for seconds in [60, 120] {
        Reassembly::new(
            ReassemblyLimits {
                ipv4_timeout_seconds: seconds,
                ..good
            },
            SECOND,
        )
        .unwrap();
    }
}

#[test]
fn host_states_capacity_per_family_and_rejects_invalid_configuration() {
    let cfg = config(1);
    let (paths, mut host_limits) = managed_limits(&cfg, 1, 1, 1, 1, 0).unwrap();
    let host = Host::new(
        ContextId::new(3),
        paths,
        host_limits,
        cfg.connection.timebase,
    )
    .unwrap();
    assert_eq!(host.reassembly_capacity(false), None);
    assert_eq!(host.reassembly_capacity(true), None);
    host_limits.reassembly = ReassemblyLimits {
        assemblies: 8,
        fragments: 8192,
        buffered_bytes: 1 << 17,
        ipv4_datagram: 65535,
        ipv6_datagram: 65575,
        ipv4_timeout_seconds: 120,
    };
    let host = Host::new(
        ContextId::new(4),
        paths,
        host_limits,
        cfg.connection.timebase,
    )
    .unwrap();
    assert_eq!(
        host.reassembly_capacity(false),
        Some(ReassemblyCapacity {
            context: ContextId::new(4),
            emtu_r: 65535,
            mms_r: 65515,
        })
    );
    assert_eq!(
        host.reassembly_capacity(true),
        Some(ReassemblyCapacity {
            context: ContextId::new(4),
            emtu_r: 65575,
            mms_r: 65535,
        })
    );
    host_limits.reassembly.ipv4_timeout_seconds = 30;
    assert!(matches!(
        Host::new(
            ContextId::new(5),
            paths,
            host_limits,
            cfg.connection.timebase
        ),
        Err(Error::Capacity)
    ));
}

#[test]
fn arrival_orders_reconstruct_the_datagram_and_atomics_bypass() {
    let f = fixture();
    for v6 in [false, true] {
        let payload = data(1000, 3);
        let pieces = [(0, 400), (400, 400), (800, 200)];
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
            let mut r = engine();
            for (step, &i) in order.iter().enumerate() {
                let (offset, len) = pieces[i];
                let fragment = frag(v6, 9, offset, i != 2, &payload[offset as usize..][..len]);
                let out = feed(&mut r, &f, step as u64, fragment);
                if step < 2 {
                    assert_eq!(out, Out::Held);
                    // An atomic datagram (or IPv6 atomic fragment) with the
                    // same identity passes beside the incomplete assembly.
                    assert_eq!(
                        feed(&mut r, &f, 0, frag(v6, 9, 0, false, &[1; 8])),
                        Out::Whole
                    );
                } else {
                    let Out::Complete(packet) = out else {
                        panic!("{out:?}")
                    };
                    check_complete(&packet, v6, &payload, 0);
                }
            }
            assert_eq!((r.assemblies(), r.buffered()), (0, 0));
        }
    }
}

#[test]
fn malformed_fragments_are_refused_before_any_state() {
    let f = fixture();
    for v6 in [false, true] {
        let mut r = engine();
        let odd = data(13, 1);
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 1, 0, true, &odd)),
            Out::Discarded(Discard::Misaligned)
        );
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 1, 8, true, &[])),
            Out::Discarded(Discard::Empty)
        );
        // A fragment ending beyond the family's largest datagram.
        let offset = if v6 { 65528 } else { 65512 };
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 1, offset, false, &[0; 16])),
            Out::Discarded(Discard::Oversize)
        );
        // Within the family maximum but beyond this Host's capacity.
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 1, 4000, false, &[0; 8])),
            Out::Discarded(Discard::Capacity)
        );
        assert_eq!((r.assemblies(), r.buffered()), (0, 0));
        // A source that is not a single host never allocates state.
        let mut frame = frag(v6, 1, 8, true, &[0; 8]).encode();
        if v6 {
            frame[8] = 0xff;
        } else {
            frame[12] = 224;
            frame[10..12].fill(0);
            let sum = ntcp_ip_common::checksum(&frame[..20]);
            frame[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        assert_eq!(
            feed_frame(&mut r, 0, f.arrival(v6), &frame),
            Out::Discarded(Discard::Source)
        );
        assert_eq!(r.assemblies(), 0);
        // Disabled reassembly holds nothing.
        let mut off = Reassembly::new(ReassemblyLimits::default(), SECOND).unwrap();
        assert_eq!(
            feed(&mut off, &f, 0, frag(v6, 1, 8, true, &[0; 8])),
            Out::Discarded(Discard::Assemblies)
        );
        assert_eq!(
            feed(&mut off, &f, 0, frag(v6, 1, 0, false, &[0; 8])),
            Out::Whole
        );
    }
}

#[test]
fn final_boundaries_must_agree() {
    let f = fixture();
    for v6 in [false, true] {
        let d = data(64, 2);
        // Two different final lengths.
        let mut r = engine();
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 2, 32, false, &d[32..])),
            Out::Held
        );
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 2, 16, false, &d[16..32])),
            Out::Discarded(Discard::Contradiction)
        );
        assert_eq!((r.assemblies(), r.buffered()), (0, 0));
        // Data beyond the final length, either order.
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 3, 0, false, &d[..0])),
            Out::Whole
        );
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 3, 16, false, &d[16..24])),
            Out::Held
        );
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 3, 24, true, &d[24..32])),
            Out::Discarded(Discard::Contradiction)
        );
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 4, 40, true, &d[40..48])),
            Out::Held
        );
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 4, 32, false, &d[32..40])),
            Out::Discarded(Discard::Contradiction)
        );
        assert_eq!(r.assemblies(), 0);
        // A non-final fragment ending exactly at a final length.
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 5, 16, true, &d[16..32])),
            Out::Held
        );
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 5, 24, false, &d[24..32])),
            if v6 {
                Out::Discarded(Discard::Overlap)
            } else {
                Out::Discarded(Discard::Contradiction)
            }
        );
    }
}

#[test]
fn exact_duplicates_take_nothing_and_never_refresh_the_deadline() {
    let f = fixture();
    for v6 in [false, true] {
        let mut r = engine();
        let d = data(48, 4);
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 6, 0, true, &d[..16])),
            Out::Held
        );
        let buffered = r.buffered();
        for t in 1..4 {
            assert_eq!(
                feed(&mut r, &f, t * 10 * SECOND, frag(v6, 6, 0, true, &d[..16])),
                Out::Duplicate
            );
        }
        assert_eq!(r.buffered(), buffered);
        // Same offset and extent but another final flag is not a duplicate.
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 6, 16, true, &d[16..32])),
            Out::Held
        );
        let other = feed(&mut r, &f, 0, frag(v6, 6, 16, false, &d[16..32]));
        assert_eq!(
            other,
            Out::Discarded(if v6 {
                Discard::Overlap
            } else {
                Discard::Contradiction
            })
        );
        let mut r = engine();
        assert_eq!(
            feed(&mut r, &f, 0, frag(v6, 6, 0, true, &d[..16])),
            Out::Held
        );
        assert_eq!(
            feed(&mut r, &f, 50 * SECOND, frag(v6, 6, 0, true, &d[..16])),
            Out::Duplicate
        );
        // The deadline stays 60 seconds after the first arrival.
        assert_eq!(r.next_deadline(), Some(60 * SECOND));
        assert_eq!(
            feed(&mut r, &f, 60 * SECOND, frag(v6, 6, 16, false, &d[16..])),
            Out::Discarded(Discard::Late)
        );
        assert_eq!(expire_all(&mut r, 60 * SECOND).len(), 1);
        assert_eq!(r.counters().duplicates, 1);
    }
}

#[test]
fn ipv4_overlap_accepts_identical_octets_and_rejects_conflicts() {
    let f = fixture();
    let d = data(64, 5);
    let mut r = engine();
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 7, 0, true, &d[..32])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 7, 16, true, &d[16..48])),
        Out::Held
    );
    let Out::Complete(packet) = feed(&mut r, &f, 0, frag(false, 7, 40, false, &d[40..])) else {
        panic!()
    };
    check_complete(&packet, false, &d, 0);
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 8, 0, true, &d[..32])),
        Out::Held
    );
    let mut changed = d.clone();
    changed[20] ^= 1;
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 8, 16, true, &changed[16..32])),
        Out::Discarded(Discard::Conflict)
    );
    assert_eq!((r.assemblies(), r.buffered()), (0, 0));
    // The datagram's remaining fragments start over: nothing is remembered.
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 8, 32, false, &d[32..])),
        Out::Held
    );
}

#[test]
fn ipv6_overlap_leaves_an_unevictable_silent_rejection_marker() {
    let f = fixture();
    let d = data(64, 6);
    let mut r = Reassembly::new(
        ReassemblyLimits {
            assemblies: 1,
            ..limits()
        },
        SECOND,
    )
    .unwrap();
    assert_eq!(
        feed(&mut r, &f, 0, frag(true, 9, 0, true, &d[..32])),
        Out::Held
    );
    // Byte-identical overlap is still overlap for IPv6 (RFC 5722).
    assert_eq!(
        feed(&mut r, &f, SECOND, frag(true, 9, 16, true, &d[16..48])),
        Out::Discarded(Discard::Overlap)
    );
    assert_eq!((r.assemblies(), r.buffered()), (1, 0));
    for fragment in [
        frag(true, 9, 0, true, &d[..32]),
        frag(true, 9, 32, false, &d[32..]),
    ] {
        assert_eq!(
            feed(&mut r, &f, 2 * SECOND, fragment),
            Out::Discarded(Discard::Rejected)
        );
    }
    // The marker keeps its slot: another datagram cannot evict it.
    assert_eq!(
        feed(&mut r, &f, 2 * SECOND, frag(true, 10, 0, true, &d[..32])),
        Out::Discarded(Discard::Assemblies)
    );
    assert_eq!(r.next_deadline(), Some(60 * SECOND));
    assert!(expire_all(&mut r, 59 * SECOND).is_empty());
    assert_eq!(r.assemblies(), 1);
    // It expires at the original deadline without a Time Exceeded.
    assert!(expire_all(&mut r, 60 * SECOND).is_empty());
    assert_eq!(r.assemblies(), 0);
    assert_eq!(
        feed(&mut r, &f, 61 * SECOND, frag(true, 9, 0, true, &d[..32])),
        Out::Held
    );
}

// RFC 5722 section 4: the later fragments of an IPv6 datagram abandoned
// for overlap are discarded silently, before the checks behind RFC 8200
// section 4.5's Parameter Problems; the same fragments of a datagram
// without a live marker are judged by those checks.
#[test]
fn rejection_markers_precede_every_error_producing_check() {
    let f = fixture();
    let d = data(64, 12);
    let checked = |id| {
        [
            (frag(true, id, 8, true, &d[..13]), Discard::Misaligned),
            (frag(true, id, 65528, false, &d[..16]), Discard::Oversize),
            (
                Frag {
                    protocol: 6,
                    ..frag(true, id, 0, true, &d[..8])
                },
                Discard::IncompleteHeader,
            ),
        ]
    };
    let mut r = engine();
    for (fragment, discard) in checked(20) {
        assert_eq!(feed(&mut r, &f, 0, fragment), Out::Discarded(discard));
        assert!(ReassemblyError::for_discard(true, discard).is_some());
    }
    assert_eq!(
        feed(&mut r, &f, 0, frag(true, 9, 0, true, &d[..32])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, SECOND, frag(true, 9, 16, true, &d[16..48])),
        Out::Discarded(Discard::Overlap)
    );
    for (fragment, _) in checked(9) {
        assert_eq!(
            feed(&mut r, &f, 2 * SECOND, fragment),
            Out::Discarded(Discard::Rejected)
        );
    }
    assert_eq!(ReassemblyError::for_discard(true, Discard::Rejected), None);
    let counters = r.counters().discarded;
    assert_eq!(
        (
            counters.rejected,
            counters.misaligned,
            counters.oversize,
            counters.incomplete_header
        ),
        (3, 1, 1, 1)
    );
    // Only the marker holds a slot; the discarded fragments created none.
    assert_eq!((r.assemblies(), r.buffered()), (1, 0));
    // At its deadline the marker no longer names a live datagram: the
    // fragments are judged again, a valid one is late until the expiry
    // pass, which sends nothing, and then starts a new assembly.
    for (fragment, discard) in checked(9) {
        assert_eq!(
            feed(&mut r, &f, 60 * SECOND, fragment),
            Out::Discarded(discard)
        );
    }
    assert_eq!(
        feed(&mut r, &f, 60 * SECOND, frag(true, 9, 0, true, &d[..32])),
        Out::Discarded(Discard::Late)
    );
    assert!(expire_all(&mut r, 60 * SECOND).is_empty());
    assert_eq!(r.assemblies(), 0);
    assert_eq!(
        feed(&mut r, &f, 61 * SECOND, frag(true, 9, 0, true, &d[..32])),
        Out::Held
    );
    // IPv4 keeps overlap support and has no markers: an identical overlap
    // is held and a later misaligned fragment is judged as before.
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 9, 0, true, &d[..32])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 9, 16, true, &d[16..48])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 9, 48, true, &d[48..61])),
        Out::Discarded(Discard::Misaligned)
    );
    assert_eq!(r.counters().discarded.rejected, 3);
}

#[test]
fn first_fragment_header_rules_differ_by_family() {
    let f = fixture();
    let mut r = engine();
    // A legal tiny IPv4 first fragment: 8 octets of a TCP header.
    let mut tcp = data(40, 7);
    tcp[12] = 10 << 4;
    let tiny = Frag {
        protocol: 6,
        ..frag(false, 11, 0, true, &tcp[..8])
    };
    assert_eq!(feed(&mut r, &f, 0, tiny), Out::Held);
    let rest = Frag {
        protocol: 6,
        ..frag(false, 11, 8, false, &tcp[8..])
    };
    assert!(matches!(feed(&mut r, &f, 0, rest), Out::Complete(_)));
    // IPv6 fragment zero must hold the TCP header through Data Offset x 4,
    // options included. A non-final fragment holds at least 8 octets, so
    // UDP's and ICMPv6's 8-octet headers are always complete.
    for (i, (protocol, len, complete)) in [
        (6, 8, false),
        (6, 16, false),
        (6, 32, false),
        (6, 40, true),
        (17, 8, true),
        (58, 8, true),
    ]
    .into_iter()
    .enumerate()
    {
        let fragment = Frag {
            protocol,
            ..frag(true, 100 + i as u32, 0, true, &tcp[..len])
        };
        let expected = if complete {
            Out::Held
        } else {
            Out::Discarded(Discard::IncompleteHeader)
        };
        assert_eq!(feed(&mut r, &f, 0, fragment), expected, "{protocol} {len}");
    }
    // Later fragments need no upper-layer header at all.
    let later = Frag {
        protocol: 6,
        ..frag(true, 120, 8, true, &tcp[..8])
    };
    assert_eq!(feed(&mut r, &f, 0, later), Out::Held);
}

#[test]
fn copied_ipv4_options_must_agree_and_fragment_zero_supplies_the_header() {
    let f = fixture();
    let d = data(48, 8);
    // A completed loose source route (pointer past its end) and Record
    // Route only in fragment zero; later fragments carry the copied route.
    let first = [131, 7, 8, 198, 51, 100, 1, 7, 7, 8, 198, 51, 100, 9, 1, 0];
    let later = [131, 7, 8, 198, 51, 100, 1, 0];
    let other_hop = [131, 7, 8, 203, 0, 113, 1, 0];
    let strict = [137, 7, 8, 198, 51, 100, 1, 0];
    let mut r = engine();
    let zero = Frag {
        options: &first,
        ..frag(false, 13, 0, true, &d[..16])
    };
    assert_eq!(feed(&mut r, &f, 0, zero), Out::Held);
    // A different recorded address in the copied route is a mutable
    // recording; the kind and length still match.
    let middle = Frag {
        options: &other_hop,
        ..frag(false, 13, 16, true, &d[16..32])
    };
    assert_eq!(feed(&mut r, &f, 0, middle), Out::Held);
    let last = Frag {
        options: &later,
        ..frag(false, 13, 32, false, &d[32..])
    };
    let Out::Complete(packet) = feed(&mut r, &f, 0, last) else {
        panic!()
    };
    assert_eq!(&packet[20..36], &first);
    assert_eq!(&packet[36..], &d);
    assert_eq!(usize::from(packet[0] & 15) * 4, 36);
    // A copied option missing from, or different in, another fragment.
    for bad in [&[][..], &strict[..]] {
        assert_eq!(feed(&mut r, &f, 0, zero), Out::Held);
        let last = Frag {
            options: bad,
            ..frag(false, 13, 32, false, &d[32..])
        };
        assert_eq!(feed(&mut r, &f, 0, last), Out::Discarded(Discard::Options));
        assert_eq!((r.assemblies(), r.buffered()), (0, 0));
    }
    // Fragment zero's header counts against the reconstructed limit.
    let big = vec![0; 1592];
    let big = Frag {
        options: &later,
        ..frag(false, 14, 8, false, &big)
    };
    assert_eq!(feed(&mut r, &f, 0, big), Out::Held);
    let zero = Frag {
        options: &first,
        ..frag(false, 14, 0, true, &d[..8])
    };
    assert_eq!(feed(&mut r, &f, 0, zero), Out::Discarded(Discard::Capacity));
    assert_eq!(r.assemblies(), 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= type=test
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# Reassembly of a fragmented packet MUST NOT lose indications of
//# congestion.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= type=test
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# In other words, if any fragment of an IP packet to be
//# reassembled has the CE codepoint set, then one of two actions MUST be
//# taken:
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= type=test
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# However, this
//# MUST NOT occur if any of the other fragments contributing to
//# this reassembly carries the Not-ECT codepoint.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= type=test
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# If both actions are applicable, either MAY be chosen.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= type=test
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# Reassembly of
//# a fragmented packet MUST NOT change the ECN codepoint when all of the
//# fragments carry the same codepoint.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= type=test
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# * The packet is dropped, instead of being reassembled, for any other reason.
fn every_ecn_combination_follows_the_published_table() {
    // RFC 3168 section 5.3 plus the selected mixed rows.
    let table = [
        (&[0][..], Some(0)),
        (&[1], Some(1)),
        (&[2], Some(2)),
        (&[3], Some(3)),
        (&[3, 1], Some(3)),
        (&[3, 2], Some(3)),
        (&[3, 1, 2], Some(3)),
        (&[3, 0], None),
        (&[3, 0, 2], None),
        (&[1, 2], Some(2)),
        (&[1, 0], Some(0)),
        (&[2, 0], Some(0)),
        (&[1, 2, 0], Some(0)),
    ];
    for (codepoints, expected) in table {
        let seen = codepoints.iter().fold(0, |s, c| s | 1 << c);
        assert_eq!(ecn_result(seen), expected, "{codepoints:?}");
    }
    let f = fixture();
    for v6 in [false, true] {
        for (codepoints, expected) in table {
            let d = data(8 * (codepoints.len() + 1), 9);
            let mut r = engine();
            let n = codepoints.len();
            for (i, &ecn) in codepoints.iter().enumerate() {
                let fragment = Frag {
                    ecn,
                    ..frag(v6, 15, 8 * i as u32, true, &d[8 * i..8 * i + 8])
                };
                assert_eq!(feed(&mut r, &f, 0, fragment), Out::Held);
            }
            // The final fragment repeats the first codepoint.
            let fragment = Frag {
                ecn: codepoints[0],
                ..frag(v6, 15, 8 * n as u32, false, &d[8 * n..])
            };
            match (expected, feed(&mut r, &f, 0, fragment)) {
                (Some(ecn), Out::Complete(packet)) => check_complete(&packet, v6, &d, ecn),
                (None, Out::Discarded(Discard::Ecn)) => {}
                (expected, out) => panic!("{codepoints:?} {expected:?} {out:?}"),
            }
            assert_eq!(r.buffered(), 0);
        }
        // CE on an exact duplicate alone still marks the datagram, and a
        // CE-marked duplicate beside a Not-ECT fragment drops it.
        for (base, expected) in [(2, Out::Held), (0, Out::Held)] {
            let d = data(16, 10);
            let mut r = engine();
            let zero = Frag {
                ecn: base,
                ..frag(v6, 16, 0, true, &d[..8])
            };
            assert_eq!(feed(&mut r, &f, 0, zero), expected);
            assert_eq!(feed(&mut r, &f, 0, Frag { ecn: 3, ..zero }), Out::Duplicate);
            let out = feed(
                &mut r,
                &f,
                0,
                Frag {
                    ecn: base,
                    ..frag(v6, 16, 8, false, &d[8..])
                },
            );
            match (base, out) {
                (2, Out::Complete(packet)) => check_complete(&packet, v6, &d, 3),
                (0, Out::Discarded(Discard::Ecn)) => {}
                (_, out) => panic!("{out:?}"),
            }
        }
        // A malformed fragment is discarded before it contributes.
        let d = data(16, 11);
        let mut r = engine();
        assert_eq!(
            feed(
                &mut r,
                &f,
                0,
                Frag {
                    ecn: 2,
                    ..frag(v6, 17, 0, true, &d[..8])
                }
            ),
            Out::Held
        );
        assert_eq!(
            feed(
                &mut r,
                &f,
                0,
                Frag {
                    ecn: 3,
                    ..frag(v6, 17, 8, true, &d[8..13])
                }
            ),
            Out::Discarded(Discard::Misaligned)
        );
        let Out::Complete(packet) = feed(
            &mut r,
            &f,
            0,
            Frag {
                ecn: 2,
                ..frag(v6, 17, 8, false, &d[8..])
            },
        ) else {
            panic!()
        };
        check_complete(&packet, v6, &d, 2);
    }
}

#[test]
fn expiry_runs_without_traffic_and_reports_only_after_fragment_zero() {
    let f = fixture();
    for v6 in [false, true] {
        let d = data(32, 12);
        let mut r = engine();
        // Missing last fragment: fragment zero arrived.
        let zero = frag(v6, 18, 0, true, &d[..16]);
        assert_eq!(feed(&mut r, &f, 0, zero), Out::Held);
        // Missing first fragment.
        assert_eq!(
            feed(&mut r, &f, 5 * SECOND, frag(v6, 19, 16, false, &d[16..])),
            Out::Held
        );
        assert!(expire_all(&mut r, 60 * SECOND - 1).is_empty());
        let expired = expire_all(&mut r, 60 * SECOND);
        assert_eq!(expired, vec![zero.encode()]);
        assert_eq!(r.assemblies(), 1);
        assert!(expire_all(&mut r, 65 * SECOND).is_empty());
        assert_eq!((r.assemblies(), r.buffered()), (0, 0));
        assert_eq!(r.counters().expired, 2);
    }
    // The IPv4 timeout is the configured value, independent of TTL.
    let mut r = Reassembly::new(
        ReassemblyLimits {
            ipv4_timeout_seconds: 120,
            ..limits()
        },
        SECOND,
    )
    .unwrap();
    let d = data(16, 13);
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 20, 0, true, &d[..8])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(true, 20, 0, true, &d[..8])),
        Out::Held
    );
    assert_eq!(expire_all(&mut r, 60 * SECOND).len(), 1);
    assert_eq!(r.next_deadline(), Some(120 * SECOND));
}

#[test]
fn retired_addresses_and_links_discard_their_assemblies_silently() {
    let f = fixture();
    let mut r = engine();
    let d = data(32, 14);
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 21, 0, true, &d[..16])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(true, 21, 0, true, &d[..16])),
        Out::Held
    );
    let mut reported = 0;
    let retired = f.local4;
    r.expire(0, |_, local| local != retired, |_| reported += 1);
    assert_eq!((reported, r.assemblies(), r.counters().retired), (0, 1, 1));
    // A replaced link generation: nothing it held survives.
    let mut paths = f.paths;
    paths.remove_link(f.link).unwrap();
    r.expire(
        0,
        |link, local| paths.owns_source(local, link).unwrap_or(false),
        |_| reported += 1,
    );
    assert_eq!((reported, r.assemblies(), r.buffered()), (0, 0, 0));
}

#[test]
fn every_bound_drops_the_new_fragment_and_is_counted() {
    let f = fixture();
    let d = data(1600, 15);
    // Assemblies.
    let mut r = Reassembly::new(
        ReassemblyLimits {
            assemblies: 2,
            ..limits()
        },
        SECOND,
    )
    .unwrap();
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 1, 0, true, &d[..8])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(true, 1, 0, true, &d[..8])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 3, 0, true, &d[..8])),
        Out::Discarded(Discard::Assemblies)
    );
    assert_eq!(r.counters().discarded.assemblies, 1);
    // Fragments per assembly: 200 descriptors cover 1600 octets in 8-octet
    // fragments; an exact duplicate takes none, an identical overlap would.
    let mut r = engine();
    for i in 0..200u32 {
        let at = (8 * i) as usize;
        assert_eq!(
            feed(&mut r, &f, 0, frag(false, 4, 8 * i, true, &d[at..at + 8])),
            Out::Held
        );
    }
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 4, 8, true, &d[8..16])),
        Out::Duplicate
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 4, 8, true, &d[8..24])),
        Out::Discarded(Discard::Fragments)
    );
    assert_eq!(r.counters().discarded.fragments, 1);
    // Buffered bytes across assemblies.
    let mut r = Reassembly::new(
        ReassemblyLimits {
            buffered_bytes: 1600,
            ..limits()
        },
        SECOND,
    )
    .unwrap();
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 5, 800, true, &d[..600])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(true, 5, 600, true, &d[..800])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(true, 6, 0, true, &d[..248])),
        Out::Discarded(Discard::Bytes)
    );
    assert_eq!(
        (r.counters().discarded.bytes, r.assemblies(), r.buffered()),
        (1, 2, 1400)
    );
}

#[test]
fn pool_compaction_preserves_held_fragments() {
    let f = fixture();
    let limits = ReassemblyLimits {
        buffered_bytes: 1600,
        ..limits()
    };
    let mut r = Reassembly::new(limits, SECOND).unwrap();
    let a = data(1000, 16);
    let b = data(1000, 17);
    // Fill, free the middle by completing one datagram, then add a fragment
    // that fits only once the remaining regions move down.
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 1, 400, false, &a[400..800])),
        Out::Held
    );
    assert_eq!(
        feed(&mut r, &f, 0, frag(false, 2, 0, true, &b[..400])),
        Out::Held
    );
    let Out::Complete(packet) = feed(&mut r, &f, 0, frag(false, 2, 400, false, &b[400..800]))
    else {
        panic!()
    };
    check_complete(&packet, false, &b[..800], 0);
    assert_eq!(
        feed(&mut r, &f, 0, frag(true, 3, 400, true, &b[..600])),
        Out::Held
    );
    let Out::Complete(packet) = feed(&mut r, &f, 0, frag(false, 1, 0, true, &a[..400])) else {
        panic!()
    };
    check_complete(&packet, false, &a[..800], 0);
}

#[test]
fn scoped_addresses_join_the_arrival_link_to_the_key() {
    let mut f = fixture();
    let other = f.paths.register_link(InterfaceKey(2), 1500).unwrap();
    let d = data(16, 18);
    let mut r = engine();
    let mut first = frag(true, 22, 0, true, &d[..8]).encode();
    let mut last = frag(true, 22, 8, false, &d[8..]).encode();
    for frame in [&mut first, &mut last] {
        frame[8] = 0xfe;
        frame[9] = 0x80;
    }
    assert_eq!(feed_frame(&mut r, 0, f.arrival(true), &first), Out::Held);
    let elsewhere = Arrival {
        link: other,
        ..f.arrival(true)
    };
    assert_eq!(feed_frame(&mut r, 0, elsewhere, &last), Out::Held);
    assert!(matches!(
        feed_frame(&mut r, 0, f.arrival(true), &last),
        Out::Complete(_)
    ));
}

// ICMP errors: codes and pointers, family-specific suppression, the
// limiter and quote sizes.
fn error_for(
    limiter: &mut ErrorLimiter,
    now: Instant,
    error: ReassemblyError,
    arrival: Arrival,
    invoking: &[u8],
) -> Option<Vec<u8>> {
    let mut message = [0; 1500];
    let sent = originate(limiter, now, error, arrival, invoking, &mut message)?;
    let source = if invoking[0] >> 4 == 6 {
        IpAddr::from(v6_source())
    } else {
        IpAddr::from(V4_SOURCE)
    };
    assert_eq!(sent.ip.destination, source);
    assert_eq!(sent.link, arrival.link);
    Some(message[..sent.len].to_vec())
}

#[test]
fn reassembly_errors_carry_family_codes_pointers_and_bounded_quotes() {
    let f = fixture();
    let mut limiter = ErrorLimiter::new(
        IcmpErrorLimits {
            burst: 100,
            per_second: 10,
        },
        SECOND,
    );
    assert_eq!(
        ReassemblyError::for_discard(true, Discard::Misaligned),
        Some(ReassemblyError::ParameterProblem {
            code: 0,
            pointer: 4
        })
    );
    assert_eq!(
        ReassemblyError::for_discard(true, Discard::Oversize),
        Some(ReassemblyError::ParameterProblem {
            code: 0,
            pointer: 42
        })
    );
    assert_eq!(
        ReassemblyError::for_discard(true, Discard::IncompleteHeader),
        Some(ReassemblyError::ParameterProblem {
            code: 3,
            pointer: 0
        })
    );
    // Overlap is silent; IPv4 defines none of these errors.
    for discard in [
        Discard::Overlap,
        Discard::Rejected,
        Discard::Capacity,
        Discard::Contradiction,
    ] {
        assert_eq!(ReassemblyError::for_discard(true, discard), None);
    }
    for discard in [
        Discard::Misaligned,
        Discard::Oversize,
        Discard::IncompleteHeader,
    ] {
        assert_eq!(ReassemblyError::for_discard(false, discard), None);
    }
    for v6 in [false, true] {
        let big = data(1400, 19);
        let zero = frag(v6, 23, 0, true, &big).encode();
        let message = error_for(
            &mut limiter,
            0,
            ReassemblyError::TimeExceeded,
            f.arrival(v6),
            &zero,
        )
        .unwrap();
        let ip = if v6 {
            IpMetadata {
                source: IpAddr::from(v6_local()),
                destination: IpAddr::from(v6_source()),
            }
        } else {
            IpMetadata {
                source: IpAddr::from(V4_LOCAL),
                destination: IpAddr::from(V4_SOURCE),
            }
        };
        assert_eq!(&message[..2], if v6 { &[3, 1] } else { &[11, 1] });
        // ICMPv6: as much as fits in 1280 octets; ICMPv4: within 576.
        assert_eq!(message.len(), if v6 { 1240 } else { 556 });
        assert_eq!(&message[8..], &zero[..message.len() - 8]);
        let sum = if v6 {
            ntcp_icmp::icmpv6_checksum(ip, &message).unwrap()
        } else {
            ntcp_ip_common::checksum(&message)
        };
        assert_eq!(sum, 0);
    }
    let misaligned = frag(true, 24, 8, true, &[0; 13]).encode();
    let message = error_for(
        &mut limiter,
        0,
        ReassemblyError::for_discard(true, Discard::Misaligned).unwrap(),
        f.arrival(true),
        &misaligned,
    )
    .unwrap();
    assert_eq!(
        (message[0], message[1], &message[4..8]),
        (4, 0, &[0, 0, 0, 4][..])
    );
    assert_eq!(&message[8..], &misaligned);
}

#[test]
fn error_suppression_is_family_specific() {
    let f = fixture();
    let mut limiter = ErrorLimiter::new(
        IcmpErrorLimits {
            burst: 100,
            per_second: 10,
        },
        SECOND,
    );
    let time = ReassemblyError::TimeExceeded;
    let problem = ReassemblyError::ParameterProblem {
        code: 0,
        pointer: 4,
    };
    let send = |l: &mut ErrorLimiter, e, a, b: &[u8]| error_for(l, 0, e, a, b).is_some();
    // IPv4 (RFC 1122 section 3.2.2): no error about a non-initial fragment,
    // an ICMP error, a multicast/broadcast destination or link-layer
    // broadcast, or a source that is not one host; queries are errors' peers.
    assert!(send(
        &mut limiter,
        time,
        f.arrival(false),
        &frag(false, 1, 0, true, &[0; 8]).encode()
    ));
    assert!(!send(
        &mut limiter,
        time,
        f.arrival(false),
        &frag(false, 1, 8, true, &[0; 8]).encode()
    ));
    let icmp = |kind: u8, v6: bool, offset: u32| {
        Frag {
            protocol: if v6 { 58 } else { 1 },
            ..frag(v6, 1, offset, true, &[kind, 0, 0, 0, 0, 0, 0, 0])
        }
        .encode()
    };
    assert!(send(
        &mut limiter,
        time,
        f.arrival(false),
        &icmp(8, false, 0)
    ));
    assert!(!send(
        &mut limiter,
        time,
        f.arrival(false),
        &icmp(3, false, 0)
    ));
    assert!(!send(
        &mut limiter,
        time,
        f.arrival(false),
        &icmp(11, false, 0)
    ));
    let multicast = Arrival {
        link_multicast: true,
        ..f.arrival(false)
    };
    assert!(!send(
        &mut limiter,
        time,
        multicast,
        &frag(false, 1, 0, true, &[0; 8]).encode()
    ));
    let mut to_broadcast = frag(false, 1, 0, true, &[0; 8]).encode();
    to_broadcast[16..20].copy_from_slice(&[255; 4]);
    assert!(!send(&mut limiter, time, f.arrival(false), &to_broadcast));
    let mut from_multicast = frag(false, 1, 0, true, &[0; 8]).encode();
    from_multicast[12] = 224;
    assert!(!send(&mut limiter, time, f.arrival(false), &from_multicast));
    // IPv6 (RFC 4443 section 2.4(e)): non-initial fragments are not
    // excluded as such, but ICMPv6 errors and Redirects are, and so is a
    // non-initial fragment of ICMPv6, whose data cannot be classified.
    assert!(send(
        &mut limiter,
        problem,
        f.arrival(true),
        &frag(true, 1, 8, true, &[0; 13]).encode()
    ));
    assert!(send(
        &mut limiter,
        problem,
        f.arrival(true),
        &icmp(128, true, 0)
    ));
    assert!(!send(
        &mut limiter,
        problem,
        f.arrival(true),
        &icmp(1, true, 0)
    ));
    assert!(!send(
        &mut limiter,
        problem,
        f.arrival(true),
        &icmp(137, true, 0)
    ));
    assert!(!send(
        &mut limiter,
        problem,
        f.arrival(true),
        &icmp(128, true, 8)
    ));
    let multicast = Arrival {
        link_multicast: true,
        ..f.arrival(true)
    };
    assert!(!send(
        &mut limiter,
        problem,
        multicast,
        &frag(true, 1, 8, true, &[0; 8]).encode()
    ));
    let mut to_multicast = frag(true, 1, 8, true, &[0; 8]).encode();
    to_multicast[24] = 0xff;
    assert!(!send(&mut limiter, problem, f.arrival(true), &to_multicast));
    // A Parameter Problem names an IPv6 packet only.
    let v4 = frag(false, 1, 0, true, &[0; 8]).encode();
    assert!(!send(&mut limiter, problem, f.arrival(false), &v4));
}

#[test]
fn one_limiter_bounds_every_error_in_bursts() {
    let f = fixture();
    let mut limiter = ErrorLimiter::new(IcmpErrorLimits::default(), SECOND);
    let v4 = frag(false, 1, 0, true, &[0; 8]).encode();
    let v6 = frag(true, 1, 0, true, &[0; 8]).encode();
    let time = ReassemblyError::TimeExceeded;
    let mut sent = 0;
    for i in 0..30 {
        let (invoking, v6) = if i % 2 == 0 {
            (&v4, false)
        } else {
            (&v6, true)
        };
        sent += usize::from(error_for(&mut limiter, 0, time, f.arrival(v6), invoking).is_some());
    }
    // RFC 4443 section 2.4(f)'s example bucket: a burst of 10 across both
    // families, then 10 per second.
    assert_eq!(sent, 10);
    assert!(error_for(&mut limiter, SECOND / 10 - 1, time, f.arrival(false), &v4).is_none());
    assert!(error_for(&mut limiter, SECOND / 10, time, f.arrival(false), &v4).is_some());
    assert!(error_for(&mut limiter, SECOND / 10, time, f.arrival(false), &v4).is_none());
    // A long quiet period refills only up to the burst.
    let mut burst = 0;
    for _ in 0..20 {
        burst += usize::from(
            error_for(&mut limiter, 100 * SECOND, time, f.arrival(true), &v6).is_some(),
        );
    }
    assert_eq!(burst, 10);
    // Suppressed messages do not spend tokens; a zero burst sends nothing.
    let mut quiet = ErrorLimiter::new(
        IcmpErrorLimits {
            burst: 1,
            per_second: 1,
        },
        SECOND,
    );
    let later = frag(false, 1, 8, true, &[0; 8]).encode();
    assert!(error_for(&mut quiet, 0, time, f.arrival(false), &later).is_none());
    assert!(error_for(&mut quiet, 0, time, f.arrival(false), &v4).is_some());
    let mut off = ErrorLimiter::new(
        IcmpErrorLimits {
            burst: 0,
            per_second: 10,
        },
        SECOND,
    );
    assert!(error_for(&mut off, 10 * SECOND, time, f.arrival(false), &v4).is_none());
}

// Seeded reference model. Each round interleaves up to three datagrams per
// family, fragmented at a random aligned size, with arrivals in order,
// reversed or shuffled, exact duplicates (with their own ECN codepoints),
// IPv4 identical and conflicting overlaps, IPv6 overlaps, contradictory
// final fragments and missing fragments, then expires the rest. The model
// tracks octets by position, independently of the engine's descriptors.
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
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

#[derive(Clone, Default)]
struct Model {
    // (offset, len, final) of every stored piece.
    pieces: Vec<(u32, u32, bool)>,
    octets: BTreeMap<u32, u8>,
    final_len: Option<u32>,
    first: Option<Vec<u8>>,
    ecn: u8,
    marker: Option<Instant>,
    deadline: Option<Instant>,
}
impl Model {
    fn charged(&self) -> usize {
        let data: u32 = self.pieces.iter().map(|p| p.1).sum();
        data as usize
            + self
                .first
                .as_ref()
                .map_or(0, |f| f.len() - self.first_data())
    }
    fn first_data(&self) -> usize {
        self.pieces
            .iter()
            .find(|p| p.0 == 0)
            .map_or(0, |p| p.1 as usize)
    }
}

#[derive(Default, Debug)]
struct Coverage {
    in_order: u64,
    reversed: u64,
    shuffled: u64,
    duplicates: u64,
    identical_overlap: u64,
    conflicts: u64,
    ipv6_overlaps: u64,
    marker_hits: u64,
    contradictions: u64,
    early_final: u64,
    missing_first: u64,
    missing_last: u64,
    expired_reported: u64,
    expired_silent: u64,
    markers_expired: u64,
    ecn_rows: [u64; 5],
    atomics: u64,
}

#[test]
fn seeded_reassembly_matches_the_reference_model() {
    let f = fixture();
    let model_limits = ReassemblyLimits {
        assemblies: 8,
        fragments: 400,
        buffered_bytes: 1 << 16,
        ..limits()
    };
    let mut c = Coverage::default();
    let seeds = 64u64;
    let mut checked = 0u64;
    for seed in 1..=seeds {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut r = Reassembly::new(model_limits, SECOND).unwrap();
        let mut now: Instant = 0;
        for round in 0..12u32 {
            // Arrivals: (datagram index, fragment, kind).
            let count = 1 + rng.below(3) as usize;
            let mut datagrams = Vec::new();
            let mut lists: Vec<Vec<(Frag<'static>, &'static str)>> = Vec::new();
            for index in 0..count {
                let v6 = rng.chance(50);
                let len = 9 + rng.below(1400) as usize;
                let unit = 8 * (1 + rng.below(64) as usize);
                let payload: &'static [u8] = Vec::leak(data(len, rng.next() as u8));
                let id = round * 16 + index as u32;
                let ecn_choices = 1 + rng.below(15) as u8;
                let mut pieces = Vec::new();
                let mut offset = 0;
                while offset < len {
                    let n = unit.min(len - offset);
                    let mut ecn = rng.below(4) as u8;
                    while ecn_choices & (1 << ecn) == 0 {
                        ecn = (ecn + 1) % 4;
                    }
                    let fragment = Frag {
                        ecn,
                        ..frag(
                            v6,
                            id,
                            offset as u32,
                            offset + n < len,
                            &payload[offset..offset + n],
                        )
                    };
                    pieces.push(fragment);
                    offset += n;
                }
                if pieces.len() < 2 {
                    continue;
                }
                let order = rng.below(3);
                match order {
                    0 => {}
                    1 => pieces.reverse(),
                    _ => {
                        for i in (1..pieces.len()).rev() {
                            let j = rng.below(i as u64 + 1) as usize;
                            pieces.swap(i, j);
                        }
                    }
                }
                let missing = rng
                    .chance(10)
                    .then(|| rng.below(pieces.len() as u64) as usize);
                let mut list: Vec<(Frag<'static>, &'static str)> = pieces
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| Some(*i) != missing)
                    .map(|(_, p)| (*p, "piece"))
                    .collect();
                // Extra arrivals inserted at random positions.
                for _ in 0..rng.below(4) {
                    let at = rng.below(list.len() as u64 + 1) as usize;
                    let base = pieces[rng.below(pieces.len() as u64) as usize];
                    let extra = match rng.below(5) {
                        0 | 1 => (
                            Frag {
                                ecn: rng.below(4) as u8,
                                ..base
                            },
                            "duplicate",
                        ),
                        2 | 3 if base.data.len() >= 16 => {
                            // An aligned overlapping piece of the same
                            // datagram; with one changed octet sometimes.
                            let start = base.offset as usize + 8;
                            let end = (start + 8 * (1 + rng.below(8) as usize)).min(len);
                            let more = end < len;
                            let end = if more {
                                start + (end - start) / 8 * 8
                            } else {
                                end
                            };
                            if end <= start {
                                continue;
                            }
                            let mut bytes = payload[start..end].to_vec();
                            let kind = if rng.chance(30) {
                                bytes[0] ^= 0x55;
                                "conflict"
                            } else {
                                "overlap"
                            };
                            let bytes: &'static [u8] = Vec::leak(bytes);
                            (
                                Frag {
                                    offset: start as u32,
                                    more,
                                    data: bytes,
                                    ..base
                                },
                                kind,
                            )
                        }
                        _ if base.more && base.offset > 0 => {
                            // A final fragment contradicting the real end.
                            (
                                Frag {
                                    more: false,
                                    ..base
                                },
                                "contradiction",
                            )
                        }
                        _ => continue,
                    };
                    list.insert(at, extra);
                }
                if missing == Some(pieces.iter().position(|p| p.offset == 0).unwrap()) {
                    c.missing_first += 1;
                }
                if missing.is_some_and(|m| !pieces[m].more) {
                    c.missing_last += 1;
                }
                // An atomic datagram with the same identity goes beside it.
                if rng.chance(20) {
                    list.insert(0, (frag(v6, id, 0, false, &payload[..8]), "atomic"));
                }
                lists.push(list);
                datagrams.push((v6, payload, order, Model::default()));
            }
            // Interleave the datagrams, each keeping its own order.
            let mut next = vec![0; lists.len()];
            let mut merged = Vec::new();
            while let Some(d) = {
                let open: Vec<usize> = (0..lists.len())
                    .filter(|d| next[*d] < lists[*d].len())
                    .collect();
                (!open.is_empty()).then(|| open[rng.below(open.len() as u64) as usize])
            } {
                let (piece, kind) = lists[d][next[d]];
                next[d] += 1;
                merged.push((d, piece, kind));
            }
            for (d, piece, kind) in merged {
                now += rng.below(SECOND / 100);
                let (v6, payload, order, model) = &mut datagrams[d];
                let frame = piece.encode();
                let out = feed_frame(&mut r, now, f.arrival(*v6), &frame);
                let expected = step(model, &piece, &frame, now, kind, &mut c);
                checked += 1;
                match (&expected, &out) {
                    (Expect::Complete(ecn, bytes), Out::Complete(packet)) => {
                        // A contradicting final fragment may legitimately
                        // end the datagram early; the model says where.
                        assert_eq!(&bytes[..], &payload[..bytes.len()]);
                        check_complete(packet, *v6, bytes, *ecn);
                        if bytes.len() < payload.len() {
                            c.early_final += 1;
                        }
                        c.ecn_rows[ecn_row(model.ecn)] += 1;
                        *model = Model::default();
                        match order {
                            0 => c.in_order += 1,
                            1 => c.reversed += 1,
                            _ => c.shuffled += 1,
                        }
                    }
                    (Expect::Ecn, Out::Discarded(Discard::Ecn)) => {
                        c.ecn_rows[ecn_row(model.ecn)] += 1;
                        *model = Model::default();
                    }
                    (Expect::Same(e), out) if e == out => {}
                    _ => panic!("seed {seed} round {round} {kind}: {expected:?} vs {out:?}"),
                }
                let charged: usize = datagrams.iter().map(|d| d.3.charged()).sum();
                assert_eq!(r.buffered(), charged, "seed {seed} round {round}");
                let live = datagrams
                    .iter()
                    .filter(|d| d.3.deadline.is_some() || d.3.marker.is_some())
                    .count();
                assert_eq!(r.assemblies(), live, "seed {seed} round {round}");
            }
            // Expire everything left; the model predicts each report.
            now += 121 * SECOND;
            let mut reports = expire_all(&mut r, now);
            for (_, _, _, model) in &datagrams {
                if model.marker.is_some() {
                    c.markers_expired += 1;
                } else if let Some(first) = &model.first {
                    let at = reports.iter().position(|r| r == first).expect("reported");
                    reports.swap_remove(at);
                    c.expired_reported += 1;
                } else if model.deadline.is_some() {
                    c.expired_silent += 1;
                }
            }
            assert!(reports.is_empty());
            assert_eq!((r.assemblies(), r.buffered()), (0, 0));
        }
    }
    std::println!("REASSEMBLY_MODEL seeds={seeds} arrivals={checked} coverage={c:?}");
    for (name, value) in [
        ("in_order", c.in_order),
        ("reversed", c.reversed),
        ("shuffled", c.shuffled),
        ("duplicates", c.duplicates),
        ("identical_overlap", c.identical_overlap),
        ("conflicts", c.conflicts),
        ("ipv6_overlaps", c.ipv6_overlaps),
        ("marker_hits", c.marker_hits),
        ("contradictions", c.contradictions),
        ("early_final", c.early_final),
        ("missing_first", c.missing_first),
        ("missing_last", c.missing_last),
        ("expired_reported", c.expired_reported),
        ("expired_silent", c.expired_silent),
        ("markers_expired", c.markers_expired),
        ("atomics", c.atomics),
    ] {
        assert!(value > 0, "{name} never exercised");
    }
    assert!(c.ecn_rows.iter().all(|n| *n > 0), "{:?}", c.ecn_rows);
}

// Rows of the ECN table: one codepoint; CE with ECT only; CE with Not-ECT;
// ECT(0) with ECT(1); ECT with Not-ECT.
fn ecn_row(seen: u8) -> usize {
    match seen {
        1 | 2 | 4 | 8 => 0,
        s if s & 8 != 0 && s & 1 == 0 => 1,
        s if s & 8 != 0 => 2,
        6 => 3,
        _ => 4,
    }
}
fn model_ecn(seen: u8) -> Option<u8> {
    match ecn_row(seen) {
        0 => Some(seen.trailing_zeros() as u8),
        1 => Some(3),
        2 => None,
        3 => Some(2),
        _ => Some(0),
    }
}

#[derive(Debug)]
enum Expect {
    Same(Out),
    Complete(u8, Vec<u8>),
    Ecn,
}

fn step(
    m: &mut Model,
    p: &Frag,
    frame: &[u8],
    now: Instant,
    kind: &str,
    c: &mut Coverage,
) -> Expect {
    use Expect::Same;
    if p.offset == 0 && !p.more {
        c.atomics += 1;
        return Same(Out::Whole);
    }
    let lifetime = 60 * SECOND;
    if m.marker.is_some() {
        c.marker_hits += 1;
        return Same(Out::Discarded(Discard::Rejected));
    }
    let (start, end) = (p.offset, p.offset + p.data.len() as u32);
    let fresh = m.deadline.is_none();
    if fresh {
        m.deadline = Some(now + lifetime);
    }
    m.ecn |= 1 << p.ecn;
    // Exact duplicate.
    if m.pieces.contains(&(start, end - start, !p.more))
        && (start..end).all(|i| m.octets.get(&i) == Some(&p.data[(i - start) as usize]))
    {
        c.duplicates += 1;
        return Same(Out::Duplicate);
    }
    let overlaps = m.pieces.iter().any(|q| q.0 < end && start < q.0 + q.1);
    let reset = |m: &mut Model| *m = Model::default();
    if overlaps {
        if p.v6 {
            c.ipv6_overlaps += 1;
            let deadline = m.deadline;
            reset(m);
            m.marker = deadline;
            m.deadline = deadline;
            return Same(Out::Discarded(Discard::Overlap));
        }
        if (start..end).any(|i| {
            m.octets
                .get(&i)
                .is_some_and(|b| *b != p.data[(i - start) as usize])
        }) {
            c.conflicts += 1;
            reset(m);
            return Same(Out::Discarded(Discard::Conflict));
        }
        c.identical_overlap += 1;
    }
    let contradiction = if p.more {
        m.final_len.is_some_and(|f| end >= f)
    } else {
        m.final_len.is_some_and(|f| f != end)
            || m.octets.range(end..).next().is_some()
            || m.pieces.iter().any(|q| !q.2 && q.0 + q.1 >= end)
    };
    if contradiction {
        if kind == "contradiction" || m.final_len.is_some() {
            c.contradictions += 1;
        }
        reset(m);
        return Same(Out::Discarded(Discard::Contradiction));
    }
    m.pieces.push((start, end - start, !p.more));
    for (i, b) in p.data.iter().enumerate() {
        m.octets.insert(start + i as u32, *b);
    }
    if !p.more {
        m.final_len = Some(end);
    }
    if p.offset == 0 && m.first.is_none() {
        m.first = Some(frame.to_vec());
    }
    let done = m.first.is_some()
        && m.final_len
            .is_some_and(|f| (0..f).all(|i| m.octets.contains_key(&i)));
    if !done {
        return Same(Out::Held);
    }
    let ecn = model_ecn(m.ecn);
    // Keep the seen set for the caller's row count; it resets the model.
    m.pieces.clear();
    m.first = None;
    m.deadline = None;
    let bytes = m
        .octets
        .range(..m.final_len.unwrap())
        .map(|(_, b)| *b)
        .collect();
    match ecn {
        Some(ecn) => Expect::Complete(ecn, bytes),
        None => Expect::Ecn,
    }
}
