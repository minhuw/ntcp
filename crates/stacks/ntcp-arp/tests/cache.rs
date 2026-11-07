// Cache tests in caller milliseconds. A constant draw of 2^31 makes every
// ReachableTime exactly the 30 s base.
use core::net::Ipv4Addr;
use ntcp_arp::*;

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER: [u8; 6] = [2, 0, 0, 0, 0, 2];
const OTHER: [u8; 6] = [2, 0, 0, 0, 0, 3];
const PUBLISHED: [u8; 6] = [2, 0, 0, 0, 0, 9];
const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const OTHER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 3);
const PROXY_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
const S: u64 = 1000;

type Cache = ArpCache<u8, u32>;

fn half() -> Option<u32> {
    Some(1 << 31)
}

fn limits() -> ArpLimits {
    ArpLimits {
        links: 2,
        entries: 4,
        held: 4,
        replies: 2,
        addresses: 4,
    }
}

fn cache_with(limits: ArpLimits) -> Cache {
    let mut cache = Cache::new(limits, ArpTimers::default(), 1000).unwrap();
    cache.add_link(0, MAC, &mut half).unwrap();
    cache.add_address(0, LOCAL, AddressKind::Local).unwrap();
    cache
}

fn cache() -> Cache {
    cache_with(limits())
}

fn arp(operation: Operation, sender: ([u8; 6], Ipv4Addr), target: ([u8; 6], Ipv4Addr)) -> Arp {
    Arp {
        operation,
        sender_mac: sender.0,
        sender_ip: sender.1,
        target_mac: target.0,
        target_ip: target.1,
    }
}

fn reply_from(mac: [u8; 6], ip: Ipv4Addr) -> Arp {
    arp(Operation::Reply, (mac, ip), (MAC, LOCAL))
}

fn request_from(mac: [u8; 6], ip: Ipv4Addr, target: Ipv4Addr) -> Arp {
    arp(Operation::Request, (mac, ip), ([0; 6], target))
}

fn receive(cache: &mut Cache, arp: Arp, now: u64) {
    cache.receive(0, &arp, now, &mut half).unwrap();
}

// Poll and complete one control message with `outcome`.
fn send(cache: &mut Cache, now: u64, outcome: ControlOutcome) -> Option<Control<u8>> {
    let (control, token) = cache.next_control(0, now)?;
    cache.complete(token, outcome, now);
    Some(control)
}

fn submit(cache: &mut Cache, now: u64) -> Option<Control<u8>> {
    send(cache, now, ControlOutcome::Submitted)
}

fn wakes(cache: &mut Cache) -> Vec<Wake<u32>> {
    core::iter::from_fn(|| cache.next_wake(|_| true)).collect()
}

fn service(cache: &mut Cache, now: u64) -> Vec<Event<u8>> {
    let mut events = Vec::new();
    cache.service(now, &mut |event| events.push(event));
    events
}

// A REACHABLE entry for PEER_IP, resolved at `now`.
fn reachable(cache: &mut Cache, now: u64) {
    assert_eq!(cache.resolve(0, PEER_IP, now, 99), Ok(Resolution::Held));
    submit(cache, now).unwrap();
    receive(cache, reply_from(PEER, PEER_IP), now);
    assert_eq!(wakes(cache), [Wake::Retry(99)]);
    assert_eq!(
        cache.entry(0, PEER_IP),
        Some((ArpState::Reachable, Some(PEER)))
    );
}

//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# The Address
//# Resolution module then sets the ar$hrd field to
//# ares_hrd$Ethernet, ar$pro to the protocol type that is being
//# resolved, ar$hln to 6 (the number of bytes in a 48.bit Ethernet
//# address), ar$pln to the length of an address in that protocol,
//# ar$op to ares_op$REQUEST, ar$sha with the 48.bit ethernet address
//# of itself, ar$spa with the protocol address of itself, and ar$tpa
//# with the protocol address of the machine that is trying to be
//# accessed.
//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# It does not set ar$tha to anything in particular,
//# because it is this value that it is trying to determine.
//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//= reason=ntcp-arp addresses each resolution request to the Ethernet broadcast address and yields it for the link the next hop was resolved on; putting it on that link is the embedding's, pending the ntcp-host/ntcp-native integration.
//# It then causes
//# this packet to be broadcast to all stations on the Ethernet cable
//# originally determined by the routing mechanism.
#[test]
fn resolution_holds_owners_once_and_releases_them_resolved() {
    let mut cache = cache();
    assert_eq!(cache.resolve(0, PEER_IP, 0, 1), Ok(Resolution::Held));
    assert_eq!(cache.resolve(0, PEER_IP, 0, 2), Ok(Resolution::Held));
    // A retry by the same owner reuses its record: two slots stay free.
    assert_eq!(cache.resolve(0, PEER_IP, 10, 1), Ok(Resolution::Held));
    assert_eq!(cache.resolve(0, OTHER_IP, 10, 3), Ok(Resolution::Held));
    assert_eq!(cache.resolve(0, OTHER_IP, 10, 4), Ok(Resolution::Held));
    assert_eq!(cache.resolve(0, OTHER_IP, 10, 5), Err(Error::Capacity));
    assert!(cache.release(4));
    assert_eq!(cache.entry(0, PEER_IP), Some((ArpState::Incomplete, None)));
    assert_eq!(cache.next_wake(|_| true), None);

    let control = submit(&mut cache, 10).unwrap();
    assert_eq!(control.link, 0);
    assert_eq!(control.source, MAC);
    assert_eq!(control.destination, [0xff; 6]);
    assert_eq!(control.arp, request_from(MAC, LOCAL, PEER_IP));
    let mut frame = [0; 60];
    assert_eq!(control.encode(&mut frame), Ok(60));
    assert_eq!(
        frame[..42],
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 1, 8, 6, 0, 1, 8, 0, 6, 4, 0, 1, 2,
            0, 0, 0, 0, 1, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2
        ]
    );
    // OTHER_IP's request is due as well.
    assert_eq!(submit(&mut cache, 10).unwrap().arp.target_ip, OTHER_IP);

    receive(&mut cache, reply_from(PEER, PEER_IP), 20);
    assert_eq!(
        cache.entry(0, PEER_IP),
        Some((ArpState::Reachable, Some(PEER)))
    );
    // Only owners of the resolved address wake, each once; a filter
    // selects among them.
    assert_eq!(cache.next_wake(|tag| *tag == 2), Some(Wake::Retry(2)));
    assert_eq!(wakes(&mut cache), [Wake::Retry(1)]);
    assert_eq!(
        cache.resolve(0, PEER_IP, 20, 1),
        Ok(Resolution::Ready(PEER))
    );
    assert_eq!(cache.counters().requests_sent, 2);
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-2.3.2.1
//= type=test
//# A mechanism to prevent ARP flooding (repeatedly sending an
//# ARP Request for the same IP address, at a high rate) MUST be
//# included.  The recommended maximum rate is 1 per second per
//# destination.
#[test]
fn requests_are_spaced_one_second_apart_then_resolution_fails() {
    let mut cache = cache();
    assert_eq!(cache.resolve(0, PEER_IP, 0, 7), Ok(Resolution::Held));
    assert_eq!(cache.next_deadline(), Some(0));
    let mut sent = Vec::new();
    for now in (0..=4 * S).step_by(100) {
        assert!(service(&mut cache, now).is_empty() || now == 3 * S);
        while let Some(control) = submit(&mut cache, now) {
            assert_eq!(control.destination, [0xff; 6]);
            sent.push(now);
        }
        // Resolving again before the failure never sends sooner.
        if now < 3 * S {
            assert_eq!(cache.resolve(0, PEER_IP, now, 7), Ok(Resolution::Held));
        }
    }
    // Exactly three broadcast requests, one per second.
    assert_eq!(sent, [0, S, 2 * S]);
    assert_eq!(cache.counters().requests_sent, 3);
    assert_eq!(cache.counters().resolution_failures, 1);
    assert_eq!(cache.entry(0, PEER_IP), None);
    assert_eq!(wakes(&mut cache), [Wake::Unreachable(7)]);
}

#[test]
fn failure_follows_one_retrans_timer_after_the_last_request() {
    let mut cache = cache();
    cache.resolve(0, PEER_IP, 0, 7).unwrap();
    for now in [0, S, 2 * S] {
        submit(&mut cache, now).unwrap();
        assert_eq!(cache.next_deadline(), Some(now + S));
    }
    assert!(service(&mut cache, 3 * S - 1).is_empty());
    assert_eq!(cache.next_wake(|_| true), None);
    assert_eq!(
        service(&mut cache, 3 * S),
        [Event::Unreachable {
            link: 0,
            address: PEER_IP
        }]
    );
    assert_eq!(cache.next_deadline(), None);
    assert_eq!(wakes(&mut cache), [Wake::Unreachable(7)]);
    // A new resolution starts afresh.
    assert_eq!(cache.resolve(0, PEER_IP, 3 * S, 7), Ok(Resolution::Held));
    assert!(submit(&mut cache, 3 * S).is_some());
}

#[test]
fn capacity_errors_leave_no_state() {
    // A full held table: no entry is created.
    let mut cache = cache_with(ArpLimits {
        held: 1,
        ..limits()
    });
    cache.resolve(0, PEER_IP, 0, 1).unwrap();
    assert_eq!(cache.resolve(0, OTHER_IP, 0, 2), Err(Error::Capacity));
    assert_eq!(cache.entry(0, OTHER_IP), None);
    // A full entry table of pinned entries: no held record remains.
    let mut cache = cache_with(ArpLimits {
        entries: 1,
        ..limits()
    });
    cache.resolve(0, PEER_IP, 0, 1).unwrap();
    assert_eq!(cache.resolve(0, OTHER_IP, 0, 2), Err(Error::Capacity));
    assert_eq!(cache.entry(0, OTHER_IP), None);
    assert!(!cache.release(2));
    assert_eq!(cache.resolve(0, OTHER_IP, 0, 1), Ok(Resolution::Held));
    // Construction and registration bounds.
    assert!(cache.has_link(0) && !cache.has_link(1));
    assert!(cache.add_link(1, OTHER, &mut half).is_ok());
    assert!(cache.has_link(1));
    assert_eq!(cache.add_link(2, OTHER, &mut half), Err(Error::Capacity));
    assert_eq!(cache.add_link(1, OTHER, &mut half), Err(Error::Duplicate));
    assert_eq!(
        Cache::new(
            limits(),
            ArpTimers {
                broadcast_requests: 0,
                ..ArpTimers::default()
            },
            1000
        )
        .err(),
        Some(Error::Config)
    );
    assert_eq!(
        Cache::new(ArpLimits::default(), ArpTimers::default(), 0).err(),
        Some(Error::Config)
    );
    assert_eq!(
        Cache::new(
            ArpLimits {
                entries: usize::MAX,
                ..limits()
            },
            ArpTimers::default(),
            1000
        )
        .err(),
        Some(Error::Capacity)
    );
}

#[test]
fn unresolvable_targets_and_missing_sources_are_refused() {
    let mut cache = cache();
    for address in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(224, 0, 0, 1),
        LOCAL,
    ] {
        assert_eq!(cache.resolve(0, address, 0, 1), Err(Error::Address));
    }
    assert_eq!(cache.resolve(5, PEER_IP, 0, 1), Err(Error::UnknownLink));
    cache.add_link(1, OTHER, &mut half).unwrap();
    assert_eq!(cache.resolve(1, PEER_IP, 0, 1), Err(Error::NoSource));
    assert_eq!(cache.entry(1, PEER_IP), None);
    // Removing a link's last local address fails what it was resolving.
    cache.resolve(0, PEER_IP, 0, 1).unwrap();
    assert!(cache.remove_address(0, LOCAL));
    assert!(!cache.remove_address(0, LOCAL));
    assert_eq!(cache.entry(0, PEER_IP), None);
    assert_eq!(wakes(&mut cache), [Wake::Unreachable(1)]);
    assert_eq!(cache.counters().resolution_failures, 1);
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-2.3.2.1
//= type=test
//# An implementation of the Address Resolution Protocol (ARP)
//# [LINK:2] MUST provide a mechanism to flush out-of-date cache
//# entries.  If this mechanism involves a timeout, it SHOULD be
//# possible to configure the timeout value.
#[test]
fn reachable_ages_to_stale_then_delay_probe_and_reachable_again() {
    let mut cache = cache();
    reachable(&mut cache, 0);
    assert_eq!(cache.next_deadline(), Some(30 * S));
    service(&mut cache, 30 * S - 1);
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Reachable);
    service(&mut cache, 30 * S);
    assert_eq!(cache.entry(0, PEER_IP), Some((ArpState::Stale, Some(PEER))));
    assert_eq!(cache.next_deadline(), None);
    // Using a STALE entry returns its MAC at once and starts DELAY.
    assert_eq!(
        cache.resolve(0, PEER_IP, 40 * S, 1),
        Ok(Resolution::Ready(PEER))
    );
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Delay);
    assert_eq!(cache.next_deadline(), Some(45 * S));
    assert!(cache.next_control(0, 44 * S).is_none());
    service(&mut cache, 45 * S);
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Probe);
    // PROBE asks the cached MAC directly.
    let probe = submit(&mut cache, 45 * S).unwrap();
    assert_eq!(probe.destination, PEER);
    assert_eq!(probe.arp, request_from(MAC, LOCAL, PEER_IP));
    assert_eq!(
        cache.resolve(0, PEER_IP, 45 * S, 1),
        Ok(Resolution::Ready(PEER))
    );
    receive(&mut cache, reply_from(PEER, PEER_IP), 45 * S + 300);
    assert_eq!(
        cache.entry(0, PEER_IP),
        Some((ArpState::Reachable, Some(PEER)))
    );
    assert_eq!(cache.next_deadline(), Some(75 * S + 300));

    // Every timer is configurable, in caller units.
    let timers = ArpTimers {
        base_reachable_ms: 2_000,
        retrans_ms: 250,
        broadcast_requests: 1,
        unicast_probes: 1,
        delay_first_probe_ms: 500,
    };
    let mut cache = Cache::new(limits(), timers, 1_000_000).unwrap();
    assert_eq!(cache.timers(), timers);
    assert_eq!(cache.units_per_second(), 1_000_000);
    cache.add_link(0, MAC, &mut half).unwrap();
    cache.add_address(0, LOCAL, AddressKind::Local).unwrap();
    cache.resolve(0, PEER_IP, 0, 1).unwrap();
    submit(&mut cache, 0).unwrap();
    receive(&mut cache, reply_from(PEER, PEER_IP), 0);
    assert_eq!(cache.next_deadline(), Some(2_000_000));
    service(&mut cache, 2_000_000);
    cache.resolve(0, PEER_IP, 2_000_000, 1).unwrap();
    assert_eq!(cache.next_deadline(), Some(2_500_000));
    service(&mut cache, 2_500_000);
    submit(&mut cache, 2_500_000).unwrap();
    assert!(cache.next_control(0, 2_750_000).is_none());
    assert_eq!(service(&mut cache, 2_750_000).len(), 1);
    assert_eq!(cache.entry(0, PEER_IP), None);
}

#[test]
fn reachable_time_is_randomized_between_half_and_one_and_a_half_base() {
    for (draw, expiry) in [(0, 15 * S), (u32::MAX, 45 * S - 1), (1 << 30, 22_500)] {
        let mut cache = Cache::new(limits(), ArpTimers::default(), 1000).unwrap();
        cache.add_link(0, MAC, &mut || Some(draw)).unwrap();
        cache.add_address(0, LOCAL, AddressKind::Local).unwrap();
        cache.resolve(0, PEER_IP, 0, 1).unwrap();
        submit(&mut cache, 0).unwrap();
        cache
            .receive(0, &reply_from(PEER, PEER_IP), 0, &mut || Some(draw))
            .unwrap();
        assert_eq!(cache.next_deadline(), Some(expiry));
    }
}

//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//= reason=ntcp-arp implements the poll: after DELAY_FIRST_PROBE an unconfirmed entry sends up to ucast_solicit unicast requests to the cached Ethernet address, one RetransTimer apart, and is deleted one RetransTimer after the last without a reply; transmitting the polled requests is the embedding's, pending the ntcp-host/ntcp-native integration.
//# After a suitable time, the daemon considers removing an entry.
//# It first sends (with a small number of retransmissions if needed)
//# an address resolution packet with opcode REQUEST directly to the
//# Ethernet address in the table.  If a REPLY is not seen in a short
//# amount of time, the entry is deleted.  The request is sent
//# directly so as not to bother every station on the Ethernet.
#[test]
fn probe_fails_after_three_unicast_probes() {
    let mut cache = cache();
    reachable(&mut cache, 0);
    service(&mut cache, 30 * S);
    cache.resolve(0, PEER_IP, 30 * S, 1).unwrap();
    service(&mut cache, 35 * S);
    let mut probes = Vec::new();
    for now in (35 * S..=40 * S).step_by(250) {
        let events = service(&mut cache, now);
        if now == 38 * S {
            assert_eq!(
                events,
                [Event::Unreachable {
                    link: 0,
                    address: PEER_IP
                }]
            );
        } else {
            assert!(events.is_empty(), "{now}");
        }
        while let Some(probe) = submit(&mut cache, now) {
            assert_eq!(probe.destination, PEER);
            probes.push(now);
        }
    }
    assert_eq!(probes, [35 * S, 36 * S, 37 * S]);
    assert_eq!(cache.entry(0, PEER_IP), None);
    assert_eq!(cache.counters().resolution_failures, 1);
    // The next use resolves again by broadcast.
    assert_eq!(cache.resolve(0, PEER_IP, 40 * S, 1), Ok(Resolution::Held));
    assert_eq!(submit(&mut cache, 40 * S).unwrap().destination, [0xff; 6]);
}

#[test]
fn upper_layer_confirmation_short_circuits_probing() {
    let mut cache = cache();
    reachable(&mut cache, 0);
    service(&mut cache, 30 * S);
    cache.resolve(0, PEER_IP, 31 * S, 1).unwrap();
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Delay);
    // TCP forward progress during DELAY: back to REACHABLE, no probe.
    assert_eq!(
        cache.confirm(0, PEER_IP, 31 * S, 32 * S, &mut half),
        Ok(true)
    );
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Reachable);
    service(&mut cache, 36 * S);
    assert!(cache.next_control(0, 36 * S).is_none());
    assert_eq!(cache.next_deadline(), Some(62 * S));
    // STALE and PROBE are confirmed alike, without traffic.
    service(&mut cache, 62 * S);
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Stale);
    assert_eq!(
        cache.confirm(0, PEER_IP, 62 * S, 62 * S, &mut half),
        Ok(true)
    );
    service(&mut cache, 92 * S);
    cache.resolve(0, PEER_IP, 92 * S, 1).unwrap();
    service(&mut cache, 97 * S);
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Probe);
    assert_eq!(
        cache.confirm(0, PEER_IP, 97 * S, 97 * S, &mut half),
        Ok(true)
    );
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Reachable);
    assert!(cache.next_control(0, 97 * S).is_none());
    assert_eq!(cache.counters().requests_sent, 1);
    // A packet sent before the mapping changed confirms nothing.
    receive(&mut cache, request_from(OTHER, PEER_IP, OTHER_IP), 100 * S);
    assert_eq!(
        cache.entry(0, PEER_IP),
        Some((ArpState::Stale, Some(OTHER)))
    );
    assert_eq!(
        cache.confirm(0, PEER_IP, 99 * S, 101 * S, &mut half),
        Ok(false)
    );
    // Neither INCOMPLETE nor unknown entries are confirmed, and failed
    // entropy changes nothing.
    assert_eq!(cache.confirm(0, OTHER_IP, 0, 0, &mut half), Ok(false));
    cache.resolve(0, OTHER_IP, 101 * S, 2).unwrap();
    assert_eq!(
        cache.confirm(0, OTHER_IP, 101 * S, 101 * S, &mut half),
        Ok(false)
    );
    assert_eq!(
        cache.confirm(0, PEER_IP, 101 * S, 101 * S, &mut || None),
        Err(Error::Entropy)
    );
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Stale);
}

//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# Merge_flag := false
//# If the pair <protocol type, sender protocol address> is
//# already in my translation table, update the sender
//# hardware address field of the entry with the new
//# information in the packet and set Merge_flag to true.
//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//# Notice that the <protocol type, sender protocol address, sender
//# hardware address> triplet is merged into the table before the
//# opcode is looked at.
#[test]
fn cached_senders_are_merged_whatever_the_target_or_opcode() {
    let mut cache = cache();
    reachable(&mut cache, 0);
    // The same mapping, in a request for someone else: state kept.
    receive(&mut cache, request_from(PEER, PEER_IP, OTHER_IP), S);
    assert_eq!(
        cache.entry(0, PEER_IP),
        Some((ArpState::Reachable, Some(PEER)))
    );
    // A changed mapping in an unrelated request: updated, unconfirmed.
    receive(&mut cache, request_from(OTHER, PEER_IP, OTHER_IP), 2 * S);
    assert_eq!(
        cache.entry(0, PEER_IP),
        Some((ArpState::Stale, Some(OTHER)))
    );
    // A gratuitous reply (to nobody's request) updates it too, unconfirmed.
    let gratuitous = arp(Operation::Reply, (PEER, PEER_IP), ([0xff; 6], PEER_IP));
    receive(&mut cache, gratuitous, 3 * S);
    assert_eq!(cache.entry(0, PEER_IP), Some((ArpState::Stale, Some(PEER))));
    // An unsolicited reply to this node while DELAY is not a confirmation.
    cache.resolve(0, PEER_IP, 4 * S, 1).unwrap();
    receive(&mut cache, reply_from(PEER, PEER_IP), 4 * S);
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Delay);
    // An INCOMPLETE entry is resolved by any packet from its address, its
    // held output then ready.
    cache.resolve(0, OTHER_IP, 5 * S, 2).unwrap();
    submit(&mut cache, 5 * S).unwrap();
    let announce = request_from(OTHER, OTHER_IP, OTHER_IP);
    receive(&mut cache, announce, 5 * S);
    assert_eq!(
        cache.entry(0, OTHER_IP),
        Some((ArpState::Stale, Some(OTHER)))
    );
    assert_eq!(wakes(&mut cache), [Wake::Retry(2)]);
    assert!(cache.next_control(0, 10 * S).is_none());
}

#[test]
fn only_answers_to_this_nodes_requests_confirm() {
    let mut cache = cache();
    cache.resolve(0, PEER_IP, 0, 1).unwrap();
    submit(&mut cache, 0).unwrap();
    // A reply to another station's MAC or address is merged unconfirmed.
    let elsewhere = arp(Operation::Reply, (PEER, PEER_IP), (OTHER, LOCAL));
    receive(&mut cache, elsewhere, 100);
    assert_eq!(cache.entry(0, PEER_IP), Some((ArpState::Stale, Some(PEER))));
    let mut cache = cache_with(limits());
    cache.resolve(0, PEER_IP, 0, 1).unwrap();
    submit(&mut cache, 0).unwrap();
    // A failing entropy source leaves the entry unresolved.
    assert_eq!(
        cache.receive(0, &reply_from(PEER, PEER_IP), 100, &mut || None),
        Err(Error::Entropy)
    );
    assert_eq!(cache.entry(0, PEER_IP), Some((ArpState::Incomplete, None)));
    // A reply with a different MAC than before supersedes it, confirmed.
    receive(&mut cache, reply_from(OTHER, PEER_IP), 200);
    assert_eq!(
        cache.entry(0, PEER_IP),
        Some((ArpState::Reachable, Some(OTHER)))
    );
    assert_eq!(
        cache.receive(1, &reply_from(PEER, PEER_IP), 0, &mut half),
        Err(Error::UnknownLink)
    );
}

#[test]
fn requests_for_answered_addresses_add_their_sender_as_stale() {
    let mut cache = cache();
    receive(&mut cache, request_from(PEER, PEER_IP, LOCAL), 0);
    assert_eq!(cache.entry(0, PEER_IP), Some((ArpState::Stale, Some(PEER))));
    // An uncached sender's reply or announcement adds nothing.
    receive(&mut cache, reply_from(OTHER, OTHER_IP), 0);
    receive(&mut cache, request_from(OTHER, OTHER_IP, OTHER_IP), 0);
    let announce = arp(Operation::Reply, (OTHER, OTHER_IP), ([0xff; 6], OTHER_IP));
    receive(&mut cache, announce, 0);
    assert_eq!(cache.entry(0, OTHER_IP), None);
    // Nor does a request for an address this node does not answer.
    receive(&mut cache, request_from(OTHER, OTHER_IP, PEER_IP), 0);
    assert_eq!(cache.entry(0, OTHER_IP), None);
}

#[test]
fn unlearnable_senders_are_never_learned() {
    let mut cache = cache();
    // RFC 5227 probe for a local address: answered to the prober's MAC,
    // nothing learned.
    receive(
        &mut cache,
        request_from(PEER, Ipv4Addr::UNSPECIFIED, LOCAL),
        0,
    );
    assert_eq!(cache.entry(0, Ipv4Addr::UNSPECIFIED), None);
    let answer = submit(&mut cache, 0).unwrap();
    assert_eq!(answer.destination, PEER);
    assert_eq!(
        answer.arp,
        arp(
            Operation::Reply,
            (MAC, LOCAL),
            (PEER, Ipv4Addr::UNSPECIFIED)
        )
    );
    // Group sender MACs and addresses: no entry, no answer.
    for (mac, ip) in [
        ([0xff; 6], PEER_IP),
        ([0x01, 0, 0x5e, 0, 0, 1], PEER_IP),
        (PEER, Ipv4Addr::BROADCAST),
        (PEER, Ipv4Addr::new(224, 0, 0, 1)),
    ] {
        receive(&mut cache, request_from(mac, ip, LOCAL), 0);
        assert_eq!(cache.entry(0, ip), None);
    }
    assert!(cache.next_control(0, 0).is_none());
    // Another station claiming the local address: counted, not learned,
    // not answered; this link's own looped-back request is neither.
    receive(&mut cache, request_from(PEER, LOCAL, LOCAL), 0);
    receive(&mut cache, reply_from(PEER, LOCAL), 0);
    receive(&mut cache, request_from(MAC, LOCAL, PEER_IP), 0);
    assert_eq!(cache.counters().conflicts, 2);
    assert_eq!(cache.entry(0, LOCAL), None);
    assert!(cache.next_control(0, 0).is_none());
    // A published address is never learned either, and not a conflict.
    cache
        .add_address(0, PROXY_IP, AddressKind::Published(PUBLISHED))
        .unwrap();
    receive(&mut cache, request_from(PEER, PROXY_IP, LOCAL), 0);
    assert_eq!(cache.entry(0, PROXY_IP), None);
    assert_eq!(cache.counters().conflicts, 2);
    assert!(cache.next_control(0, 0).is_none());
}

//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//= type=test
//= reason=ntcp-arp builds the reply (fields swapped, local hardware and protocol addresses as sender, ar$op REPLY) and next_control yields it for the receiving link, unicast to the requester's sender hardware address; transmitting it on that link is the embedding's, pending the ntcp-host/ntcp-native integration.
//# ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
//# Yes:
//# Swap hardware and protocol fields, putting the local
//# hardware and protocol addresses in the sender fields.
//# Set the ar$op field to ares_op$REPLY
//# Send the packet to the (new) target hardware address on
//# the same hardware on which the request was received.
#[test]
fn requests_for_local_and_published_addresses_are_answered_unicast() {
    let mut cache = cache();
    cache.add_link(1, OTHER, &mut half).unwrap();
    cache
        .add_address(0, PROXY_IP, AddressKind::Published(PUBLISHED))
        .unwrap();
    receive(&mut cache, request_from(PEER, PEER_IP, LOCAL), 0);
    let local = submit(&mut cache, 0).unwrap();
    assert_eq!(
        (local.link, local.source, local.destination),
        (0, MAC, PEER)
    );
    assert_eq!(
        local.arp,
        arp(Operation::Reply, (MAC, LOCAL), (PEER, PEER_IP))
    );
    let mut frame = [0; 60];
    local.encode(&mut frame).unwrap();
    assert_eq!(ntcp_arp::parse_frame(&frame), Ok((PEER, MAC, local.arp)));
    // A published address is answered with its MAC, from the link's.
    receive(&mut cache, request_from(PEER, PEER_IP, PROXY_IP), 0);
    let proxy = submit(&mut cache, 0).unwrap();
    assert_eq!((proxy.source, proxy.destination), (MAC, PEER));
    assert_eq!(
        proxy.arp,
        arp(Operation::Reply, (PUBLISHED, PROXY_IP), (PEER, PEER_IP))
    );
    assert_eq!(cache.counters().replies_sent, 2);
    // Requests for other addresses, replies, and requests for this link's
    // addresses arriving on another link are not answered.
    receive(&mut cache, request_from(PEER, PEER_IP, OTHER_IP), 0);
    receive(&mut cache, reply_from(PEER, PEER_IP), 0);
    cache
        .receive(1, &request_from(PEER, PEER_IP, LOCAL), 0, &mut half)
        .unwrap();
    assert!(cache.next_control(0, 0).is_none());
    assert!(cache.next_control(1, 0).is_none());
    // A published address is not defended against RFC 5227 probes, and
    // is not a source.
    receive(
        &mut cache,
        request_from(PEER, Ipv4Addr::UNSPECIFIED, PROXY_IP),
        0,
    );
    assert!(cache.next_control(0, 0).is_none());
    assert_eq!(cache.resolve(0, PROXY_IP, 0, 1), Err(Error::Address));
    assert_eq!(
        cache.add_address(0, PROXY_IP, AddressKind::Local),
        Err(Error::Duplicate)
    );
    assert_eq!(
        cache.add_address(0, Ipv4Addr::BROADCAST, AddressKind::Local),
        Err(Error::Address)
    );
    assert_eq!(
        cache.add_address(3, PEER_IP, AddressKind::Local),
        Err(Error::UnknownLink)
    );
}

#[test]
fn permanent_entries_are_never_overwritten_or_evicted() {
    let mut cache = cache_with(ArpLimits {
        entries: 2,
        ..limits()
    });
    cache.add_permanent(0, PEER_IP, PEER, 0).unwrap();
    assert_eq!(cache.resolve(0, PEER_IP, 0, 1), Ok(Resolution::Ready(PEER)));
    receive(&mut cache, request_from(OTHER, PEER_IP, LOCAL), S);
    receive(&mut cache, reply_from(OTHER, PEER_IP), S);
    assert_eq!(
        cache.entry(0, PEER_IP),
        Some((ArpState::Permanent, Some(PEER)))
    );
    // Still answered, though not learned from.
    assert_eq!(submit(&mut cache, S).unwrap().destination, OTHER);
    assert_eq!(cache.confirm(0, PEER_IP, S, S, &mut half), Ok(false));
    service(&mut cache, 1_000_000 * S);
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Permanent);
    assert_eq!(cache.next_deadline(), None);
    // Not reclaimed: with one STALE entry taken, a new resolution needs
    // the STALE one, and then there is none.
    receive(&mut cache, request_from(OTHER, OTHER_IP, LOCAL), 2 * S);
    submit(&mut cache, 2 * S).unwrap();
    let third = Ipv4Addr::new(192, 0, 2, 4);
    assert_eq!(cache.resolve(0, third, 3 * S, 2), Ok(Resolution::Held));
    assert_eq!(cache.entry(0, OTHER_IP), None);
    let fourth = Ipv4Addr::new(192, 0, 2, 5);
    assert_eq!(cache.resolve(0, fourth, 3 * S, 3), Err(Error::Capacity));
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Permanent);
    // A permanent entry replaces a dynamic one in place, readying it.
    cache.add_permanent(0, third, OTHER, 4 * S).unwrap();
    assert_eq!(wakes(&mut cache), [Wake::Retry(2)]);
    assert_eq!(cache.add_permanent(0, LOCAL, OTHER, 0), Err(Error::Address));
    assert_eq!(
        cache.add_permanent(0, fourth, [0xff; 6], 0),
        Err(Error::Address)
    );
    assert_eq!(
        cache.add_permanent(0, fourth, OTHER, 0),
        Err(Error::Capacity)
    );
    assert!(cache.remove_entry(0, PEER_IP));
    assert!(!cache.remove_entry(0, PEER_IP));
    assert_eq!(cache.entry(0, PEER_IP), None);
}

#[test]
fn reclaim_takes_the_least_recently_used_idle_stale_entry() {
    let mut cache = cache_with(ArpLimits {
        entries: 3,
        ..limits()
    });
    let a = Ipv4Addr::new(192, 0, 2, 10);
    let b = Ipv4Addr::new(192, 0, 2, 11);
    let c = Ipv4Addr::new(192, 0, 2, 12);
    let d = Ipv4Addr::new(192, 0, 2, 13);
    let e = Ipv4Addr::new(192, 0, 2, 14);
    for (i, ip) in [a, b, c].into_iter().enumerate() {
        let mac = [2, 0, 0, 0, 1, i as u8];
        receive(&mut cache, request_from(mac, ip, LOCAL), i as u64 * S);
        submit(&mut cache, 0);
    }
    // `a` is used (now DELAY, pinned), so `b` is the oldest idle entry.
    assert!(matches!(
        cache.resolve(0, a, 5 * S, 1),
        Ok(Resolution::Ready(_))
    ));
    assert_eq!(cache.resolve(0, d, 6 * S, 2), Ok(Resolution::Held));
    assert_eq!(cache.entry(0, b), None);
    assert!(cache.entry(0, c).is_some());
    // INCOMPLETE `d`, DELAY `a`: only `c` is reclaimable.
    assert_eq!(cache.resolve(0, e, 7 * S, 3), Ok(Resolution::Held));
    assert_eq!(cache.entry(0, c), None);
    assert_eq!(cache.resolve(0, b, 7 * S, 4), Err(Error::Capacity));
    // A STALE entry still owing held output is pinned too: `e` resolves
    // unconfirmed (STALE) but its owner has not yet been woken.
    receive(&mut cache, request_from(OTHER, e, LOCAL), 8 * S);
    assert_eq!(cache.entry(0, e).unwrap().0, ArpState::Stale);
    receive(&mut cache, request_from(PEER, PEER_IP, LOCAL), 8 * S);
    assert_eq!(cache.entry(0, PEER_IP), None);
    assert_eq!(cache.next_wake(|tag| *tag == 3), Some(Wake::Retry(3)));
    receive(&mut cache, request_from(PEER, PEER_IP, LOCAL), 9 * S);
    assert_eq!(cache.entry(0, e), None);
    assert!(cache.entry(0, PEER_IP).is_some());
    assert!(cache.entry(0, d).is_some());
}

#[test]
fn reply_queue_overflow_is_counted_and_retransmissions_coalesce() {
    let mut cache = cache();
    receive(&mut cache, request_from(PEER, PEER_IP, LOCAL), 0);
    receive(&mut cache, request_from(PEER, PEER_IP, LOCAL), 0);
    receive(&mut cache, request_from(OTHER, OTHER_IP, LOCAL), 0);
    assert_eq!(cache.counters().replies_dropped, 0);
    let third = Ipv4Addr::new(192, 0, 2, 4);
    receive(
        &mut cache,
        request_from([2, 0, 0, 0, 0, 4], third, LOCAL),
        0,
    );
    assert_eq!(cache.counters().replies_dropped, 1);
    assert_eq!(cache.next_deadline(), Some(0));
    assert_eq!(submit(&mut cache, 0).unwrap().destination, PEER);
    assert_eq!(submit(&mut cache, 0).unwrap().destination, OTHER);
    assert!(cache.next_control(0, 0).is_none());
    assert_eq!(cache.counters().replies_sent, 2);
}

#[test]
fn blocked_and_failed_outcomes_consume_nothing() {
    let mut cache = cache();
    cache.resolve(0, PEER_IP, 0, 1).unwrap();
    // Blocked and Failed leave the request due, unspaced and uncounted.
    for outcome in [ControlOutcome::Blocked, ControlOutcome::Failed] {
        send(&mut cache, 0, outcome).unwrap();
        assert!(cache.next_control(0, 0).is_some());
        assert_eq!(cache.next_deadline(), Some(0));
    }
    assert_eq!(cache.counters().requests_sent, 0);
    // Uncertain consumes an attempt and spaces the next like Submitted.
    send(&mut cache, 0, ControlOutcome::Uncertain).unwrap();
    assert!(cache.next_control(0, S - 1).is_none());
    send(&mut cache, S, ControlOutcome::Submitted).unwrap();
    assert_eq!(cache.counters().requests_sent, 2);
    // A stale token completes nothing.
    let (_, token) = cache.next_control(0, 2 * S).unwrap();
    receive(&mut cache, reply_from(PEER, PEER_IP), 2 * S);
    cache.complete(token, ControlOutcome::Submitted, 2 * S);
    assert_eq!(cache.counters().requests_sent, 2);
    // A blocked reply stays queued; a failed one ends, counted dropped.
    receive(&mut cache, request_from(OTHER, OTHER_IP, LOCAL), 3 * S);
    send(&mut cache, 3 * S, ControlOutcome::Blocked).unwrap();
    send(&mut cache, 3 * S, ControlOutcome::Failed).unwrap();
    assert!(cache.next_control(0, 3 * S).is_none());
    assert_eq!(cache.counters().replies_dropped, 1);
    assert_eq!(cache.counters().replies_sent, 0);
    receive(&mut cache, request_from(OTHER, OTHER_IP, LOCAL), 4 * S);
    send(&mut cache, 4 * S, ControlOutcome::Uncertain).unwrap();
    assert_eq!(cache.counters().replies_sent, 1);
}

#[test]
fn time_running_backwards_delays_timers_but_never_fires_them_early() {
    let mut cache = cache();
    cache.resolve(0, PEER_IP, 10 * S, 1).unwrap();
    submit(&mut cache, 10 * S).unwrap();
    // Earlier time: the next request is not due, nothing fails.
    assert!(cache.next_control(0, 5 * S).is_none());
    assert!(service(&mut cache, 5 * S).is_empty());
    assert!(cache.next_control(0, 11 * S - 1).is_none());
    submit(&mut cache, 11 * S).unwrap();
    // Completing at an earlier time spaces from that time: the clock's own
    // order, never sooner than one RetransTimer after the completion.
    submit(&mut cache, 12 * S).unwrap();
    assert!(service(&mut cache, 12 * S).is_empty());
    receive(&mut cache, reply_from(PEER, PEER_IP), 12 * S);
    assert_eq!(cache.next_deadline(), Some(42 * S));
    // REACHABLE expiry is measured from the reply, whatever came before.
    assert!(service(&mut cache, 41 * S).is_empty());
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Reachable);
    service(&mut cache, 42 * S);
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Stale);
    // DELAY started at a later time is not ended by an earlier one.
    cache.resolve(0, PEER_IP, 50 * S, 1).unwrap();
    service(&mut cache, 45 * S);
    service(&mut cache, 54 * S);
    assert_eq!(cache.entry(0, PEER_IP).unwrap().0, ArpState::Delay);
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-2.3.2.2
//= type=test
//= reason=ntcp-arp records one held tag per owner while its next hop is unresolved and reports Wake::Retry once resolved (Wake::Unreachable on failure); the embedding keeps the owner's latest frame in its one transmit slot and retransmits it on Retry. Keeping and resending the frame belongs to the ntcp-host/ntcp-native integration, which is pending.
//# The link layer SHOULD save (rather than discard) at least
//# one (the latest) packet of each set of packets destined to
//# the same unresolved IP address, and transmit the saved
//# packet when the address has been resolved.
#[test]
fn held_owners_are_told_to_retry_once_resolved() {
    let mut cache = cache();
    for tag in [1, 2, 3] {
        assert_eq!(cache.resolve(0, PEER_IP, 0, tag), Ok(Resolution::Held));
    }
    submit(&mut cache, 0).unwrap();
    receive(&mut cache, reply_from(PEER, PEER_IP), 0);
    assert_eq!(
        wakes(&mut cache),
        [Wake::Retry(1), Wake::Retry(2), Wake::Retry(3)]
    );
    for tag in [1, 2, 3] {
        assert_eq!(
            cache.resolve(0, PEER_IP, 0, tag),
            Ok(Resolution::Ready(PEER))
        );
    }
    // Removing a link fails what it held.
    cache.resolve(0, OTHER_IP, 0, 4).unwrap();
    cache.remove_link(0);
    assert_eq!(wakes(&mut cache), [Wake::Unreachable(4)]);
    assert_eq!(cache.next_deadline(), None);
    assert_eq!(cache.resolve(0, PEER_IP, 0, 1), Err(Error::UnknownLink));
}

// A link without a local address can send no request. Its due entries fail
// instead of keeping an unvalidated mapping in use and a deadline that is
// always due.
#[test]
fn validation_fails_once_the_last_local_address_is_gone() {
    let mut cache = cache();
    reachable(&mut cache, 0);
    assert!(cache.remove_address(0, LOCAL));
    assert!(service(&mut cache, 30 * S).is_empty());
    assert_eq!(
        cache.resolve(0, PEER_IP, 31 * S, 1),
        Ok(Resolution::Ready(PEER))
    );
    assert_eq!(cache.entry(0, PEER_IP), Some((ArpState::Delay, Some(PEER))));
    assert_eq!(cache.next_deadline(), Some(36 * S));
    assert_eq!(
        service(&mut cache, 36 * S),
        [Event::Unreachable {
            link: 0,
            address: PEER_IP
        }]
    );
    assert_eq!(cache.entry(0, PEER_IP), None);
    assert_eq!(cache.next_deadline(), None);
    assert_eq!(cache.counters().resolution_failures, 1);
    assert_eq!(cache.resolve(0, PEER_IP, 36 * S, 1), Err(Error::NoSource));
}

// The same for a link that only publishes addresses but learned a
// requester.
#[test]
fn a_publishing_only_link_fails_validation_instead_of_stalling() {
    let mut proxy = cache();
    let proxy_mac = [2, 0, 0, 0, 0, 4];
    proxy.add_link(1, proxy_mac, &mut half).unwrap();
    proxy
        .add_address(1, PROXY_IP, AddressKind::Published(PUBLISHED))
        .unwrap();
    let request = request_from(PEER, PEER_IP, PROXY_IP);
    proxy.receive(1, &request, 0, &mut half).unwrap();
    let (reply, token) = proxy.next_control(1, 0).unwrap();
    assert_eq!(reply.arp.sender_mac, PUBLISHED);
    proxy.complete(token, ControlOutcome::Submitted, 0);
    assert_eq!(proxy.entry(1, PEER_IP), Some((ArpState::Stale, Some(PEER))));
    assert_eq!(proxy.resolve(1, PEER_IP, S, 1), Ok(Resolution::Ready(PEER)));
    assert_eq!(
        service(&mut proxy, 6 * S),
        [Event::Unreachable {
            link: 1,
            address: PEER_IP
        }]
    );
    assert_eq!(proxy.next_deadline(), None);
    assert!(proxy.next_control(1, 6 * S).is_none());
}
