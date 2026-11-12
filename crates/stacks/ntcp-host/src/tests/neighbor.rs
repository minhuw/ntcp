// The neighbor cache and DAD state machine against RFC 4861 sections 7.2.3,
// 7.2.5, 7.3.3 and RFC 4862 section 5.4, driven with caller time in
// microseconds.
use super::*;
use crate::neighbor::*;
use alloc::boxed::Box;
use core::net::Ipv6Addr;

const SECOND: u64 = 1_000_000;
const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 0xa];
const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 0xb];
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];

fn link() -> LinkId {
    let mut paths = PathService::new(
        ContextId::new(1),
        path::Limits {
            links: 1,
            sources: 1,
            source_owners: 1,
            routes: 1,
            paths: 1,
            clients: 1,
        },
        [1; 16],
    )
    .unwrap();
    paths.register_link(InterfaceKey(1), 1500).unwrap()
}
fn neighbor() -> Ipv6Addr {
    "fe80::a".parse().unwrap()
}
fn own() -> Ipv6Addr {
    "fe80::1".parse().unwrap()
}
// Entropy whose every draw starts with `value` and continues with zeros:
// 0x80 gives exactly the base, and half the maximum DAD delay.
fn fixed(value: u8) -> Entropy {
    Box::new(move |out: &mut [u8]| {
        out.fill(0);
        out[0] = value;
        Ok(())
    })
}
fn limits(entries: usize, pending: usize) -> NeighborLimits {
    NeighborLimits {
        entries,
        pending_packets: pending,
        addresses: 2,
        answers: 2,
    }
}
// A cache with one port whose address `own()` is assigned (DAD disabled).
fn cache(entries: usize, pending: usize) -> (Neighbors<u32>, LinkId, Entropy) {
    let mut entropy = fixed(0x80);
    let mut cache = Neighbors::new(limits(entries, pending), 1, SECOND).unwrap();
    let link = link();
    let port = NdPort {
        dad_transmits: 0,
        ..NdPort::new(OWN)
    };
    cache.add_port(link, port, Some(&mut entropy)).unwrap();
    assert_eq!(cache.add_address(link, own()), Ok(AddressState::Assigned));
    (cache, link, entropy)
}
fn na(solicited: bool, override_: bool, mac: Option<[u8; 6]>) -> ntcp_icmp::NeighborAdvertisement {
    ntcp_icmp::NeighborAdvertisement {
        router: false,
        solicited,
        override_,
        target: neighbor(),
        target_link_layer: mac,
    }
}
fn no_events(_: NdEvent) {
    panic!("unexpected DAD event")
}

#[test]
fn resolution_holds_packets_and_counts_only_submitted_solicitations() {
    let (mut cache, link, mut entropy) = cache(1, 1);
    assert_eq!(cache.output(link, neighbor(), 0, 7), Ok(Resolution::Held));
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Incomplete
    );
    // A retried held attempt keeps its one slot; the slot is taken, so
    // other output is backpressure.
    assert_eq!(cache.output(link, neighbor(), 0, 7), Ok(Resolution::Held));
    assert_eq!(cache.output(link, neighbor(), 0, 8), Err(Error::Capacity));
    let (control, token) = cache.next_control(link, 0).unwrap();
    assert_eq!(
        control,
        Control::Solicit {
            link,
            target: neighbor(),
            destination: Destination::Multicast,
            dad: false,
        }
    );
    // Neither a blocked nor a failed local submission is an attempt.
    cache.complete(token, ControlOutcome::Blocked, 0);
    let (_, token) = cache.next_control(link, 0).unwrap();
    cache.complete(token, ControlOutcome::Failed, 0);
    let mut now = 0;
    for _ in 0..3 {
        let (_, token) = cache.next_control(link, now).unwrap();
        cache.complete(token, ControlOutcome::Submitted, now);
        // The next one waits a full RetransTimer.
        assert_eq!(cache.next_control(link, now + SECOND - 1), None);
        now += SECOND;
    }
    // After the third, failure only a full RetransTimer later.
    assert_eq!(cache.next_control(link, now), None);
    cache.service(now - 1, &mut no_events);
    assert!(cache.state(link, neighbor()).is_some());
    let mut events = Vec::new();
    cache.service(now, &mut |event| events.push(event));
    assert_eq!(cache.state(link, neighbor()), None);
    // The failure is reported: what forwarded through it ends.
    assert_eq!(
        events,
        [NdEvent::Unreachable {
            link,
            address: neighbor()
        }]
    );
    // The held attempt fails, never having been transmitted.
    let (slot, tag, mac) = cache.next_pending(|_| true).unwrap();
    assert_eq!((tag, mac), (7, None));
    cache.release(slot);
    assert!(cache.next_pending(|_| true).is_none());
    // An NA after failure finds no entry.
    assert_eq!(
        cache.advertisement(
            link,
            na(true, true, Some(MAC_A)),
            now,
            Some(&mut entropy),
            &mut no_events
        ),
        Ok(NaBranch::NoEntry)
    );
}

#[test]
fn exhausted_storage_never_leaves_an_unserviceable_entry() {
    // No pending storage: nothing is created.
    let (mut c, link, _) = cache(1, 0);
    assert_eq!(c.output(link, neighbor(), 0, 1), Err(Error::Capacity));
    assert_eq!(c.state(link, neighbor()), None);
    // No free entry: the reserved slot is not consumed.
    let (mut c, link, _) = cache(1, 2);
    let other: Ipv6Addr = "fe80::b".parse().unwrap();
    assert_eq!(c.output(link, other, 0, 1), Ok(Resolution::Held));
    assert_eq!(c.output(link, neighbor(), 0, 2), Err(Error::Capacity));
    assert_eq!(c.state(link, neighbor()), None);
    assert_eq!(c.output(link, other, 0, 3), Ok(Resolution::Held));
}

#[test]
fn idle_stale_entries_are_reclaimed_and_active_ones_pinned() {
    let (mut c, link, _) = cache(2, 3);
    let [a, b, d, e, f]: [Ipv6Addr; 5] =
        ["fe80::a", "fe80::b", "fe80::d", "fe80::e", "fe80::f"].map(|s| s.parse().unwrap());
    let ns = |mac| ntcp_icmp::NeighborSolicitation {
        target: own(),
        source_link_layer: Some(mac),
    };
    // Peers' solicitations fill the cache with STALE entries.
    c.solicitation(link, a, ns(MAC_A), 0, &mut no_events)
        .unwrap();
    c.solicitation(link, b, ns(MAC_B), 1, &mut no_events)
        .unwrap();
    // A new resolution still gets an entry: the one STALE the longest goes.
    assert_eq!(c.output(link, d, 2, 1), Ok(Resolution::Held));
    assert_eq!(c.state(link, a), None);
    assert_eq!(c.state(link, d).unwrap().0, NeighborState::Incomplete);
    assert_eq!(c.output(link, e, 3, 2), Ok(Resolution::Held));
    assert_eq!(c.state(link, b), None);
    // Active entries are pinned: exhaustion is backpressure leaving no
    // entry, and nothing is learned.
    assert_eq!(c.output(link, f, 4, 3), Err(Error::Capacity));
    assert_eq!(c.state(link, f), None);
    c.solicitation(link, a, ns(MAC_A), 4, &mut no_events)
        .unwrap();
    assert_eq!(c.state(link, a), None);
    // A STALE entry still owing held output is not reclaimed.
    c.advertisement(
        link,
        ntcp_icmp::NeighborAdvertisement {
            target: d,
            ..na(false, false, Some(MAC_A))
        },
        5,
        None,
        &mut no_events,
    )
    .unwrap();
    assert_eq!(c.state(link, d).unwrap().0, NeighborState::Stale);
    assert_eq!(c.output(link, f, 6, 3), Err(Error::Capacity));
    let (slot, tag, mac) = c.next_pending(|_| true).unwrap();
    assert_eq!((tag, mac), (1, Some(MAC_A)));
    c.release(slot);
    assert_eq!(c.output(link, f, 7, 3), Ok(Resolution::Held));
    assert_eq!(c.state(link, d), None);
}

#[test]
fn one_ports_blocked_control_output_never_holds_back_another() {
    let mut paths = PathService::new(
        ContextId::new(1),
        path::Limits {
            links: 2,
            sources: 1,
            source_owners: 1,
            routes: 1,
            paths: 1,
            clients: 1,
        },
        [1; 16],
    )
    .unwrap();
    let a = paths.register_link(InterfaceKey(1), 1500).unwrap();
    let b = paths.register_link(InterfaceKey(2), 1500).unwrap();
    let mut entropy = fixed(0x80);
    let mut c = Neighbors::new(limits(2, 1), 2, SECOND).unwrap();
    for link in [a, b] {
        let port = NdPort {
            dad_transmits: 0,
            ..NdPort::new(OWN)
        };
        c.add_port(link, port, Some(&mut entropy)).unwrap();
        assert_eq!(c.add_address(link, own()), Ok(AddressState::Assigned));
    }
    // A's answer is queued and its transmit path blocks; B resolves.
    let ns = ntcp_icmp::NeighborSolicitation {
        target: own(),
        source_link_layer: Some(MAC_A),
    };
    c.solicitation(a, neighbor(), ns, 0, &mut no_events)
        .unwrap();
    assert_eq!(c.output(b, neighbor(), 0, 1), Ok(Resolution::Held));
    let (control, token) = c.next_control(a, 0).unwrap();
    assert!(matches!(control, Control::Advertise { link, .. } if link == a));
    c.complete(token, ControlOutcome::Blocked, 0);
    assert!(c.next_control(a, 0).is_some());
    let (control, token) = c.next_control(b, 0).unwrap();
    assert_eq!(
        control,
        Control::Solicit {
            link: b,
            target: neighbor(),
            destination: Destination::Multicast,
            dad: false,
        }
    );
    c.complete(token, ControlOutcome::Submitted, 0);
    assert_eq!(c.next_control(b, 0), None);
}

#[test]
fn solicitations_for_foreign_targets_are_discarded_before_the_cache() {
    let (mut c, link, _) = cache(2, 1);
    let [a, b, d]: [Ipv6Addr; 3] = ["fe80::a", "fe80::b", "fe80::d"].map(|s| s.parse().unwrap());
    let ns = |target, mac| ntcp_icmp::NeighborSolicitation {
        target,
        source_link_layer: Some(mac),
    };
    c.solicitation(link, a, ns(own(), MAC_A), 0, &mut no_events)
        .unwrap();
    c.solicitation(link, b, ns(own(), MAC_B), 1, &mut no_events)
        .unwrap();
    // A target this port does not own (RFC 4861 section 7.2.3): no entry
    // is created, none reclaimed or updated, and nothing is answered.
    let foreign: Ipv6Addr = "fe80::dead".parse().unwrap();
    c.solicitation(link, d, ns(foreign, MAC_A), 2, &mut no_events)
        .unwrap();
    c.solicitation(link, a, ns(foreign, MAC_B), 3, &mut no_events)
        .unwrap();
    assert_eq!(c.state(link, d), None);
    assert_eq!(
        c.state(link, a),
        Some((NeighborState::Stale, Some(MAC_A), false))
    );
    assert_eq!(
        c.state(link, b),
        Some((NeighborState::Stale, Some(MAC_B), false))
    );
    let mut answers = 0;
    while let Some((control, token)) = c.next_control(link, 3) {
        assert!(matches!(control, Control::Advertise { target, .. } if target == own()));
        c.complete(token, ControlOutcome::Submitted, 3);
        answers += 1;
    }
    assert_eq!(answers, 2);
}

#[test]
fn reachability_timers_follow_caller_time() {
    let (mut cache, link, mut entropy) = cache(1, 1);
    cache.output(link, neighbor(), 0, 1).unwrap();
    let (_, token) = cache.next_control(link, 0).unwrap();
    cache.complete(token, ControlOutcome::Submitted, 0);
    assert_eq!(
        cache.advertisement(
            link,
            na(true, false, Some(MAC_A)),
            10,
            Some(&mut entropy),
            &mut no_events
        ),
        Ok(NaBranch::IncompleteSolicited)
    );
    // The held packet is released at the learned address.
    let (slot, _, mac) = cache.next_pending(|_| true).unwrap();
    assert_eq!(mac, Some(MAC_A));
    cache.release(slot);
    // ReachableTime equals BaseReachableTime (30 s) with this entropy.
    let reachable = 10 + 30 * SECOND;
    cache.service(reachable - 1, &mut no_events);
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Reachable
    );
    cache.service(reachable, &mut no_events);
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Stale
    );
    // STALE keeps sending at the cached address and enters DELAY.
    assert_eq!(
        cache.output(link, neighbor(), reachable, 2),
        Ok(Resolution::Ready(MAC_A))
    );
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Delay
    );
    assert_eq!(cache.next_deadline(), Some(reachable + 5 * SECOND));
    cache.service(reachable + 5 * SECOND, &mut no_events);
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Probe
    );
    // PROBE still sends at the cached address; probes are unicast.
    let probe = reachable + 5 * SECOND;
    assert_eq!(
        cache.output(link, neighbor(), probe, 3),
        Ok(Resolution::Ready(MAC_A))
    );
    let (control, _) = cache.next_control(link, probe).unwrap();
    assert!(matches!(
        control,
        Control::Solicit {
            destination: Destination::Unicast(MAC_A),
            ..
        }
    ));
    // Forward progress by a packet sent since the mapping was learned (at
    // 10) makes it REACHABLE; one sent before went elsewhere and confirms
    // nothing.
    assert_eq!(
        cache.confirm(link, neighbor(), 9, probe, Some(&mut entropy)),
        Ok(false)
    );
    assert_eq!(
        cache.confirm(link, neighbor(), 10, probe, Some(&mut entropy)),
        Ok(true)
    );
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Reachable
    );
}

#[test]
fn probes_exhausted_remove_the_entry() {
    let (mut cache, link, mut entropy) = cache(1, 1);
    cache.output(link, neighbor(), 0, 1).unwrap();
    cache
        .advertisement(
            link,
            na(false, false, Some(MAC_A)),
            0,
            Some(&mut entropy),
            &mut no_events,
        )
        .unwrap();
    let (slot, ..) = cache.next_pending(|_| true).unwrap();
    cache.release(slot);
    cache.output(link, neighbor(), 0, 2).unwrap();
    cache.service(5 * SECOND, &mut no_events);
    let mut now = 5 * SECOND;
    for _ in 0..3 {
        let (_, token) = cache.next_control(link, now).unwrap();
        cache.complete(token, ControlOutcome::Submitted, now);
        now += SECOND;
    }
    cache.service(now - 1, &mut no_events);
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Probe
    );
    // Unsolicited advertisements leaving the mapping unchanged confirm
    // nothing: no probe is re-armed and failure is not postponed.
    for advertisement in [
        na(false, false, None),
        na(false, false, Some(MAC_A)),
        na(false, true, Some(MAC_A)),
    ] {
        assert_eq!(
            cache.advertisement(link, advertisement, now - 1, None, &mut no_events),
            Ok(NaBranch::UpdatedUnchanged)
        );
        assert_eq!(cache.next_control(link, now - 1), None);
    }
    let mut events = Vec::new();
    cache.service(now, &mut |event| events.push(event));
    assert_eq!(cache.state(link, neighbor()), None);
    assert_eq!(
        events,
        [NdEvent::Unreachable {
            link,
            address: neighbor()
        }]
    );
}

#[test]
fn entropy_failure_is_explicit_and_changes_nothing() {
    let (mut cache, link, _) = cache(1, 1);
    cache.output(link, neighbor(), 0, 1).unwrap();
    let mut failing: Entropy = Box::new(|_: &mut [u8]| Err(EntropyError));
    assert_eq!(
        cache.advertisement(
            link,
            na(true, true, Some(MAC_A)),
            0,
            Some(&mut failing),
            &mut no_events
        ),
        Err(Error::Entropy)
    );
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Incomplete
    );
    assert_eq!(
        cache.advertisement(link, na(true, true, Some(MAC_A)), 0, None, &mut no_events),
        Err(Error::Entropy)
    );
    // An unsolicited advertisement needs no new ReachableTime.
    assert_eq!(
        cache.advertisement(link, na(false, true, Some(MAC_A)), 0, None, &mut no_events),
        Ok(NaBranch::IncompleteUnsolicited)
    );
}

#[test]
fn reachable_time_is_uniform_between_half_and_one_and_a_half_base() {
    let ones: fn() -> Entropy = || {
        Box::new(|out: &mut [u8]| {
            out.fill(0xff);
            Ok(())
        })
    };
    for (mut entropy, expected) in [
        (fixed(0), 15 * SECOND),
        (fixed(0x80), 30 * SECOND),
        (ones(), 45 * SECOND - 1),
    ] {
        let (mut c, link, _) = cache(1, 1);
        c.output(link, neighbor(), 0, 1).unwrap();
        c.advertisement(
            link,
            na(true, true, Some(MAC_A)),
            0,
            Some(&mut entropy),
            &mut no_events,
        )
        .unwrap();
        assert_eq!(c.next_deadline(), Some(expected));
    }
}

#[test]
fn solicitations_create_or_update_stale_entries() {
    let (mut cache, link, _) = cache(1, 0);
    let ns = |mac| ntcp_icmp::NeighborSolicitation {
        target: own(),
        source_link_layer: Some(mac),
    };
    cache
        .solicitation(link, neighbor(), ns(MAC_A), 0, &mut no_events)
        .unwrap();
    assert_eq!(
        cache.state(link, neighbor()),
        Some((NeighborState::Stale, Some(MAC_A), false))
    );
    // The answer goes to the stated address, solicited.
    let (control, token) = cache.next_control(link, 0).unwrap();
    assert_eq!(
        control,
        Control::Advertise {
            link,
            target: own(),
            to: Some((neighbor(), MAC_A)),
        }
    );
    cache.complete(token, ControlOutcome::Submitted, 0);
    assert_eq!(cache.next_control(link, 0), None);
    // The same address keeps the state; a changed one is STALE again.
    cache.output(link, neighbor(), 0, 0).unwrap();
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Delay
    );
    cache
        .solicitation(link, neighbor(), ns(MAC_A), 0, &mut no_events)
        .unwrap();
    assert_eq!(
        cache.state(link, neighbor()).unwrap().0,
        NeighborState::Delay
    );
    cache
        .solicitation(link, neighbor(), ns(MAC_B), 0, &mut no_events)
        .unwrap();
    assert_eq!(
        cache.state(link, neighbor()),
        Some((NeighborState::Stale, Some(MAC_B), false))
    );
    // Another node's DAD probe is answered to all-nodes and learns nothing.
    let (_, token) = cache.next_control(link, 0).unwrap();
    cache.complete(token, ControlOutcome::Submitted, 0);
    let dad = ntcp_icmp::NeighborSolicitation {
        target: own(),
        source_link_layer: None,
    };
    cache
        .solicitation(link, Ipv6Addr::UNSPECIFIED, dad, 0, &mut no_events)
        .unwrap();
    let (control, _) = cache.next_control(link, 0).unwrap();
    assert_eq!(
        control,
        Control::Advertise {
            link,
            target: own(),
            to: None,
        }
    );
}

#[test]
fn duplicate_address_detection_both_ways() {
    let link = link();
    let tentative: Ipv6Addr = "fe80::5".parse().unwrap();
    let make = |loops_back_multicast| {
        let mut entropy = fixed(0x80);
        let mut cache = Neighbors::<u32>::new(limits(1, 1), 1, SECOND).unwrap();
        let port = NdPort {
            loops_back_multicast,
            ..NdPort::new(OWN)
        };
        cache.add_port(link, port, Some(&mut entropy)).unwrap();
        assert_eq!(
            cache.add_address(link, tentative),
            Ok(AddressState::Tentative)
        );
        (cache, entropy)
    };
    // Nothing is probed before the groups are joined.
    let (mut cache, mut entropy) = make(false);
    assert_eq!(cache.next_control(link, 10 * SECOND), None);
    cache
        .membership_ready(link, tentative, 0, Some(&mut entropy))
        .unwrap();
    // The random delay (half of MAX_RTR_SOLICITATION_DELAY here).
    assert_eq!(cache.next_control(link, SECOND / 2 - 1), None);
    let (control, token) = cache.next_control(link, SECOND / 2).unwrap();
    assert_eq!(
        control,
        Control::Solicit {
            link,
            target: tentative,
            destination: Destination::Multicast,
            dad: true,
        }
    );
    cache.complete(token, ControlOutcome::Blocked, SECOND / 2);
    let mut assigned = None;
    cache.service(10 * SECOND, &mut |e| assigned = Some(e));
    assert_eq!(assigned, None);
    let (_, token) = cache.next_control(link, SECOND).unwrap();
    cache.complete(token, ControlOutcome::Submitted, SECOND);
    // A resolution solicitation for a tentative address is ignored.
    let ns = ntcp_icmp::NeighborSolicitation {
        target: tentative,
        source_link_layer: Some(MAC_A),
    };
    cache
        .solicitation(link, neighbor(), ns, SECOND, &mut no_events)
        .unwrap();
    assert_eq!(
        (
            cache.next_control(link, SECOND),
            cache.state(link, neighbor())
        ),
        (None, None)
    );
    cache.service(2 * SECOND - 1, &mut no_events);
    assert_eq!(
        cache.address_state(link, tentative),
        Some(AddressState::Tentative)
    );
    cache.service(2 * SECOND, &mut |e| assigned = Some(e));
    assert_eq!(
        assigned,
        Some(NdEvent::Assigned {
            link,
            address: tentative
        })
    );
    assert_eq!(
        cache.address_state(link, tentative),
        Some(AddressState::Assigned)
    );

    // Another node's DAD probe fails it.
    let dad = ntcp_icmp::NeighborSolicitation {
        target: tentative,
        source_link_layer: None,
    };
    let (mut cache, mut entropy) = make(false);
    cache
        .membership_ready(link, tentative, 0, Some(&mut entropy))
        .unwrap();
    let mut failed = None;
    cache
        .solicitation(link, Ipv6Addr::UNSPECIFIED, dad, 0, &mut |e| {
            failed = Some(e)
        })
        .unwrap();
    assert_eq!(
        failed,
        Some(NdEvent::Duplicate {
            link,
            address: tentative
        })
    );
    assert_eq!(
        cache.address_state(link, tentative),
        Some(AddressState::Duplicate)
    );
    assert_eq!(cache.next_control(link, 10 * SECOND), None);

    // Its own probe looped back is not another node's.
    let (mut cache, mut entropy) = make(true);
    cache
        .membership_ready(link, tentative, 0, Some(&mut entropy))
        .unwrap();
    let (_, token) = cache.next_control(link, SECOND).unwrap();
    cache.complete(token, ControlOutcome::Submitted, SECOND);
    cache
        .solicitation(link, Ipv6Addr::UNSPECIFIED, dad, SECOND, &mut no_events)
        .unwrap();
    let mut failed = None;
    cache
        .solicitation(link, Ipv6Addr::UNSPECIFIED, dad, SECOND, &mut |e| {
            failed = Some(e)
        })
        .unwrap();
    assert_eq!(
        failed,
        Some(NdEvent::Duplicate {
            link,
            address: tentative
        })
    );

    // A valid advertisement of the tentative address, without any cache
    // entry, fails it too.
    let (mut cache, mut entropy) = make(false);
    let mut failed = None;
    let claim = ntcp_icmp::NeighborAdvertisement {
        target: tentative,
        ..na(false, true, Some(MAC_A))
    };
    cache
        .advertisement(link, claim, 0, Some(&mut entropy), &mut |e| {
            failed = Some(e)
        })
        .unwrap();
    assert_eq!(
        failed,
        Some(NdEvent::Duplicate {
            link,
            address: tentative
        })
    );
}

// The RFC 4861 section 7.2.5 table as an independent reference: the state
// and address an advertisement leaves, from the state and address before.
fn reference(
    state: Option<(NeighborState, Option<[u8; 6]>)>,
    advertisement: ntcp_icmp::NeighborAdvertisement,
) -> Option<(NeighborState, Option<[u8; 6]>)> {
    use NeighborState::*;
    let (state, mac) = state?;
    let tllao = advertisement.target_link_layer;
    if state == Incomplete {
        return match tllao {
            None => Some((state, mac)),
            Some(new) if advertisement.solicited => Some((Reachable, Some(new))),
            Some(new) => Some((Stale, Some(new))),
        };
    }
    let different = tllao.is_some() && tllao != mac;
    if !advertisement.override_ && different {
        return Some((if state == Reachable { Stale } else { state }, mac));
    }
    let mac = tllao.or(mac);
    if advertisement.solicited {
        Some((Reachable, mac))
    } else if different {
        Some((Stale, mac))
    } else {
        Some((state, mac))
    }
}

// Seeded random operation sequences over one neighbor: every advertisement
// result is checked against the reference table, and every 7.2.5 branch
// and every state is reached.
#[test]
fn seeded_state_model_covers_every_advertisement_branch() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut model = cache(1, 4);
    let mut now = 0;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut branches = Vec::new();
    let mut states = Vec::new();
    for step in 0..4000 {
        // Fresh episodes: a cache that holds no entry yet, too.
        if step % 100 == 0 {
            model = cache(1, 4);
            now = 0;
        }
        let (cache, link, entropy) = &mut model;
        let link = *link;
        let roll = next();
        let before = cache.state(link, neighbor()).map(|(s, m, _)| (s, m));
        // The pending solicitation, its attempt count included.
        let due = cache.next_control(link, now);
        match roll % 6 {
            0 => {
                if cache.output(link, neighbor(), now, 0) == Ok(Resolution::Held) {
                    // Held packets are released or failed, never queued
                    // beyond storage.
                }
                while let Some((slot, ..)) = cache.next_pending(|_| true) {
                    cache.release(slot);
                }
            }
            1 | 2 => {
                let mac = match (roll >> 8) % 3 {
                    0 => None,
                    1 => Some(MAC_A),
                    _ => Some(MAC_B),
                };
                let advertisement = na(roll >> 16 & 1 == 1, roll >> 17 & 1 == 1, mac);
                let branch = cache
                    .advertisement(link, advertisement, now, Some(entropy), &mut no_events)
                    .unwrap();
                let after = cache.state(link, neighbor()).map(|(s, m, _)| (s, m));
                assert_eq!(
                    after,
                    reference(before, advertisement),
                    "{before:?} {advertisement:?}"
                );
                // A branch keeping the state keeps its solicitation
                // progress too.
                if matches!(
                    branch,
                    NaBranch::IncompleteNoAddress
                        | NaBranch::KeptIgnored
                        | NaBranch::UpdatedUnchanged
                ) {
                    assert_eq!(
                        cache.next_control(link, now),
                        due,
                        "{before:?} {advertisement:?}"
                    );
                }
                if !branches.contains(&branch) {
                    branches.push(branch);
                }
            }
            3 => {
                if let Some((_, token)) = cache.next_control(link, now) {
                    let outcome = [
                        ControlOutcome::Submitted,
                        ControlOutcome::Uncertain,
                        ControlOutcome::Blocked,
                        ControlOutcome::Failed,
                    ][(roll >> 8) as usize % 4];
                    cache.complete(token, outcome, now);
                }
            }
            4 => {
                now += (roll >> 8) % (8 * SECOND);
                cache.service(now, &mut no_events);
            }
            _ => {
                let carried_at = now.saturating_sub((roll >> 8) % (2 * SECOND));
                cache
                    .confirm(link, neighbor(), carried_at, now, Some(entropy))
                    .unwrap();
            }
        }
        if let Some((state, ..)) = cache.state(link, neighbor())
            && !states.contains(&state)
        {
            states.push(state);
        }
    }
    use NaBranch::*;
    for branch in [
        NoEntry,
        IncompleteNoAddress,
        IncompleteSolicited,
        IncompleteUnsolicited,
        KeptReachableToStale,
        KeptIgnored,
        UpdatedSolicited,
        UpdatedChanged,
        UpdatedUnchanged,
    ] {
        assert!(branches.contains(&branch), "{branch:?} not covered");
    }
    use NeighborState::*;
    for state in [Incomplete, Reachable, Stale, Delay, Probe] {
        assert!(states.contains(&state), "{state:?} not reached");
    }
}

// RFC 4861 section 8.3: a Redirect's Target Link-Layer Address creates a
// STALE entry or changes a different mapping to STALE, while the same
// mapping keeps its state; a router target is marked IsRouter even
// without a mapping, a target that is the destination is not on a new
// entry and keeps an existing entry's flag. Clearing IsRouter by an
// advertisement is reported (section 7.2.5).
#[test]
fn redirect_targets_update_the_cache_and_router_flag() {
    let (mut cache, link, mut entropy) = cache(2, 1);
    // A router target without a mapping and without an entry: nothing is
    // created (no unresolved entry without a held packet); the entry
    // resolution creates later is marked by the Host.
    cache.redirect(link, neighbor(), None, true, 0);
    assert_eq!(cache.state(link, neighbor()), None);
    assert_eq!(cache.output(link, neighbor(), 0, 1), Ok(Resolution::Held));
    cache.mark_router(link, neighbor());
    assert_eq!(
        cache.state(link, neighbor()),
        Some((NeighborState::Incomplete, None, true))
    );
    // Its mapping resolves the held packet as STALE.
    cache.redirect(link, neighbor(), Some(MAC_A), true, 1);
    assert_eq!(
        cache.state(link, neighbor()),
        Some((NeighborState::Stale, Some(MAC_A), true))
    );
    assert!(matches!(cache.next_pending(|_| true), Some((_, 1, Some(MAC_A)))));
    // A solicited advertisement makes it REACHABLE; the same mapping again
    // keeps that state, a different one makes it STALE.
    let mut confirmed = na(true, true, Some(MAC_A));
    confirmed.router = true;
    cache
        .advertisement(link, confirmed, 2, Some(&mut entropy), &mut no_events)
        .unwrap();
    cache.redirect(link, neighbor(), Some(MAC_A), true, 3);
    assert_eq!(
        cache.state(link, neighbor()),
        Some((NeighborState::Reachable, Some(MAC_A), true))
    );
    // The destination as its own target keeps the existing flag.
    cache.redirect(link, neighbor(), Some(MAC_B), false, 4);
    assert_eq!(
        cache.state(link, neighbor()),
        Some((NeighborState::Stale, Some(MAC_B), true))
    );
    // A new entry for an on-link destination is not a router.
    let other: Ipv6Addr = "fe80::b".parse().unwrap();
    cache.redirect(link, other, Some(MAC_A), false, 5);
    assert_eq!(
        cache.state(link, other),
        Some((NeighborState::Stale, Some(MAC_A), false))
    );
    // An advertisement without the Router flag ends its router role.
    let mut events = Vec::new();
    cache
        .advertisement(link, na(false, true, Some(MAC_B)), 6, Some(&mut entropy), &mut |e| {
            events.push(e)
        })
        .unwrap();
    assert_eq!(
        events,
        [NdEvent::RouterLost {
            link,
            address: neighbor()
        }]
    );
    assert_eq!(cache.state(link, neighbor()).map(|n| n.2), Some(false));
}

// RFC 4861 section 7.2.5 as an exhaustive table, the IsRouter flag
// included: from each of the five states, with the flag set or clear,
// every combination of Solicited, Override, Router and Target Link-Layer
// Address (absent, the cached one, another). INCOMPLETE takes the flag
// with the address; otherwise only the update branch sets it (an ignored
// advertisement and REACHABLE turned STALE change nothing else), and a
// flag the update clears is reported.
#[test]
fn advertisements_update_the_router_flag_only_where_permitted() {
    use NeighborState::*;
    // A cache whose entry for `neighbor()` is in `state`, mapped to MAC_A
    // unless INCOMPLETE, with IsRouter `router`, at the returned time.
    let prepare = |state: NeighborState, router: bool| {
        let (mut c, link, mut entropy) = cache(1, 2);
        let mut events = |_| {};
        c.output(link, neighbor(), 0, 1).unwrap();
        if state == Incomplete {
            if router {
                c.redirect(link, neighbor(), None, true, 0);
            }
            return (c, link, entropy, 0);
        }
        let mut setup = na(state == Reachable, false, Some(MAC_A));
        setup.router = router;
        c.advertisement(link, setup, 0, Some(&mut entropy), &mut events)
            .unwrap();
        while let Some((slot, ..)) = c.next_pending(|_| true) {
            c.release(slot);
        }
        let mut now = 0;
        if matches!(state, Delay | Probe) {
            now = SECOND;
            assert_eq!(
                c.output(link, neighbor(), now, 2),
                Ok(Resolution::Ready(MAC_A))
            );
            while let Some((slot, ..)) = c.next_pending(|_| true) {
                c.release(slot);
            }
        }
        if state == Probe {
            now += 5 * SECOND;
            c.service(now, &mut events);
        }
        assert_eq!(
            c.state(link, neighbor()),
            Some((state, (state != Incomplete).then_some(MAC_A), router))
        );
        (c, link, entropy, now)
    };
    for state in [Incomplete, Reachable, Stale, Delay, Probe] {
        for router in [false, true] {
            for bits in 0..8u8 {
                let (solicited, override_, flag) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
                for tllao in [None, Some(MAC_A), Some(MAC_B)] {
                    let (mut c, link, mut entropy, now) = prepare(state, router);
                    let before = c.state(link, neighbor()).unwrap();
                    let mut advertisement = na(solicited, override_, tllao);
                    advertisement.router = flag;
                    let mut events = Vec::new();
                    c.advertisement(link, advertisement, now, Some(&mut entropy), &mut |e| {
                        events.push(e)
                    })
                    .unwrap();
                    let after = c.state(link, neighbor()).unwrap();
                    let (expected_state, expected_mac) =
                        reference(Some((before.0, before.1)), advertisement).unwrap();
                    let updates = if state == Incomplete {
                        tllao.is_some()
                    } else {
                        override_ || tllao.is_none() || tllao == before.1
                    };
                    let expected_router = if updates { flag } else { router };
                    let case = (state, router, solicited, override_, flag, tllao);
                    assert_eq!(
                        after,
                        (expected_state, expected_mac, expected_router),
                        "{case:?}"
                    );
                    let lost = router && !expected_router;
                    assert_eq!(
                        events,
                        if lost {
                            vec![NdEvent::RouterLost {
                                link,
                                address: neighbor(),
                            }]
                        } else {
                            vec![]
                        },
                        "{case:?}"
                    );
                }
            }
        }
    }
}
