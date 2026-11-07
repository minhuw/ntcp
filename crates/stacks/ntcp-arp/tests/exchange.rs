// Two caches resolving each other through encoded Ethernet frames.
use core::net::Ipv4Addr;
use ntcp_arp::*;

const A_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xa];
const B_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xb];
const A_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

type Cache = ArpCache<(), u8>;

fn half() -> Option<u32> {
    Some(1 << 31)
}

fn node(mac: [u8; 6], ip: Ipv4Addr) -> Cache {
    let limits = ArpLimits {
        links: 1,
        entries: 4,
        held: 4,
        replies: 4,
        addresses: 1,
    };
    let mut cache = Cache::new(limits, ArpTimers::default(), 1000).unwrap();
    cache.add_link((), mac, &mut half).unwrap();
    cache.add_address((), ip, AddressKind::Local).unwrap();
    cache
}

// Emit `from`'s next frame, as a padded Ethernet frame, completing it as
// submitted.
fn transmit(from: &mut Cache, now: u64) -> Option<[u8; 60]> {
    let (control, token) = from.next_control((), now)?;
    let mut frame = [0; 60];
    assert_eq!(control.encode(&mut frame), Ok(60));
    from.complete(token, ControlOutcome::Submitted, now);
    Some(frame)
}

// Deliver a frame to `to` if the Ethernet destination is its MAC or
// broadcast, as an Ethernet port filters.
fn deliver(to: &mut Cache, mac: [u8; 6], frame: &[u8], now: u64) -> bool {
    let (destination, source, arp) = parse_frame(frame).unwrap();
    assert_eq!(source, arp.sender_mac);
    if destination != mac && destination != [0xff; 6] {
        return false;
    }
    to.receive((), &arp, now, &mut half).unwrap();
    true
}

#[test]
fn two_caches_resolve_each_other_over_frames() {
    let mut a = node(A_MAC, A_IP);
    let mut b = node(B_MAC, B_IP);
    assert_eq!(a.resolve((), B_IP, 0, 1), Ok(Resolution::Held));

    // A broadcasts its request; B learns A (STALE) and answers unicast.
    let request = transmit(&mut a, 0).unwrap();
    assert_eq!(request[..6], [0xff; 6]);
    assert!(transmit(&mut a, 0).is_none());
    assert!(deliver(&mut b, B_MAC, &request, 1));
    assert_eq!(b.entry((), A_IP), Some((ArpState::Stale, Some(A_MAC))));
    let reply = transmit(&mut b, 1).unwrap();
    assert_eq!(reply[..6], A_MAC);
    // The reply reaches A only.
    assert!(!deliver(&mut node([2; 6], B_IP), [2; 6], &reply, 2));
    assert!(deliver(&mut a, A_MAC, &reply, 2));
    assert_eq!(a.entry((), B_IP), Some((ArpState::Reachable, Some(B_MAC))));
    assert_eq!(a.next_wake(|_| true), Some(Wake::Retry(1)));
    assert_eq!(a.resolve((), B_IP, 3, 1), Ok(Resolution::Ready(B_MAC)));

    // B already knows A without asking: its use starts DELAY, and when no
    // upper layer confirms it, B probes A unicast and A's answer confirms.
    assert_eq!(b.resolve((), A_IP, 3, 7), Ok(Resolution::Ready(A_MAC)));
    assert_eq!(b.entry((), A_IP).unwrap().0, ArpState::Delay);
    b.service(5_003, &mut |_| unreachable!());
    let probe = transmit(&mut b, 5_003).unwrap();
    assert_eq!(probe[..6], A_MAC);
    assert!(deliver(&mut a, A_MAC, &probe, 5_004));
    let answer = transmit(&mut a, 5_004).unwrap();
    assert!(deliver(&mut b, B_MAC, &answer, 5_005));
    assert_eq!(b.entry((), A_IP), Some((ArpState::Reachable, Some(A_MAC))));
    assert!(transmit(&mut a, 5_005).is_none());
    assert!(transmit(&mut b, 5_005).is_none());
    assert_eq!(a.counters().requests_sent, 1);
    assert_eq!(a.counters().replies_sent, 1);
    assert_eq!(b.counters().requests_sent, 1);
    assert_eq!(b.counters().replies_sent, 1);
}
