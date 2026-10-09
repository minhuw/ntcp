use ntcp_ip::path_mtu::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;
thread_local! { static ALLOCS: Cell<Option<usize>> = const { Cell::new(None) }; }
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn key() -> PathKey {
    PathKey::new(
        "192.0.2.1".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        7,
        1,
        0,
    )
    .unwrap()
}
fn v6() -> PathKey {
    PathKey::new(
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        7,
        1,
        0,
    )
    .unwrap()
}
fn drop<const N: usize>(
    s: &mut PathMtuService<N>,
    h: PathHandle,
    mtu: u32,
    now: u64,
) -> DropOutcome {
    let context = s.query(h).unwrap().context;
    s.decrease(HostValidatedDrop::new(context, context.key(), 42, mtu), now)
        .unwrap()
}

#[test]
fn shared_path_queries_and_distinct_drop_notifications() {
    let mut s = PathMtuService::<2>::new();
    let tcp = s.register(key(), 9000, Policy::default(), 0).unwrap();
    let udp = s.register(key(), 9000, Policy::default(), 0).unwrap();
    assert_eq!(tcp, udp); // conceptual subscribers, no per-flow MSS/cwnd stored
    let event = drop(&mut s, udp, 1400, 1);
    assert_eq!(event.change.unwrap().reason, ChangeReason::Decreased);
    assert_eq!(event.dropped.packet_id, 42); // host token, not fabricated TCP seq
    assert_eq!(s.query(tcp).unwrap().mtu, 1400);
    let repeated = drop(&mut s, udp, 1400, 2);
    assert!(repeated.change.is_none());
    assert_eq!(repeated.dropped.packet_id, 42);
    assert!(drop(&mut s, tcp, 8000, 3).change.is_none());
    assert_eq!(s.query(tcp).unwrap().mtu, 1400);
}

#[test]
fn keys_isolate_local_remote_interface_route_and_all_tos_bits() {
    let base = key();
    let keys = [
        base,
        PathKey {
            local: "192.0.2.3".parse().unwrap(),
            ..base
        },
        PathKey {
            remote: "192.0.2.3".parse().unwrap(),
            ..base
        },
        PathKey {
            interface: 8,
            ..base
        },
        PathKey {
            route_generation: 2,
            ..base
        },
        PathKey {
            traffic_class: 4,
            ..base
        },
        PathKey {
            traffic_class: 3,
            ..base
        },
    ];
    let mut s = PathMtuService::<7>::new();
    let handles = keys.map(|k| s.register(k, 1500, Policy::default(), 0).unwrap());
    drop(&mut s, handles[0], 68, 1);
    for h in &handles[1..] {
        assert_eq!(s.query(*h).unwrap().mtu, 1500);
    }
    assert_eq!(s.iter().count(), 7);
    assert_eq!(
        PathKey::new(base.local, v6().remote, 0, 0, 0),
        Err(Error::Family)
    );
}

#[test]
fn reject_forged_path_stale_context_and_old_probes() {
    let mut s = PathMtuService::<1>::new();
    let h = s.register(key(), 1500, Policy::default(), 0).unwrap();
    let old = s.query(h).unwrap().context;
    let wrong = PathKey {
        route_generation: 2,
        ..key()
    };
    assert_eq!(
        s.decrease(HostValidatedDrop::new(old, wrong, 0, 1400), 1),
        Err(Error::PathMismatch)
    );
    drop(&mut s, h, 1400, 1);
    assert_eq!(s.confirm_probe(old, 1500, 2), Err(Error::StaleContext));
    let context = s.query(h).unwrap().context;
    s.first_hop_changed(h, 1300, 2).unwrap();
    assert_eq!(
        s.decrease(HostValidatedDrop::new(context, key(), 0, 1200), 3),
        Err(Error::StaleContext)
    );
    let context = s.query(h).unwrap().context;
    s.set_policy(
        h,
        Policy {
            mtu: Some(1200),
            ..Policy::default()
        },
        3,
    )
    .unwrap();
    assert_eq!(s.confirm_probe(context, 1300, 4), Err(Error::StaleContext));
    s.invalidate(h).unwrap();
    let replacement = s.register(key(), 1500, Policy::default(), 4).unwrap();
    assert_ne!(h, replacement);
    assert_eq!(s.query(h), Err(Error::StaleContext));
}

#[test]
fn aging_is_bounded_and_never_implicitly_increases() {
    let mut s = PathMtuService::<2>::new();
    let p = Policy {
        aging: Some(10),
        ..Policy::default()
    };
    let h = s.register(key(), 9000, p, 0).unwrap();
    let infinite = s.register(v6(), 9000, Policy::default(), 0).unwrap();
    drop(&mut s, h, 1400, 1);
    assert_eq!(s.age(h, 10), Ok(None));
    assert_eq!(
        s.age(h, 11).unwrap().unwrap().reason,
        ChangeReason::Revalidation
    );
    assert_eq!(s.query(h).unwrap().mtu, 1400);
    assert!(s.query(h).unwrap().revalidation_needed);
    assert_eq!(s.age(h, 12), Ok(None));
    assert_eq!(s.age(infinite, 100), Ok(None));
    let c = s.query(h).unwrap().context;
    let event = s.confirm_probe(c, 1600, 100).unwrap();
    assert_eq!(event.reason, ChangeReason::ProbeConfirmed);
    assert_eq!(s.query(h).unwrap().mtu, 1600);
    assert!(!s.query(h).unwrap().revalidation_needed);
    assert_eq!(s.age(h, 99), Err(Error::ClockWentBackwards));
    let before = s.query(h).unwrap();
    assert_eq!(s.set_policy(h, p, u64::MAX), Err(Error::TimeOverflow));
    assert_eq!(s.query(h).unwrap(), before);
    assert_eq!(
        s.age(h, 110).unwrap().unwrap().reason,
        ChangeReason::Revalidation
    );
}

#[test]
fn administration_link_events_family_floors_and_df_metadata() {
    let mut s = PathMtuService::<2>::new();
    assert_eq!(
        s.register(key(), 67, Policy::default(), 0),
        Err(Error::InvalidMtu)
    );
    assert_eq!(
        s.register(v6(), 1279, Policy::default(), 0),
        Err(Error::InvalidMtu)
    );
    let h = s.register(key(), 9000, Policy::default(), 0).unwrap();
    let h6 = s.register(v6(), 9000, Policy::default(), 0).unwrap();
    assert_eq!(
        s.register(key(), 1500, Policy::default(), 0),
        Err(Error::ConfigurationConflict)
    );
    let bad_df = Policy {
        ipv4_df: Ipv4Df::Clear,
        ..Policy::default()
    };
    assert_eq!(s.set_policy(h, bad_df, 1), Err(Error::InvalidPolicy));
    let disabled = Policy {
        enabled: false,
        ..bad_df
    };
    s.set_policy(h, disabled, 1).unwrap();
    assert_eq!(s.query(h).unwrap().policy.ipv4_df, Ipv4Df::Clear);
    assert!(drop(&mut s, h, 68, 2).change.is_none());
    s.set_policy(h6, disabled, 2).unwrap();
    assert_eq!(s.query(h6).unwrap().mtu, 1280);
    s.set_policy(h6, Policy::default(), 3).unwrap();
    assert_eq!(s.query(h6).unwrap().mtu, 1280);
    assert!(s.query(h6).unwrap().revalidation_needed);
    let c = s.query(h6).unwrap().context;
    assert_eq!(
        s.decrease(HostValidatedDrop::new(c, v6(), 0, 1279), 3),
        Err(Error::InvalidMtu)
    );
    s.set_policy(
        h,
        Policy {
            mtu: Some(68),
            ..Policy::default()
        },
        4,
    )
    .unwrap();
    assert_eq!(s.query(h).unwrap().mtu, 68);
    assert_eq!(
        s.confirm_probe(s.query(h).unwrap().context, 69, 4),
        Err(Error::InvalidMtu)
    );
    s.set_policy(h, Policy::default(), 5).unwrap();
    assert_eq!(s.query(h).unwrap().mtu, 68);
    s.first_hop_changed(h, 1000, 6).unwrap();
    s.confirm_probe(s.query(h).unwrap().context, 1000, 7)
        .unwrap();
    s.first_hop_changed(h, 500, 8).unwrap();
    assert_eq!(s.query(h).unwrap().mtu, 500);
    s.first_hop_changed(h, 1500, 9).unwrap();
    assert_eq!(s.query(h).unwrap().mtu, 500);
    assert!(s.query(h).unwrap().revalidation_needed);
}

#[test]
fn fixed_capacity_reuse_and_allocation_free_operations() {
    let k = key();
    let other = v6();
    ALLOCS.with(|count| count.set(Some(0)));
    let mut s = PathMtuService::<1>::new();
    let h = s.register(k, 1500, Policy::default(), 0).unwrap();
    assert_eq!(
        s.register(other, 1500, Policy::default(), 0),
        Err(Error::Capacity)
    );
    assert_eq!(s.query(h).unwrap().mtu, 1500);
    drop(&mut s, h, 1200, 1);
    s.set_policy(
        h,
        Policy {
            aging: Some(1),
            ..Policy::default()
        },
        2,
    )
    .unwrap();
    s.age(h, 3).unwrap();
    s.first_hop_changed(h, 1300, 4).unwrap();
    s.confirm_probe(s.query(h).unwrap().context, 1300, 5)
        .unwrap();
    assert_eq!(s.iter().count(), 1);
    s.invalidate(h).unwrap();
    let new = s.register(other, 1500, Policy::default(), 6).unwrap();
    assert_ne!(h, new);
    assert_eq!(s.query(h), Err(Error::StaleContext));
    assert_eq!(
        PathMtuService::<0>::new().register(k, 1500, Policy::default(), 0),
        Err(Error::Capacity)
    );
    let allocations = ALLOCS.with(|count| count.replace(None).unwrap());
    assert_eq!(allocations, 0);
}
