// Per-source identifier continuity facts on one allocator.
use super::*;

// One allocator serves every source, each after its own fact.
#[test]
fn each_source_keeps_its_own_identifier_quiet_period() {
    let (local, remote) = addresses(false);
    let other: IpAddr = "192.0.2.9".parse().unwrap();
    let mut a = managed_identified_unstarted(local, 74);
    a.0.start_identifiers(Continuity::QuietSince(0)).unwrap();
    a.0.start_source_identifiers(local.ip(), 0, u64::MAX).unwrap();
    a.0.start_source_identifiers(other, 0, 100).unwrap();
    let mdl = u64::from(DEFAULT_LIFETIME_SECONDS) * 1_000_000;
    assert!(a.0.lease_identification(0, local.ip(), remote.ip(), 17).is_ok());
    assert_eq!(
        a.0.lease_identification(mdl - 100_000_001, other, remote.ip(), 17).err(),
        Some(IdentifierBackpressure::Unavailable {
            until: Some(mdl - 100_000_000)
        })
    );
    assert!(a.0.lease_identification(mdl - 100_000_000, other, remote.ip(), 17).is_ok());
    // A source without its own fact keeps the start's.
    let unstated: IpAddr = "192.0.2.10".parse().unwrap();
    assert_eq!(
        a.0.lease_identification(mdl - 1, unstated, remote.ip(), 17).err(),
        Some(IdentifierBackpressure::Unavailable { until: Some(mdl) })
    );
    // One value on two links waits for the later of its facts.
    a.0.start_source_identifiers(other, mdl - 100_000_000, 0).unwrap();
    assert_eq!(
        a.0.lease_identification(mdl, other, remote.ip(), 17).err(),
        Some(IdentifierBackpressure::Unavailable {
            until: Some(2 * mdl - 100_000_000)
        })
    );
}

#[test]
fn a_source_fact_needs_a_started_allocator() {
    let (local, _) = addresses(false);
    let mut a = managed_identified_unstarted(local, 75);
    assert_eq!(
        a.0.start_source_identifiers(local.ip(), 0, 1).err(),
        Some(Error::InvalidContext)
    );
}

fn managed_identified_unstarted(local: SocketAddr, identity: u128) -> (Host, Endpoint, IngressContext) {
    let mut side = managed_limited(local, identity, config(4), false, None, None, |p, mut l| {
        l.datagrams.identifiers = IdentifierLimits {
            lifetime_seconds: DEFAULT_LIFETIME_SECONDS,
            ipv4_tuples: 4,
            ipv6_leases: 2,
        };
        (p, l, 1)
    });
    side.0.set_entropy(std::boxed::Box::new(|out: &mut [u8]| {
        out.fill(0x5a);
        Ok(())
    }));
    side
}
