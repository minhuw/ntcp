// The lifecycle gate through Host factories, with simulated time: nothing is
// prepared, leased or emitted before the deadline, and only TCP waits.
use super::admission::{Counting, core_input, syn, usage};
use super::*;

const QUIET: u64 = 240_000_000;

fn quiet(local: SocketAddr, identity: u128) -> (Host, Endpoint, IngressContext) {
    managed_lifecycle(
        local,
        identity,
        config(4),
        false,
        None,
        None,
        |paths, limits| (paths, limits, 1),
        ntcp::Lifecycle::default(),
    )
}

#[test]
fn managed_active_opens_are_refused_before_any_path_preparation() {
    let cfg = config(4);
    let (local, remote) = addresses(false);
    let mut a = quiet(local, 71);
    a.1.enable_fast_open().unwrap();
    let before = usage(&a.0);
    let mut provider = Counting { host: &mut a.0, prepared: 0 };
    assert_eq!(
        a.1.connect_with_path_provider(QUIET - 1, local, remote, options(&cfg, 0), &mut provider)
            .map_err(Error::from),
        Err(Error::Endpoint(EndpointError::QuietUntil(QUIET)))
    );
    assert_eq!(
        a.1.connect_fast_open_with_path_provider(
            QUIET - 1,
            local,
            remote,
            b"early",
            options(&cfg, 0),
            None,
            ntcp::FastOpenClientPolicy::RequireCookie,
            &mut provider,
        )
        .map(|_| ())
        .map_err(Error::from),
        Err(Error::Endpoint(EndpointError::QuietUntil(QUIET)))
    );
    assert_eq!(provider.prepared, 0);
    assert_eq!(usage(&a.0), before);
    assert!(selected(&mut a.1, QUIET - 1).is_none());

    let mut provider = Counting { host: &mut a.0, prepared: 0 };
    a.1.connect_with_path_provider(QUIET, local, remote, options(&cfg, 0), &mut provider)
        .unwrap();
    assert_eq!(provider.prepared, 1);
    assert!(selected(&mut a.1, QUIET).is_some());
}

// Quiet time is the last refusal: an open the Host could not prepare now
// keeps the Host's own error, with nothing acquired, rather than one that
// says it would start at the deadline.
#[test]
fn an_unroutable_managed_open_keeps_its_error_during_quiet_time() {
    let cfg = config(4);
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = quiet(local, 76);
        a.1.enable_fast_open().unwrap();
        let request =
            a.0.request(local.ip(), remote.ip(), None, Dscp::new(0).unwrap())
                .unwrap();
        let route = a.0.paths().resolve(request).unwrap().key().route();
        a.0.remove_route(route).unwrap();
        let before = usage(&a.0);
        let mut provider = Counting { host: &mut a.0, prepared: 0 };
        assert_eq!(
            a.1.connect_with_path_provider(QUIET - 1, local, remote, options(&cfg, 0), &mut provider),
            Err(ManagedError::Provider(Error::Path(path::Error::NoRoute))),
            "v6={v6}"
        );
        assert_eq!(
            a.1.connect_fast_open_with_path_provider(
                QUIET - 1,
                local,
                remote,
                b"early",
                options(&cfg, 0),
                None,
                ntcp::FastOpenClientPolicy::RequireCookie,
                &mut provider,
            )
            .map(|_| ()),
            Err(ManagedError::Provider(Error::Path(path::Error::NoRoute))),
            "v6={v6}"
        );
        assert_eq!(provider.prepared, 0);
        assert_eq!(usage(&a.0), before);
        assert!(selected(&mut a.1, QUIET - 1).is_none());
    }
}

#[test]
fn managed_input_prepares_nothing_and_replies_nothing_before_the_deadline() {
    let (local, remote) = addresses(false);
    let mut b = quiet(remote, 72);
    let port = b.1.listen(remote, 4).unwrap();
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let before = usage(&b.0);
    let (result, prepared) = core_input(&mut b, QUIET - 1, ip, &syn(ip, 1000));
    assert_eq!(result.unwrap(), ntcp::InputDisposition::Dropped);
    assert_eq!(prepared, 0);
    assert_eq!(usage(&b.0), before);
    assert!(selected(&mut b.1, QUIET - 1).is_none());
    assert_eq!(b.1.listener_queue_info(port).unwrap().0, 0);

    let (result, prepared) = core_input(&mut b, QUIET, ip, &syn(ip, 1000));
    assert_eq!(result.unwrap(), ntcp::InputDisposition::Processed);
    assert_eq!(prepared, 1);
    assert!(selected(&mut b.1, QUIET).is_some());
}

// Quiet time is TCP only: the same lifecycle leaves the Host's own services
// and its registration alone.
#[test]
fn identifier_service_runs_during_quiet_time() {
    let (local, remote) = addresses(false);
    let mut a = managed_lifecycle(
        local,
        73,
        config(4),
        false,
        None,
        None,
        |paths, mut limits| {
            limits.datagrams.identifiers = IdentifierLimits {
                lifetime_seconds: DEFAULT_LIFETIME_SECONDS,
                ipv4_tuples: 2,
                ipv6_leases: 2,
            };
            (paths, limits, 1)
        },
        ntcp::Lifecycle::default(),
    );
    a.0.set_entropy(std::boxed::Box::new(|out: &mut [u8]| {
        out.fill(0x5a);
        Ok(())
    }));
    a.0.start_identifiers(Continuity::QuietFor { at: 0, seconds: u64::MAX })
        .unwrap();
    assert!(a.0.lease_identification(0, local.ip(), remote.ip(), 17).is_ok());
    assert_eq!(a.1.quiet_until(0), Some(QUIET));
}

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
