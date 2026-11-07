use super::*;
use crate::wire::FastOpenCookie;

fn peer(key: u8) -> (Endpoint, ActiveOpenOptions) {
    let config = EndpointConfig {
        max_connections: 32,
        max_listeners: 4,
        connection: ConnectionConfig {
            mss: 1460,
            timestamps: false,
            nagle: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let options = ActiveOpenOptions::from(&config.connection);
    let mut endpoint = Endpoint::new(config, [key; 32], 0, |_| true).unwrap();
    endpoint.enable_fast_open().unwrap();
    (endpoint, options)
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn linux_default_lease_expires_at_admission_without_timer_service() {
    for v6 in [false, true] {
        let (mut server, _) = peer(2);
        server.set_fast_open_cookie_policy(FastOpenCookiePolicy::LinuxSipHash24(
            LinuxSipHash24Key::new([7; 16]),
        ));
        let (_, remote) = addresses(v6, 40000);
        let listener = server.listen(remote, 16).unwrap();
        server.set_listener_fast_open(listener, 4).unwrap();
        let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
        for (port, now, early) in [
            (40001, crate::fast_open::LIFETIME_US - 1, true),
            (40002, crate::fast_open::LIFETIME_US, false),
            (40003, crate::fast_open::LIFETIME_US + 1, false),
        ] {
            let (mut client, _) = peer(1);
            let (local, _) = addresses(v6, port);
            open(
                &mut client,
                &mut server,
                listener,
                local,
                remote,
                now,
                Some(cookie),
                early,
            );
        }
    }
}

// Every branch below exchanges actual SYN/SYN-ACK/ACK/data packets. In
// particular, fallback proves that rejecting credentials preserves byte progress.
fn lifecycle_open(
    server: &mut Endpoint,
    listener: ListenerId,
    v6: bool,
    now: u64,
    port: u16,
    cookie: FastOpenCookie,
    early: bool,
) -> Option<FastOpenCookie> {
    let (_, remote) = addresses(v6, port);
    lifecycle_open_to(server, listener, v6, now, port, remote, cookie, early)
}

fn lifecycle_open_to(
    server: &mut Endpoint,
    listener: ListenerId,
    v6: bool,
    now: u64,
    port: u16,
    remote: SocketAddr,
    cookie: FastOpenCookie,
    early: bool,
) -> Option<FastOpenCookie> {
    let (mut client, options) = peer(1);
    let (local, _) = addresses(v6, port);
    let (id, n) = client
        .connect_fast_open_with_server_cookie(now, local, remote, b"early", options, Some(cookie))
        .unwrap();
    assert_eq!(n, 5);
    let syn = packet(&mut client, now);
    let seq = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
    deliver(server, now, &syn);
    let reply = packet(server, now);
    let parsed = wire::parse(reply.0, &reply.1).unwrap();
    assert_eq!(
        parsed.header.acknowledgment,
        seq.wrapping_add(if early { 6 } else { 1 })
    );
    let response = parsed.options.fast_open;
    let child = if early {
        Some(server.accept(listener).unwrap())
    } else {
        assert!(server.accept(listener).is_err());
        None
    };
    deliver(&mut client, now, &reply);
    deliver(server, now, &packet(&mut client, now));
    let child = child.unwrap_or_else(|| server.accept(listener).unwrap());
    let mut bytes = [0; 5];
    assert_eq!(server.read(child, &mut bytes), Ok(5));
    assert_eq!(&bytes, b"early");
    assert_eq!(server.state(child), Ok(State::Established));
    assert_eq!(client.state(id), Ok(State::Established));
    assert_eq!(client.transport_info(id).unwrap().syn_data_acked, early);
    response
}

fn server_key(policy: &FastOpenCookiePolicy, byte: u8) -> FastOpenServerKey {
    match policy {
        FastOpenCookiePolicy::HmacSha256 => FastOpenServerKey::HmacSha256([byte; 32]),
        #[cfg(feature = "tfo-linux-cookie")]
        FastOpenCookiePolicy::LinuxSipHash24(_) => {
            FastOpenServerKey::LinuxSipHash24(LinuxSipHash24Key::new([byte; 16]))
        }
    }
}

fn timed_install(
    server: &mut Endpoint,
    listener: ListenerId,
    scoped: bool,
    now: u64,
    key: FastOpenServerKey,
    lease: FastOpenKeyLease,
    rotate: bool,
) {
    if scoped {
        server
            .install_listener_fast_open_key(now, listener, key, lease, rotate)
            .unwrap();
    } else {
        server
            .install_fast_open_key(now, key, lease, rotate)
            .unwrap();
    }
}

// Full lifecycle evidence remains partial until the embedding preserves trusted
// lease deadlines across restart. The raw codec tests alone make no such claim.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//# To gradually invalidate cookies over time, the server can implement key rotation to generate and verify cookies using multiple keys. This approach is useful for large-scale servers to retain Fast Open rolling key updates. We do not specify a particular mechanism because the implementation is server specific.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Endpoint admission enforces finite HMAC current/previous epochs and LinuxSipHash24 key leases with absolute issue/accept deadlines, including delayed service, retiring keys and same-key no-renewal through the endpoint-owned identity registry across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux validation intentionally ignores epoch, including u64::MAX, to preserve wire bytes; that raw codec result is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# 5. The cookie expires after a certain amount of time. The reason for cookie expiration is detailed in the "Security Considerations" section (Section 5). This can be done by either periodically changing the server key used to generate cookies or including a timestamp when generating the cookie.
//= https://www.rfc-editor.org/rfc/rfc7413#section-3
//= type=test
//= reason=Actual IPv4/IPv6 endpoints repeatedly reuse credentials before expiry, reject expired SYN data at admission and complete ordinary TCP byte delivery with fresh-cookie learning or no-cookie fallback. HMAC keeps current/previous epochs; LinuxSipHash24 keeps raw bytes under finite key leases. Raw epoch-independent codec vectors are not server acceptance evidence. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# 5. The rest of the connection proceeds like a normal TCP connection. The client can repeat many Fast Open operations once it acquires a cookie (until the cookie is expired by the server).
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Server-selected HMAC/SipHash authenticate addresses; admission now enforces finite HMAC epochs and LinuxSipHash24 key leases, and protected services independently bypass cookies. Raw Linux epoch-independent validation preserves bytes and is not server admission. The full imported property set remains TODO: T6 now supplies release actual-path measurements with source/executable provenance, scoped admission/issuance counts, raw rounds and observer controls in integration/rfc_host/check_mac_cost.py; HMAC overlap remains substantial and the complete relative-cost assessment awaits independent review/T23 disposition. External raw keys keep their original boot-named leases across restarts; only that assessment remains.
//# The server is in charge of cookie generation and authentication. The cookie SHOULD be a MAC tag with the following properties. We use "SHOULD" because, in some cases, the cookie may be trivially generated as discussed in Section 7.3.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Passive admission authenticates both address families using current/retiring bounded key contexts consulting one endpoint-owned identity/deadline registry, finite HMAC epochs and LinuxSipHash24 leases. Traffic tests reject expired and invalid credentials exactly at deadlines and complete fallback; raw Linux epoch-independent codec validation alone is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# - IsCookieValid(IP_Address, Cookie): checks if the cookie is valid, i.e., it has not expired and the cookie authenticates the client IP address.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
//= type=test
//= reason=Real request/SYN-ACK exchanges issue usable cookies only within issuance deadlines; finite HMAC epochs and LinuxSipHash24 leases govern admission independently of raw epoch-independent encoding. T6 now measures actual release SYN/SYN-ACK admission/issuance and remaining processing in integration/rfc_host/check_mac_cost.py, retaining raw rounds, multiplicities, source/executable provenance and observer controls; HMAC overlap remains substantial and full relative-cost assessment awaits independent review/T23 disposition. External raw keys keep their original boot-named leases across restarts; the whole clause remains TODO only for that assessment.
//# 2. The server responds with a SYN-ACK based on the procedures in the "Server Cookie Handling" section (Section 4.1.2).
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=Repeated Fast Open, manual key revocation, finite HMAC epochs and LinuxSipHash24 key leases are exercised through actual endpoints in both IP families. Admission checks issue/accept deadlines without timer service; expired and invalid credentials complete ordinary TCP, fresh keys teach usable replacements, and same-key reinstalls cannot renew expired leases in the endpoint authority across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux epoch-independent codec tests are not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# Once the client obtains the cookie from the target server, it can perform subsequent TFO connections until the cookie is expired by the server.
#[test]
fn timed_credentials_enforce_issue_accept_retirement_and_no_renewal_in_both_timebases() {
    for v6 in [false, true] {
        for units in [1_000_000, 1_000_000_000] {
            for policy in policies() {
                for scoped in [false, true] {
                    let config = EndpointConfig {
                        max_connections: 32,
                        connection: ConnectionConfig {
                            timestamps: false,
                            nagle: false,
                            timebase: CallerTimebase {
                                units_per_second: units,
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    let tb = config.connection.timebase;
                    let mut server = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
                    server.enable_fast_open().unwrap();
                    let (_, remote) = addresses(v6, 40000);
                    let listener = server.listen(remote, 24).unwrap();
                    server.set_listener_fast_open(listener, 4).unwrap();
                    let duration = FastOpenCookieLifetime::from_micros(1_000_000).unwrap();
                    if scoped {
                        server
                            .set_listener_fast_open_cookie_lifetime(listener, duration)
                            .unwrap();
                    } else {
                        server.set_fast_open_cookie_lifetime(duration);
                    }
                    let lease = FastOpenKeyLease::for_lifetime(0, duration, tb, true).unwrap();
                    timed_install(
                        &mut server,
                        listener,
                        scoped,
                        0,
                        server_key(&policy, 7),
                        lease,
                        false,
                    );
                    let (_, old) = learn(&mut server, listener, v6, 0, 40000);
                    lifecycle_open(&mut server, listener, v6, units - 1, 40001, old, true);
                    // Issuance stops exactly on issue_until, acceptance continues.
                    assert_eq!(
                        lifecycle_open(&mut server, listener, v6, units, 40002, old, true),
                        None
                    );
                    let next = FastOpenKeyLease::for_lifetime(units, duration, tb, true).unwrap();
                    timed_install(
                        &mut server,
                        listener,
                        scoped,
                        units,
                        server_key(&policy, 8),
                        next,
                        true,
                    );
                    // Current/retiring both authenticate while only current issues.
                    let fresh = lifecycle_open(&mut server, listener, v6, units, 40003, old, true);
                    let fresh = fresh.unwrap_or_else(|| {
                        // Linux omits refresh for valid retiring cookies; obtain
                        // the new cookie through a real invalid/request SYN.
                        learn(&mut server, listener, v6, units, 40004).1
                    });
                    assert_ne!(old, fresh);
                    lifecycle_open(&mut server, listener, v6, units + 1, 40005, fresh, true);
                    let invalid = wire::FastOpenCookie::new(&[0x55; 8]).unwrap();
                    assert_eq!(
                        lifecycle_open(&mut server, listener, v6, units + 1, 40006, invalid, false),
                        Some(fresh)
                    );
                    // No timers were serviced. The original retiring deadline
                    // is authoritative, including for delayed admission.
                    lifecycle_open(&mut server, listener, v6, 2 * units - 1, 40007, old, true);
                    assert_eq!(
                        lifecycle_open(&mut server, listener, v6, 2 * units, 40008, old, false),
                        None
                    );
                    assert_eq!(
                        lifecycle_open(&mut server, listener, v6, 3 * units, 40009, fresh, false),
                        None
                    );
                    // A same-key install carrying later deadlines cannot revive
                    // the expired current credential or promise a fresh cookie.
                    let later =
                        FastOpenKeyLease::for_lifetime(3 * units, duration, tb, true).unwrap();
                    timed_install(
                        &mut server,
                        listener,
                        scoped,
                        3 * units,
                        server_key(&policy, 8),
                        later,
                        false,
                    );
                    assert_eq!(
                        lifecycle_open(&mut server, listener, v6, 3 * units, 40010, fresh, false),
                        None
                    );
                    timed_install(
                        &mut server,
                        listener,
                        scoped,
                        3 * units,
                        server_key(&policy, 9),
                        later,
                        false,
                    );
                    let replacement =
                        lifecycle_open(&mut server, listener, v6, 3 * units, 40011, fresh, false)
                            .unwrap();
                    lifecycle_open(
                        &mut server,
                        listener,
                        v6,
                        3 * units,
                        40012,
                        replacement,
                        true,
                    );
                }
            }
        }
    }
}

#[test]
fn hmac_real_credentials_expire_after_current_and_previous_epochs() {
    for v6 in [false, true] {
        let (mut server, _) = peer(2);
        let (_, remote) = addresses(v6, 40000);
        let listener = server.listen(remote, 16).unwrap();
        server.set_listener_fast_open(listener, 4).unwrap();
        let lifetime = crate::fast_open::LIFETIME_US;
        let (_, old) = learn(&mut server, listener, v6, lifetime - 1, 40000);
        lifecycle_open(&mut server, listener, v6, lifetime, 40001, old, true);
        lifecycle_open(
            &mut server,
            listener,
            v6,
            2 * lifetime - 1,
            40002,
            old,
            true,
        );
        let fresh =
            lifecycle_open(&mut server, listener, v6, 2 * lifetime, 40003, old, false).unwrap();
        lifecycle_open(
            &mut server,
            listener,
            v6,
            2 * lifetime + 1,
            40004,
            fresh,
            true,
        );
    }
}

#[test]
fn inherited_policy_override_preserves_issue_and_accept_deadlines() {
    for v6 in [false, true] {
        for policy in policies() {
            for override_at in [100, 50] {
                let (mut server, _) = peer(2);
                let (_, remote) = addresses(v6, 40000);
                let listener = server.listen(remote, 16).unwrap();
                server.set_listener_fast_open(listener, 4).unwrap();
                let lease = FastOpenKeyLease {
                    not_before: 0,
                    issue_until: 50,
                    accept_until: 100,
                    units_per_second: 1_000_000,
                };
                server
                    .install_fast_open_key(0, server_key(&policy, 7), lease, false)
                    .unwrap();
                let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
                lifecycle_open(&mut server, listener, v6, 49, 40001, cookie, true);
                // A future-install duration must not change the inherited key's
                // epoch parameters when it becomes an explicit listener policy.
                server.set_fast_open_cookie_lifetime(
                    FastOpenCookieLifetime::from_micros(100).unwrap(),
                );
                let early = override_at < lease.accept_until;
                assert_eq!(
                    lifecycle_open(&mut server, listener, v6, override_at, 40002, cookie, early),
                    None
                );
                server
                    .set_listener_fast_open_cookie_policy(listener, Some(policy.clone()))
                    .unwrap();
                assert_eq!(
                    lifecycle_open(&mut server, listener, v6, override_at, 40003, cookie, early),
                    None
                );
                // Restoring inheritance and making it explicit again also
                // preserves the expired lease, without timer service.
                server
                    .set_listener_fast_open_cookie_policy(listener, None)
                    .unwrap();
                assert_eq!(
                    lifecycle_open(&mut server, listener, v6, 100, 40004, cookie, false),
                    None
                );
                server
                    .set_listener_fast_open_cookie_policy(listener, Some(policy.clone()))
                    .unwrap();
                assert_eq!(
                    lifecycle_open(&mut server, listener, v6, 100, 40005, cookie, false),
                    None
                );
                assert_eq!(
                    lifecycle_open(&mut server, listener, v6, 101, 40006, cookie, false),
                    None
                );
            }
        }
    }
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn hmac_policy_round_trip_preserves_expired_lease_and_epoch_metadata() {
    for v6 in [false, true] {
        for scoped in [false, true] {
            for rotate in [false, true] {
                let (mut server, _) = peer(2);
                let (_, remote) = addresses(v6, 40000);
                let listener = server.listen(remote, 16).unwrap();
                server.set_listener_fast_open(listener, 4).unwrap();
                let lease = FastOpenKeyLease {
                    not_before: 0,
                    issue_until: 10_000_000,
                    accept_until: 20_000_000,
                    units_per_second: 1_000_000,
                };
                // Make the key available for policy selection in either scope.
                server.set_fast_open_hmac_key([7; 32]);
                timed_install(
                    &mut server,
                    listener,
                    scoped,
                    0,
                    FastOpenServerKey::HmacSha256([7; 32]),
                    lease,
                    false,
                );
                let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
                lifecycle_open(&mut server, listener, v6, 19_999_999, 40001, cookie, true);
                assert_eq!(
                    lifecycle_open(&mut server, listener, v6, 20_000_000, 40002, cookie, false),
                    None
                );
                let raw = FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([8; 16]));
                if rotate {
                    timed_install(
                        &mut server,
                        listener,
                        scoped,
                        20_000_000,
                        server_key(&raw, 8),
                        FastOpenKeyLease::for_lifetime(
                            20_000_000,
                            Default::default(),
                            CallerTimebase::default(),
                            true,
                        )
                        .unwrap(),
                        true,
                    );
                } else if scoped {
                    server
                        .set_listener_fast_open_cookie_policy(listener, Some(raw))
                        .unwrap();
                } else {
                    server.set_fast_open_cookie_policy(raw);
                }
                if scoped {
                    server
                        .set_listener_fast_open_cookie_policy(
                            listener,
                            Some(FastOpenCookiePolicy::HmacSha256),
                        )
                        .unwrap();
                } else {
                    server.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
                }
                assert_eq!(
                    lifecycle_open(&mut server, listener, v6, 20_000_000, 40003, cookie, false),
                    None
                );
                // Neither same-key manual replacement nor a later timed lease
                // may renew the credential after the policy round trip.
                server.set_fast_open_hmac_key([7; 32]);
                let later = FastOpenKeyLease::for_lifetime(
                    20_000_000,
                    Default::default(),
                    CallerTimebase::default(),
                    true,
                )
                .unwrap();
                timed_install(
                    &mut server,
                    listener,
                    scoped,
                    20_000_000,
                    FastOpenServerKey::HmacSha256([7; 32]),
                    later,
                    false,
                );
                assert_eq!(
                    lifecycle_open(&mut server, listener, v6, 20_000_000, 40004, cookie, false),
                    None
                );
                timed_install(
                    &mut server,
                    listener,
                    scoped,
                    20_000_000,
                    FastOpenServerKey::HmacSha256([9; 32]),
                    later,
                    false,
                );
                let fresh =
                    lifecycle_open(&mut server, listener, v6, 20_000_000, 40005, cookie, false)
                        .unwrap();
                lifecycle_open(&mut server, listener, v6, 20_000_000, 40006, fresh, true);
            }
        }
    }
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn linux_policy_round_trip_preserves_original_lease() {
    for v6 in [false, true] {
        for scoped in [false, true] {
            for explicit in [false, true] {
                for switch_at in [50, 100] {
                    for (timed_departure, timed_return) in
                        [(false, false), (false, true), (true, false), (true, true)]
                    {
                        let (mut server, _) = peer(2);
                        let (_, remote) = addresses(v6, 40000);
                        let listener = server.listen(remote, 16).unwrap();
                        server.set_listener_fast_open(listener, 4).unwrap();
                        let duration = FastOpenCookieLifetime::from_micros(100).unwrap();
                        server.set_fast_open_cookie_lifetime(duration);
                        let raw =
                            FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([7; 16]));
                        if explicit {
                            timed_install(
                                &mut server,
                                listener,
                                scoped,
                                0,
                                server_key(&raw, 7),
                                FastOpenKeyLease {
                                    not_before: 0,
                                    issue_until: 50,
                                    accept_until: 100,
                                    units_per_second: 1_000_000,
                                },
                                false,
                            );
                        } else if scoped {
                            server
                                .set_listener_fast_open_cookie_policy(listener, Some(raw.clone()))
                                .unwrap();
                        } else {
                            server.set_fast_open_cookie_policy(raw.clone());
                        }
                        let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
                        lifecycle_open(&mut server, listener, v6, 49, 40001, cookie, true);
                        lifecycle_open(
                            &mut server,
                            listener,
                            v6,
                            switch_at,
                            40002,
                            cookie,
                            switch_at < 100,
                        );
                        let later = FastOpenKeyLease::for_lifetime(
                            switch_at,
                            duration,
                            CallerTimebase::default(),
                            true,
                        )
                        .unwrap();
                        if timed_departure {
                            timed_install(
                                &mut server,
                                listener,
                                scoped,
                                switch_at,
                                FastOpenServerKey::HmacSha256([2; 32]),
                                later,
                                switch_at == 100,
                            );
                        } else if scoped {
                            server
                                .set_listener_fast_open_cookie_policy(
                                    listener,
                                    Some(FastOpenCookiePolicy::HmacSha256),
                                )
                                .unwrap();
                        } else {
                            server.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
                        }
                        if timed_return {
                            timed_install(
                                &mut server,
                                listener,
                                scoped,
                                switch_at,
                                server_key(&raw, 7),
                                later,
                                false,
                            );
                        } else if scoped {
                            server
                                .set_listener_fast_open_cookie_policy(listener, Some(raw))
                                .unwrap();
                        } else {
                            server.set_fast_open_cookie_policy(raw);
                        }
                        if switch_at < 100 {
                            // Reinstalling before expiry preserves both the old
                            // issuance boundary and the remaining acceptance window.
                            let invalid = FastOpenCookie::new(&[0x55; 8]).unwrap();
                            let response = lifecycle_open(
                                &mut server,
                                listener,
                                v6,
                                50,
                                40003,
                                invalid,
                                false,
                            );
                            assert_eq!(response, (!explicit).then_some(cookie));
                            lifecycle_open(&mut server, listener, v6, 99, 40004, cookie, true);
                        }
                        // No timer servicing: policy selection and a later timed
                        // install must not revive the old raw cookie at expiry.
                        assert_eq!(
                            lifecycle_open(&mut server, listener, v6, 100, 40005, cookie, false),
                            None
                        );
                        assert_eq!(
                            lifecycle_open(&mut server, listener, v6, 101, 40006, cookie, false),
                            None
                        );
                        timed_install(
                            &mut server,
                            listener,
                            scoped,
                            101,
                            FastOpenServerKey::LinuxSipHash24(LinuxSipHash24Key::new([8; 16])),
                            FastOpenKeyLease::for_lifetime(
                                101,
                                duration,
                                CallerTimebase::default(),
                                true,
                            )
                            .unwrap(),
                            false,
                        );
                        let fresh =
                            lifecycle_open(&mut server, listener, v6, 101, 40007, cookie, false)
                                .unwrap();
                        assert_ne!(fresh, cookie);
                        lifecycle_open(&mut server, listener, v6, 101, 40008, fresh, true);
                    }
                }
            }
        }
    }
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn hmac_policy_round_trip_keeps_original_epoch_duration() {
    for v6 in [false, true] {
        for scoped in [false, true] {
            let (mut server, _) = peer(2);
            let (_, remote) = addresses(v6, 40000);
            let listener = server.listen(remote, 16).unwrap();
            server.set_listener_fast_open(listener, 4).unwrap();
            let duration = FastOpenCookieLifetime::from_micros(1_000_000).unwrap();
            server.set_fast_open_cookie_lifetime(duration);
            server.set_fast_open_hmac_key([7; 32]);
            if scoped {
                server
                    .set_listener_fast_open_cookie_policy(
                        listener,
                        Some(FastOpenCookiePolicy::HmacSha256),
                    )
                    .unwrap();
            }
            let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
            lifecycle_open(&mut server, listener, v6, 1_999_999, 40001, cookie, true);
            let raw = FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([8; 16]));
            // Future-install configuration cannot rewrite the old HMAC epochs.
            if scoped {
                server
                    .set_listener_fast_open_cookie_lifetime(listener, Default::default())
                    .unwrap();
                server
                    .set_listener_fast_open_cookie_policy(listener, Some(raw))
                    .unwrap();
                server
                    .set_listener_fast_open_cookie_policy(
                        listener,
                        Some(FastOpenCookiePolicy::HmacSha256),
                    )
                    .unwrap();
            } else {
                server.set_fast_open_cookie_lifetime(Default::default());
                server.set_fast_open_cookie_policy(raw);
                server.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
            }
            let fresh =
                lifecycle_open(&mut server, listener, v6, 2_000_000, 40002, cookie, false).unwrap();
            assert_ne!(fresh, cookie);
            lifecycle_open(&mut server, listener, v6, 2_000_000, 40003, fresh, true);
        }
    }
}

#[test]
fn constructor_hmac_rotation_preserves_current_and_previous_epoch_cookies() {
    for v6 in [false, true] {
        for scoped in [false, true] {
            let (mut server, _) = peer(2);
            let (_, remote) = addresses(v6, 40000);
            let listener = server.listen(remote, 16).unwrap();
            server.set_listener_fast_open(listener, 4).unwrap();
            let lifetime = crate::fast_open::LIFETIME_US;
            let (_, old) = learn(&mut server, listener, v6, lifetime / 2, 40000);
            let now = 3 * lifetime / 4;
            let lease = FastOpenKeyLease::for_lifetime(
                now,
                FastOpenCookieLifetime::default(),
                CallerTimebase::default(),
                true,
            )
            .unwrap();
            timed_install(
                &mut server,
                listener,
                scoped,
                now,
                FastOpenServerKey::HmacSha256([7; 32]),
                lease,
                true,
            );
            lifecycle_open(&mut server, listener, v6, now, 40001, old, true);
            let fresh =
                lifecycle_open(&mut server, listener, v6, lifetime, 40002, old, true).unwrap();
            lifecycle_open(
                &mut server,
                listener,
                v6,
                2 * lifetime - 1,
                40003,
                old,
                true,
            );
            assert_eq!(
                lifecycle_open(&mut server, listener, v6, 2 * lifetime, 40004, old, false),
                None
            );
            lifecycle_open(&mut server, listener, v6, 2 * lifetime, 40005, fresh, true);
        }
    }
}

// All identity-cycle cases use real SYN data and exact ordinary-TCP delivery.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Endpoint admission enforces finite HMAC current/previous epochs and LinuxSipHash24 key leases with absolute issue/accept deadlines, including delayed service, retiring keys and same-key no-renewal through the endpoint-owned identity registry across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux validation intentionally ignores epoch, including u64::MAX, to preserve wire bytes; that raw codec result is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# 5. The cookie expires after a certain amount of time. The reason for cookie expiration is detailed in the "Security Considerations" section (Section 5). This can be done by either periodically changing the server key used to generate cookies or including a timestamp when generating the cookie.
#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn credential_authority_rejects_arbitrary_key_cycles_on_actual_traffic() {
    for v6 in [false, true] {
        for scoped in [false, true] {
            for length in [2, 3] {
                for timed in [false, true] {
                    let (mut server, _) = peer(2);
                    server.set_fast_open_cookie_lifetime(
                        FastOpenCookieLifetime::from_micros(100).unwrap(),
                    );
                    let (_, remote) = addresses(v6, 40000);
                    let listener = server.listen(remote, 16).unwrap();
                    server.set_listener_fast_open(listener, 4).unwrap();
                    let raw = |byte| {
                        FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([byte; 16]))
                    };
                    let lease = |now| {
                        FastOpenKeyLease::for_lifetime(
                            now,
                            FastOpenCookieLifetime::from_micros(100).unwrap(),
                            CallerTimebase::default(),
                            false,
                        )
                        .unwrap()
                    };
                    timed_install(
                        &mut server,
                        listener,
                        scoped,
                        0,
                        server_key(&raw(7), 7),
                        lease(0),
                        false,
                    );
                    let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
                    lifecycle_open(&mut server, listener, v6, 99, 40001, cookie, true);
                    for byte in 8..8 + length - 1 {
                        timed_install(
                            &mut server,
                            listener,
                            scoped,
                            100,
                            server_key(&raw(byte), byte),
                            lease(100),
                            false,
                        );
                        // Interleaving a different codec cannot erase any raw identity.
                        if scoped {
                            server
                                .set_listener_fast_open_cookie_policy(
                                    listener,
                                    Some(FastOpenCookiePolicy::HmacSha256),
                                )
                                .unwrap();
                        } else {
                            server.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
                        }
                    }
                    // Advance the authoritative clock to 101 through actual traffic.
                    lifecycle_open(&mut server, listener, v6, 101, 40002, cookie, false);
                    if timed {
                        timed_install(
                            &mut server,
                            listener,
                            scoped,
                            101,
                            server_key(&raw(7), 7),
                            lease(101),
                            false,
                        );
                    } else if scoped {
                        server
                            .set_listener_fast_open_cookie_policy(listener, Some(raw(7)))
                            .unwrap();
                    } else {
                        server.set_fast_open_cookie_policy(raw(7));
                    }
                    let usage = server.fast_open_key_registry_usage();
                    assert_eq!(
                        lifecycle_open(&mut server, listener, v6, 101, 40003, cookie, false),
                        None
                    );
                    assert_eq!(server.fast_open_key_registry_usage(), usage);
                    timed_install(
                        &mut server,
                        listener,
                        scoped,
                        101,
                        server_key(&raw(11), 11),
                        lease(101),
                        false,
                    );
                    let fresh =
                        lifecycle_open(&mut server, listener, v6, 101, 40004, cookie, false)
                            .unwrap();
                    lifecycle_open(&mut server, listener, v6, 200, 40005, fresh, true);
                    assert_eq!(
                        lifecycle_open(&mut server, listener, v6, 201, 40006, fresh, false),
                        None
                    );
                }
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Endpoint admission enforces finite HMAC current/previous epochs and LinuxSipHash24 key leases with absolute issue/accept deadlines, including delayed service, retiring keys and same-key no-renewal through the endpoint-owned identity registry across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux validation intentionally ignores epoch, including u64::MAX, to preserve wire bytes; that raw codec result is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# 5. The cookie expires after a certain amount of time. The reason for cookie expiration is detailed in the "Security Considerations" section (Section 5). This can be done by either periodically changing the server key used to generate cookies or including a timestamp when generating the cookie.
#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn credential_authority_survives_distinct_default_clear_close_and_cross_listener_reuse() {
    for v6 in [false, true] {
        let (mut server, _) = peer(2);
        server.set_fast_open_cookie_lifetime(FastOpenCookieLifetime::from_micros(100).unwrap());
        let (_, remote) = addresses(v6, 40000);
        let mut listener = server.listen(remote, 16).unwrap();
        server.set_listener_fast_open(listener, 4).unwrap();
        let raw = FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([7; 16]));
        server
            .set_listener_fast_open_cookie_policy(listener, Some(raw.clone()))
            .unwrap();
        let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
        lifecycle_open(&mut server, listener, v6, 99, 40001, cookie, true);
        assert_eq!(
            lifecycle_open(&mut server, listener, v6, 100, 40002, cookie, false),
            None
        );
        server
            .set_listener_fast_open_cookie_policy(listener, None)
            .unwrap();
        // The default is a distinct constructor HMAC identity, with no Linux key.
        server
            .set_listener_fast_open_cookie_policy(listener, Some(raw.clone()))
            .unwrap();
        assert_eq!(
            lifecycle_open(&mut server, listener, v6, 101, 40003, cookie, false),
            None
        );
        let usage = server.fast_open_key_registry_usage();
        server.close_listener(listener).unwrap();
        server.poll_transmit(101, &mut [0; 2048], 64).unwrap();
        listener = server.listen(remote, 16).unwrap();
        server.set_listener_fast_open(listener, 4).unwrap();
        server
            .set_listener_fast_open_cookie_policy(listener, Some(raw.clone()))
            .unwrap();
        assert_eq!(
            lifecycle_open(&mut server, listener, v6, 101, 40004, cookie, false),
            None
        );
        let other_remote = SocketAddr::new(remote.ip(), remote.port() + 1);
        let other = server.listen(other_remote, 16).unwrap();
        server.set_listener_fast_open(other, 4).unwrap();
        server
            .set_listener_fast_open_cookie_policy(other, Some(raw))
            .unwrap();
        assert_eq!(
            lifecycle_open_to(
                &mut server,
                other,
                v6,
                101,
                40005,
                other_remote,
                cookie,
                false
            ),
            None
        );
        server.clear_fast_open_client_cache();
        assert_eq!(server.fast_open_key_registry_usage(), usage);
        let fresh_policy = FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([8; 16]));
        server
            .set_listener_fast_open_cookie_policy(other, Some(fresh_policy))
            .unwrap();
        let fresh = lifecycle_open_to(
            &mut server,
            other,
            v6,
            101,
            40006,
            other_remote,
            cookie,
            false,
        )
        .unwrap();
        lifecycle_open_to(
            &mut server,
            other,
            v6,
            200,
            40007,
            other_remote,
            fresh,
            true,
        );
        assert_eq!(
            lifecycle_open_to(
                &mut server,
                other,
                v6,
                201,
                40008,
                other_remote,
                fresh,
                false
            ),
            None
        );
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Passive admission authenticates both address families using current/retiring bounded key contexts consulting one endpoint-owned identity/deadline registry, finite HMAC epochs and LinuxSipHash24 leases. Traffic tests reject expired and invalid credentials exactly at deadlines and complete fallback; raw Linux epoch-independent codec validation alone is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# - IsCookieValid(IP_Address, Cookie): checks if the cookie is valid, i.e., it has not expired and the cookie authenticates the client IP address.
#[test]
fn global_credential_tightening_reaches_all_listener_selections_and_preserves_children() {
    for v6 in [false, true] {
        for policy in policies() {
            let (mut server, _) = peer(2);
            let (_, remote) = addresses(v6, 40000);
            let listener = server.listen(remote, 16).unwrap();
            server.set_listener_fast_open(listener, 4).unwrap();
            let lease = FastOpenKeyLease {
                not_before: 0,
                issue_until: 100,
                accept_until: 100,
                units_per_second: 1_000_000,
            };
            let key = server_key(&policy, 7);
            server
                .install_fast_open_key(0, key.clone(), lease, false)
                .unwrap();
            server
                .set_listener_fast_open_cookie_lifetime(
                    listener,
                    FastOpenCookieLifetime::from_micros(999).unwrap(),
                )
                .unwrap();
            let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
            let other_remote = SocketAddr::new(remote.ip(), remote.port() + 1);
            let other = server.listen(other_remote, 16).unwrap();
            server.set_listener_fast_open(other, 4).unwrap();
            server
                .install_listener_fast_open_key(0, other, key.clone(), lease, false)
                .unwrap();
            lifecycle_open_to(
                &mut server,
                other,
                v6,
                49,
                40001,
                other_remote,
                cookie,
                true,
            );
            let (mut held_client, options) = peer(1);
            let (local, _) = addresses(v6, 40010);
            held_client
                .connect_fast_open_with_server_cookie(
                    49,
                    local,
                    remote,
                    b"early",
                    options,
                    Some(cookie),
                )
                .unwrap();
            deliver(&mut server, 49, &packet(&mut held_client, 49));
            server.enable_output_reservations().unwrap();
            let mut held = [0; 2048];
            let (output, token) = server.poll_reserved_transmit(49, &mut held, 64).unwrap();
            let tx = output.packet.unwrap();
            let snapshot = held[..tx.len].to_vec();
            let usage = server.fast_open_key_registry_usage();
            server
                .install_fast_open_key(
                    50,
                    key,
                    FastOpenKeyLease {
                        issue_until: 50,
                        accept_until: 50,
                        ..lease
                    },
                    false,
                )
                .unwrap();
            assert_eq!(&held[..tx.len], snapshot);
            assert!(server.accept_transmit(50, token.unwrap()).unwrap());
            let child = server.accept(listener).unwrap();
            let mut data = [0; 5];
            assert_eq!(server.read(child, &mut data), Ok(5));
            assert_eq!(&data, b"early");
            deliver(&mut held_client, 50, &(tx.ip, snapshot));
            deliver(&mut server, 50, &packet(&mut held_client, 50));
            assert_eq!(server.state(child), Ok(State::Established));
            assert_eq!(
                lifecycle_open(&mut server, listener, v6, 50, 40002, cookie, false),
                None
            );
            assert_eq!(
                lifecycle_open_to(
                    &mut server,
                    other,
                    v6,
                    50,
                    40003,
                    other_remote,
                    cookie,
                    false
                ),
                None
            );
            assert_eq!(server.fast_open_key_registry_usage(), usage);
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Endpoint admission enforces finite HMAC current/previous epochs and LinuxSipHash24 key leases with absolute issue/accept deadlines, including delayed service, retiring keys and same-key no-renewal through the endpoint-owned identity registry across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux validation intentionally ignores epoch, including u64::MAX, to preserve wire bytes; that raw codec result is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# 5. The cookie expires after a certain amount of time. The reason for cookie expiration is detailed in the "Security Considerations" section (Section 5). This can be done by either periodically changing the server key used to generate cookies or including a timestamp when generating the cookie.
#[test]
fn hmac_long_cycles_keep_original_epoch_mapping_across_listeners() {
    for v6 in [false, true] {
        let (mut server, _) = peer(2);
        server.set_fast_open_cookie_lifetime(FastOpenCookieLifetime::from_micros(100).unwrap());
        server.try_set_fast_open_hmac_key([7; 32]).unwrap();
        let (_, remote) = addresses(v6, 40000);
        let listener = server.listen(remote, 16).unwrap();
        server.set_listener_fast_open(listener, 4).unwrap();
        let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
        lifecycle_open(&mut server, listener, v6, 199, 40001, cookie, true);
        server.try_set_fast_open_hmac_key([8; 32]).unwrap();
        #[cfg(feature = "tfo-linux-cookie")]
        server.set_fast_open_cookie_policy(FastOpenCookiePolicy::LinuxSipHash24(
            LinuxSipHash24Key::new([8; 16]),
        ));
        server.try_set_fast_open_hmac_key([9; 32]).unwrap();
        server.set_fast_open_cookie_lifetime(FastOpenCookieLifetime::from_micros(10_000).unwrap());
        server.try_set_fast_open_hmac_key([7; 32]).unwrap();
        server.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
        let usage = server.fast_open_key_registry_usage();
        let fresh = lifecycle_open(&mut server, listener, v6, 200, 40002, cookie, false).unwrap();
        // The old identity still uses epoch 2 of its original 100us mapping,
        // rather than epoch 0 of the new 10000us setting.
        assert_eq!(
            fresh,
            crate::fast_open::issue(&[7; 32], remote.ip(), addresses(v6, 40000).0.ip(), 2)
        );
        server
            .set_listener_fast_open_cookie_policy(listener, Some(FastOpenCookiePolicy::HmacSha256))
            .unwrap();
        lifecycle_open(&mut server, listener, v6, 399, 40003, fresh, true);
        lifecycle_open(&mut server, listener, v6, 400, 40004, fresh, false);
        assert_eq!(server.fast_open_key_registry_usage(), usage);
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Passive admission authenticates both address families using current/retiring bounded key contexts consulting one endpoint-owned identity/deadline registry, finite HMAC epochs and LinuxSipHash24 leases. Traffic tests reject expired and invalid credentials exactly at deadlines and complete fallback; raw Linux epoch-independent codec validation alone is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# - IsCookieValid(IP_Address, Cookie): checks if the cookie is valid, i.e., it has not expired and the cookie authenticates the client IP address.
#[test]
fn bounded_registry_legacy_failure_blocks_explicit_listeners_and_preserves_tcp_progress() {
    for v6 in [false, true] {
        let config = EndpointConfig {
            max_connections: 16,
            preallocate_connections: 16,
            connection: ConnectionConfig {
                mss: 1460,
                timestamps: false,
                nagle: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut probe = Endpoint::new(config.clone(), [2; 32], 0, |_| true).unwrap();
        probe.enable_fast_open().unwrap();
        let lease = FastOpenKeyLease {
            not_before: 0,
            issue_until: 100,
            accept_until: 100,
            units_per_second: 1_000_000,
        };
        probe
            .register_fast_open_key(0, FastOpenServerKey::HmacSha256([7; 32]), lease)
            .unwrap();
        let budget = probe.buffer_bytes();
        let mut server = Endpoint::new(
            EndpointConfig {
                max_buffer_bytes: budget,
                ..config
            },
            [2; 32],
            0,
            |_| true,
        )
        .unwrap();
        server.enable_fast_open().unwrap();
        server
            .install_fast_open_key(0, FastOpenServerKey::HmacSha256([7; 32]), lease, false)
            .unwrap();
        let (_, remote) = addresses(v6, 40000);
        let listener = server.listen(remote, 16).unwrap();
        server.set_listener_fast_open(listener, 4).unwrap();
        server
            .set_listener_fast_open_cookie_lifetime(listener, Default::default())
            .unwrap();
        let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
        let usage = server.fast_open_key_registry_usage();
        assert_eq!(
            server.try_set_fast_open_hmac_key([8; 32]),
            Err(Error::NoMemory.into())
        );
        lifecycle_open(&mut server, listener, v6, 49, 40001, cookie, true);
        server.set_fast_open_hmac_key([8; 32]);
        assert_eq!(server.fast_open_cookie_error(), Some(Error::NoMemory));
        assert_eq!(server.fast_open_hmac_key_error(), Some(Error::NoMemory));
        assert_eq!(
            server.listener_fast_open_cookie_error(listener).unwrap(),
            Some(Error::NoMemory)
        );
        assert_eq!(
            lifecycle_open(&mut server, listener, v6, 50, 40002, cookie, false),
            None
        );
        // Restore a valid default using a known identity. The explicit blocked
        // listener must not fall through to this otherwise-authorizing default.
        server
            .install_fast_open_key(50, FastOpenServerKey::HmacSha256([2; 32]), lease, false)
            .unwrap();
        let default_cookie =
            crate::fast_open::issue(&[2; 32], remote.ip(), addresses(v6, 40000).0.ip(), 0);
        assert_eq!(
            lifecycle_open(&mut server, listener, v6, 50, 40003, default_cookie, false),
            None
        );
        server
            .set_listener_fast_open_cookie_policy(listener, None)
            .unwrap();
        lifecycle_open(&mut server, listener, v6, 50, 40004, default_cookie, true);
        assert_eq!(server.fast_open_key_registry_usage(), usage);
        assert!(server.buffer_bytes() <= budget);
        // A failed void policy replacement blocks inherited listeners too.
        #[cfg(feature = "tfo-linux-cookie")]
        {
            server.set_fast_open_cookie_policy(FastOpenCookiePolicy::LinuxSipHash24(
                LinuxSipHash24Key::new([9; 16]),
            ));
            assert_eq!(server.fast_open_cookie_error(), Some(Error::NoMemory));
            assert_eq!(
                lifecycle_open(&mut server, listener, v6, 51, 40005, default_cookie, false),
                None
            );
            assert_eq!(server.fast_open_key_registry_usage(), usage);
        }
    }
}

#[test]
fn timed_key_interfaces_reject_bad_units_overflow_and_clock_rollback() {
    assert!(FastOpenCookieLifetime::from_micros(0).is_err());
    assert!(FastOpenCookieLifetime::from_micros(u64::MAX).is_err());
    let lifetime = FastOpenCookieLifetime::default();
    for units in [1_000_000, 1_000_000_000] {
        let tb = CallerTimebase {
            units_per_second: units,
            ..Default::default()
        };
        assert!(FastOpenKeyLease::for_lifetime(u64::MAX, lifetime, tb, false).is_err());
        let mut config = EndpointConfig::default();
        config.connection.timestamps = false;
        config.connection.timebase = tb;
        let mut endpoint = Endpoint::new(config, [2; 32], 10, |_| true).unwrap();
        let valid = FastOpenKeyLease::for_lifetime(10, lifetime, tb, true).unwrap();
        for invalid in [
            FastOpenKeyLease {
                units_per_second: 123,
                ..valid
            },
            FastOpenKeyLease {
                not_before: 11,
                ..valid
            },
            FastOpenKeyLease {
                issue_until: 10,
                ..valid
            },
            FastOpenKeyLease {
                accept_until: valid.issue_until - 1,
                ..valid
            },
        ] {
            assert!(
                endpoint
                    .install_fast_open_key(
                        10,
                        FastOpenServerKey::HmacSha256([7; 32]),
                        invalid,
                        false
                    )
                    .is_err()
            );
        }
        assert_eq!(
            endpoint.install_fast_open_key(9, FastOpenServerKey::HmacSha256([7; 32]), valid, false),
            Err(EndpointError::Connection(Error::TimeWentBackwards))
        );
        endpoint
            .install_fast_open_key(10, FastOpenServerKey::HmacSha256([7; 32]), valid, false)
            .unwrap();
        endpoint
            .install_fast_open_key(11, FastOpenServerKey::HmacSha256([8; 32]), valid, true)
            .unwrap();
        assert!(
            endpoint
                .install_fast_open_key(11, FastOpenServerKey::HmacSha256([7; 32]), valid, true)
                .is_err()
        );
        let (local, remote) = addresses(false, 40000);
        assert!(
            endpoint
                .connect_fast_open(11, local, remote, b"disabled")
                .is_err()
        );
    }
    let invalid = CallerTimebase {
        units_per_second: 0,
        ..Default::default()
    };
    assert!(FastOpenKeyLease::for_lifetime(0, lifetime, invalid, true).is_err());
}

#[test]
fn timed_rotation_preserves_reserved_synack_authorization_pending_and_tcp_identity() {
    for v6 in [false, true] {
        for policy in policies() {
            let (mut server, _) = peer(2);
            let (_, remote) = addresses(v6, 40000);
            let listener = server.listen(remote, 16).unwrap();
            server.set_listener_fast_open(listener, 1).unwrap();
            let lease = FastOpenKeyLease {
                not_before: 0,
                issue_until: 10,
                accept_until: 20,
                units_per_second: 1_000_000,
            };
            timed_install(
                &mut server,
                listener,
                false,
                0,
                server_key(&policy, 7),
                lease,
                false,
            );
            let (_, old) = learn(&mut server, listener, v6, 0, 40000);
            let (mut client, options) = peer(1);
            let (local, _) = addresses(v6, 40001);
            client
                .connect_fast_open_with_server_cookie(
                    0,
                    local,
                    remote,
                    b"early",
                    options,
                    Some(old),
                )
                .unwrap();
            deliver(&mut server, 0, &packet(&mut client, 0));
            server.enable_output_reservations().unwrap();
            let mut bytes = [0; 2048];
            let (output, attempt) = server.poll_reserved_transmit(0, &mut bytes, 64).unwrap();
            let tx = output.packet.unwrap();
            let original = bytes[..tx.len].to_vec();
            let charge = server.buffer_bytes();
            let next = FastOpenKeyLease {
                not_before: 1,
                issue_until: 30,
                accept_until: 40,
                ..lease
            };
            let registry_before = server.fast_open_key_registry_usage().1;
            server
                .install_fast_open_key(1, server_key(&policy, 8), next, true)
                .unwrap();
            assert_eq!(
                server.buffer_bytes() - server.fast_open_key_registry_usage().1,
                charge - registry_before
            );
            assert_eq!(&bytes[..tx.len], &original);
            // Expiry and rotation cannot revoke already authorized data or
            // recompute the cookie committed to this child's SYN-ACK.
            assert!(server.accept_transmit(20, attempt.unwrap()).unwrap());
            let child = server.accept(listener).unwrap();
            let mut data = [0; 5];
            assert_eq!(server.read(child, &mut data), Ok(5));
            assert_eq!(&data, b"early");
            deliver(&mut client, 20, &(tx.ip, original));
            deliver(&mut server, 20, &packet(&mut client, 20));
            assert_eq!(server.state(child), Ok(State::Established));
            let replacement = lifecycle_open(&mut server, listener, v6, 20, 40002, old, false);
            assert!(replacement.is_some());
        }
    }
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn hmac_same_key_is_idempotent_while_retiring_under_linux_and_manual_change_revokes() {
    for v6 in [false, true] {
        let (mut server, _) = peer(2);
        let (_, remote) = addresses(v6, 40000);
        let listener = server.listen(remote, 16).unwrap();
        server.set_listener_fast_open(listener, 4).unwrap();
        let lease = FastOpenKeyLease {
            not_before: 0,
            issue_until: 10,
            accept_until: 20,
            units_per_second: 1_000_000,
        };
        server
            .install_fast_open_key(0, FastOpenServerKey::HmacSha256([7; 32]), lease, false)
            .unwrap();
        let (_, cookie) = learn(&mut server, listener, v6, 0, 40000);
        server
            .install_fast_open_key(
                1,
                FastOpenServerKey::LinuxSipHash24(LinuxSipHash24Key::new([8; 16])),
                FastOpenKeyLease {
                    not_before: 1,
                    issue_until: 30,
                    accept_until: 40,
                    ..lease
                },
                true,
            )
            .unwrap();
        server.set_fast_open_hmac_key([7; 32]);
        lifecycle_open(&mut server, listener, v6, 1, 40001, cookie, true);
        server.set_fast_open_hmac_key([9; 32]);
        let fresh = lifecycle_open(&mut server, listener, v6, 2, 40002, cookie, false).unwrap();
        lifecycle_open(&mut server, listener, v6, 2, 40003, fresh, true);
    }
}

fn policies() -> Vec<FastOpenCookiePolicy> {
    vec![
        FastOpenCookiePolicy::HmacSha256,
        #[cfg(feature = "tfo-linux-cookie")]
        FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([7; 16])),
    ]
}

// Obtain credentials exclusively from an actual passive endpoint and finish
// both sides of the handshake. Each client retains its independently learned cache.
fn learn(
    b: &mut Endpoint,
    listener: ListenerId,
    v6: bool,
    now: u64,
    port: u16,
) -> (Endpoint, FastOpenCookie) {
    let (mut a, _) = peer(1);
    let (local, remote) = addresses(v6, port);
    let (id, n) = a.connect_fast_open(now, local, remote, b"cold").unwrap();
    assert_eq!(n, 0);
    deliver(b, now, &packet(&mut a, now));
    let reply = packet(b, now);
    let cookie = wire::parse(reply.0, &reply.1)
        .unwrap()
        .options
        .fast_open
        .unwrap();
    deliver(&mut a, now, &reply);
    deliver(b, now, &packet(&mut a, now));
    let child = b.accept(listener).unwrap();
    assert_eq!(a.state(id), Ok(State::Established));
    assert_eq!(b.state(child), Ok(State::Established));
    (a, cookie)
}

fn open(
    a: &mut Endpoint,
    b: &mut Endpoint,
    listener: ListenerId,
    local: SocketAddr,
    remote: SocketAddr,
    now: u64,
    cookie: Option<FastOpenCookie>,
    early: bool,
) -> (ConnectionId, FastOpenCookie) {
    let options = ActiveOpenOptions::from(&ConnectionConfig::default());
    let (id, n) = a
        .connect_fast_open_with_server_cookie(now, local, remote, b"early", options, cookie)
        .unwrap();
    assert_eq!(n, 5);
    let syn = packet(a, now);
    let sent = wire::parse(syn.0, &syn.1).unwrap();
    if let Some(cookie) = cookie {
        assert_eq!(sent.options.fast_open, Some(cookie));
    }
    assert_eq!(sent.payload, b"early");
    deliver(b, now, &syn);
    let reply = packet(b, now);
    let received = wire::parse(reply.0, &reply.1).unwrap();
    assert_eq!(
        received.header.acknowledgment,
        sent.header.sequence.wrapping_add(if early { 6 } else { 1 })
    );
    let response_cookie = received.options.fast_open.or(cookie).unwrap();
    if early {
        let child = b.accept(listener).unwrap();
        assert_eq!(b.read(child, &mut [0; 5]), Ok(5));
    } else {
        assert!(b.accept(listener).is_err());
    }
    deliver(a, now, &reply);
    deliver(b, now, &packet(a, now));
    assert_eq!(a.state(id), Ok(State::Established));
    if !early {
        let child = b.accept(listener).unwrap();
        let mut data = [0; 5];
        assert_eq!(b.read(child, &mut data), Ok(5));
        assert_eq!(&data, b"early");
    }
    (id, response_cookie)
}

// The first validated SYN-ACK teaches the cache. Both server algorithms and
// both public client credential paths must preserve the server's opaque bytes.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1
//= type=test
//# The cookie is a MAC tag generated by the server and is opaque to the client; the client simply caches the cookie and passes it back on subsequent SYN packets to open new connections.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//# 4. A server may encode other information in the cookie and accept more than one valid cookie per client at any given time. But this is server-implementation dependent and transparent to the client.
#[test]
fn issued_cookies_are_opaque_for_learned_and_supplied_clients_and_adjacent_epochs() {
    for v6 in [false, true] {
        for policy in policies() {
            let (mut b, _) = peer(2);
            // This raw-byte test spans two HMAC epochs. Give the independent
            // Linux lease two hours explicitly; the production default is one.
            b.set_fast_open_cookie_lifetime(
                FastOpenCookieLifetime::from_micros(2 * crate::fast_open::LIFETIME_US).unwrap(),
            );
            b.set_fast_open_cookie_policy(policy.clone());
            let (_, remote) = addresses(v6, 40000);
            let listener = b.listen(remote, 16).unwrap();
            b.set_listener_fast_open(listener, 4).unwrap();
            let lifetime = crate::fast_open::LIFETIME_US;
            let (old_client, previous) = learn(&mut b, listener, v6, lifetime - 10, 40000);
            let (current_client, current) = learn(&mut b, listener, v6, lifetime + 10, 40001);
            if matches!(policy, FastOpenCookiePolicy::HmacSha256) {
                assert_ne!(previous, current);
            }
            let now = lifetime + 12345;
            for (i, (mut learned, cookie)) in [(old_client, previous), (current_client, current)]
                .into_iter()
                .enumerate()
            {
                for supplied in [false, true] {
                    let (local, remote) =
                        addresses(v6, 41000 + (i * 2 + usize::from(supplied)) as u16);
                    let (mut explicit, _) = peer(3);
                    let client = if supplied {
                        &mut explicit
                    } else {
                        &mut learned
                    };
                    if !supplied {
                        // The public API must use the bytes learned at its own epoch.
                        assert!(
                            client
                                .has_fast_open_cookie(now, local.ip(), remote.ip())
                                .unwrap()
                        );
                    }
                    let options = ActiveOpenOptions::from(&ConnectionConfig::default());
                    let (id, n) = client
                        .connect_fast_open_with_server_cookie(
                            now,
                            local,
                            remote,
                            b"early",
                            options,
                            supplied.then_some(cookie),
                        )
                        .unwrap();
                    assert_eq!(n, 5);
                    let syn = packet(client, now);
                    assert_eq!(
                        wire::parse(syn.0, &syn.1).unwrap().options.fast_open,
                        Some(cookie)
                    );
                    deliver(&mut b, now, &syn);
                    let reply = packet(&mut b, now);
                    let child = b.accept(listener).unwrap();
                    let mut data = [0; 5];
                    assert_eq!(b.read(child, &mut data), Ok(5));
                    assert_eq!(&data, b"early");
                    deliver(client, now, &reply);
                    deliver(&mut b, now, &packet(client, now));
                    assert_eq!(client.state(id), Ok(State::Established));
                    assert_eq!(b.state(child), Ok(State::Established));
                    assert!(client.transport_info(id).unwrap().syn_data_acked);
                }
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1
//= type=test
//# The server can expire the cookie at any time to enhance security.
#[test]
fn arbitrary_revocation_rejects_both_hmac_epochs_and_linux_keys_on_new_requests() {
    for v6 in [false, true] {
        for policy in policies() {
            for listener_override in [false, true] {
                let (mut b, _) = peer(2);
                b.set_fast_open_cookie_lifetime(
                    FastOpenCookieLifetime::from_micros(2 * crate::fast_open::LIFETIME_US).unwrap(),
                );
                let (_, remote) = addresses(v6, 40000);
                let listener = b.listen(remote, 16).unwrap();
                b.set_listener_fast_open(listener, 4).unwrap();
                if listener_override {
                    b.set_listener_fast_open_cookie_policy(listener, Some(policy.clone()))
                        .unwrap();
                } else {
                    b.set_fast_open_cookie_policy(policy.clone());
                }
                let lifetime = crate::fast_open::LIFETIME_US;
                let (mut previous_client, previous) =
                    learn(&mut b, listener, v6, lifetime - 10, 40000);
                let (mut current_client, current) =
                    learn(&mut b, listener, v6, lifetime + 10, 40001);
                let now = lifetime + 12345;
                // Changing a server key must leave this endpoint's active cache intact too.
                let (_, a_remote) = addresses(v6, 40002);
                let a_local = SocketAddr::new(a_remote.ip(), 42000);
                b.connect_fast_open(now, a_local, addresses(v6, 40002).0, &[])
                    .unwrap();
                let outbound = packet(&mut b, now);
                deliver(&mut b, now, &cache_reply(&outbound, 940, Some(&[91; 8])));
                packet(&mut b, now);
                let before = b.buffer_bytes();
                let registry_before = b.fast_open_key_registry_usage().1;
                b.try_set_fast_open_hmac_key([9; 32]).unwrap();
                #[cfg(feature = "tfo-linux-cookie")]
                if matches!(policy, FastOpenCookiePolicy::LinuxSipHash24(_)) {
                    let replacement =
                        FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([9; 16]));
                    if listener_override {
                        b.set_listener_fast_open_cookie_policy(listener, Some(replacement))
                            .unwrap();
                    } else {
                        b.try_set_fast_open_cookie_policy(replacement).unwrap();
                    }
                }
                assert_eq!(
                    b.buffer_bytes() - b.fast_open_key_registry_usage().1,
                    before - registry_before
                );
                let (local, _) = addresses(v6, 41000);
                let (_, fresh) = open(
                    &mut previous_client,
                    &mut b,
                    listener,
                    local,
                    remote,
                    now,
                    Some(previous),
                    false,
                );
                let (local, _) = addresses(v6, 41001);
                let (_, fresh_again) = open(
                    &mut current_client,
                    &mut b,
                    listener,
                    local,
                    remote,
                    now,
                    Some(current),
                    false,
                );
                assert_eq!(fresh, fresh_again);
                assert_ne!(fresh, current);
                let (mut a, _) = peer(4);
                let (local, _) = addresses(v6, 41002);
                b.set_fast_open_hmac_key([9; 32]); // Same-key replacement is idempotent.
                open(
                    &mut a,
                    &mut b,
                    listener,
                    local,
                    remote,
                    now,
                    Some(fresh),
                    true,
                );
                let active_local = SocketAddr::new(a_remote.ip(), 42001);
                let (_, n) = b
                    .connect_fast_open(now, active_local, addresses(v6, 40002).0, &[0; 1000])
                    .unwrap();
                assert_eq!(n, 900);
                let syn = packet(&mut b, now);
                assert_eq!(
                    wire::parse(syn.0, &syn.1).unwrap().options.fast_open,
                    Some(FastOpenCookie::new(&[91; 8]).unwrap())
                );
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1
//= type=test
//# The server can expire the cookie at any time to enhance security.
#[test]
fn hmac_revocation_preserves_snapshotted_responses_children_and_quota() {
    for v6 in [false, true] {
        for listener_override in [false, true] {
            let (mut b, _) = peer(2);
            let (_, remote) = addresses(v6, 40000);
            let listener = b.listen(remote, 16).unwrap();
            b.set_listener_fast_open(listener, 1).unwrap();
            if listener_override {
                b.set_listener_fast_open_cookie_policy(
                    listener,
                    Some(FastOpenCookiePolicy::HmacSha256),
                )
                .unwrap();
            }
            let (_, old) = learn(&mut b, listener, v6, 0, 40000);
            assert_eq!(
                old,
                crate::fast_open::issue(&[2; 32], remote.ip(), addresses(v6, 40000).0.ip(), 0)
            );
            let (mut a, options) = peer(1);
            let (local, _) = addresses(v6, 40001);
            a.connect_fast_open_with_server_cookie(0, local, remote, b"early", options, Some(old))
                .unwrap();
            let early_syn = packet(&mut a, 0);
            let early_sequence = wire::parse(early_syn.0, &early_syn.1)
                .unwrap()
                .header
                .sequence;
            deliver(&mut b, 0, &early_syn);
            b.enable_output_reservations().unwrap();
            let before = b.buffer_bytes();
            let registry_before = b.fast_open_key_registry_usage().1;
            b.try_set_fast_open_hmac_key([9; 32]).unwrap();
            let mut bytes = [0; 2048];
            let (out, token) = b.poll_reserved_transmit(0, &mut bytes, 64).unwrap();
            let tx = out.packet.unwrap();
            let child = tx.connection.unwrap();
            let first = bytes[..tx.len].to_vec();
            let decoded = wire::parse(tx.ip, &first).unwrap();
            assert_eq!(decoded.options.fast_open, Some(old));
            assert_eq!(
                decoded.header.acknowledgment,
                early_sequence.wrapping_add(6)
            );
            b.try_set_fast_open_hmac_key([10; 32]).unwrap();
            assert_eq!(
                b.buffer_bytes() - b.fast_open_key_registry_usage().1,
                before - registry_before
            );
            assert_eq!(&bytes[..tx.len], first);
            assert_eq!(b.accept(listener), Err(EndpointError::OutputReserved));
            assert!(b.reject_unsubmitted(token.unwrap()).unwrap());
            let (out, retry) = b
                .poll_reserved_transmit_for(0, child, &mut bytes, 64)
                .unwrap();
            let tx = out.packet.unwrap();
            let next = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            assert_eq!(decoded.header, next.header);
            assert_eq!(decoded.options, next.options);
            let held_reply = (tx.ip, bytes[..tx.len].to_vec());
            assert!(b.accept_transmit(0, retry.unwrap()).unwrap());
            assert_eq!(b.accept(listener), Ok(child));
            assert_eq!(b.read(child, &mut [0; 5]), Ok(5));
            let (mut c, _) = peer(3);
            let (local, _) = addresses(v6, 40002);
            // A fresh request obtains the replacement even while the old child
            // occupies the pending slot. A valid cookie does not bypass quota.
            let options = ActiveOpenOptions::from(&ConnectionConfig::default());
            c.connect_fast_open_with_server_cookie(0, local, remote, b"early", options, Some(old))
                .unwrap();
            let syn = packet(&mut c, 0);
            let sequence = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
            deliver(&mut b, 0, &syn);
            let response = packet(&mut b, 0);
            let reply = wire::parse(response.0, &response.1).unwrap();
            assert_eq!(reply.header.acknowledgment, sequence.wrapping_add(1));
            let fresh = reply.options.fast_open.unwrap();
            assert_ne!(fresh, old);
            let (mut d, _) = peer(4);
            let (local, _) = addresses(v6, 40003);
            d.connect_fast_open_with_server_cookie(
                0,
                local,
                remote,
                b"early",
                options,
                Some(fresh),
            )
            .unwrap();
            let syn = packet(&mut d, 0);
            let sequence = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
            deliver(&mut b, 0, &syn);
            let response = packet(&mut b, 0);
            assert_eq!(
                wire::parse(response.0, &response.1)
                    .unwrap()
                    .header
                    .acknowledgment,
                sequence.wrapping_add(1)
            );
            assert!(b.accept(listener).is_err());
            // Completing the already-authorized child releases its slot.
            deliver(&mut a, 0, &held_reply);
            deliver(&mut b, 0, &packet(&mut a, 0));
            let (mut e, _) = peer(5);
            let (local, _) = addresses(v6, 40004);
            open(
                &mut e,
                &mut b,
                listener,
                local,
                remote,
                0,
                Some(fresh),
                true,
            );
        }
    }
}

#[test]
fn hmac_key_change_is_deferred_while_protected_or_linux_policy_is_selected() {
    for v6 in [false, true] {
        for policy in policies() {
            let linux = !matches!(policy, FastOpenCookiePolicy::HmacSha256);
            let (mut b, _) = peer(2);
            b.set_fast_open_cookie_policy(policy);
            let (local, remote) = addresses(v6, 40000);
            let listener = b.listen(remote, 16).unwrap();
            b.set_listener_fast_open(listener, 2).unwrap();
            let (_, old) = learn(&mut b, listener, v6, 0, 40000);
            if !linux {
                b.set_listener_fast_open_early_data_policy(
                    listener,
                    FastOpenEarlyDataPolicy::ApplicationProtected,
                )
                .unwrap();
            }
            b.set_fast_open_hmac_key([9; 32]);
            let (mut a, options) = peer(1);
            let local = SocketAddr::new(local.ip(), 40001);
            if linux {
                // Replacing the HMAC key does not replace the selected Linux raw key.
                open(&mut a, &mut b, listener, local, remote, 0, Some(old), true);
            } else {
                let (_, n) = a
                    .connect_fast_open_with_policy(
                        0,
                        local,
                        remote,
                        b"early",
                        options,
                        FastOpenClientPolicy::ApplicationProtected,
                    )
                    .unwrap();
                assert_eq!(n, 5);
                deliver(&mut b, 0, &packet(&mut a, 0));
                let reply = packet(&mut b, 0);
                assert_eq!(
                    wire::parse(reply.0, &reply.1).unwrap().options.fast_open,
                    None
                );
                let child = b.accept(listener).unwrap();
                assert_eq!(b.read(child, &mut [0; 5]), Ok(5));
                deliver(&mut a, 0, &reply);
                deliver(&mut b, 0, &packet(&mut a, 0));
                b.set_listener_fast_open_early_data_policy(
                    listener,
                    FastOpenEarlyDataPolicy::RequireCookie,
                )
                .unwrap();
            }
            b.set_fast_open_cookie_policy(FastOpenCookiePolicy::HmacSha256);
            let (_, fresh) = learn(&mut b, listener, v6, 0, 40002);
            let (mut control, _) = peer(9);
            let l = control.listen(remote, 8).unwrap();
            control.set_listener_fast_open(l, 2).unwrap();
            let (_, expected) = learn(&mut control, l, v6, 0, 40000);
            assert_eq!(fresh, expected);
            assert_ne!(fresh, old);
        }
    }
}

fn drain(a: &mut Endpoint, now: u64) {
    while a
        .poll_transmit(now, &mut [0; 2048], 64)
        .unwrap()
        .packet
        .is_some()
    {}
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.1
//= type=test
//# 3. If the SYN-ACK has a Fast Open option with a cookie, the client replaces the cookie and other information as described in the "Client Cookie Handling" section (Section 4.1.3). Otherwise, if the SYN-ACK is first seen and not a (spurious) retransmission, the client MAY remove the server information from the cookie cache. If the SYN-ACK is a spurious retransmission, the client does nothing to the cookie cache for the reasons below.
#[test]
fn spurious_synacks_cannot_revert_parallel_cookie_mss_or_extend_lifetimes() {
    for v6 in [false, true] {
        for negative in [false, true] {
            let (mut a, options) = peer(1);
            let (local, remote) = addresses(v6, 40000);
            a.connect_fast_open(0, local, remote, &[]).unwrap();
            let old_syn = packet(&mut a, 0);
            let initial = cache_reply(&old_syn, 1460, Some(&[1; 8]));
            deliver(&mut a, 10, &initial);
            drain(&mut a, 10);
            let (local, _) = addresses(v6, 40001);
            a.connect_fast_open(20, local, remote, &[]).unwrap();
            let parallel_syn = packet(&mut a, 20);
            deliver(&mut a, 30, &cache_reply(&parallel_syn, 940, Some(&[2; 8])));
            drain(&mut a, 30);
            if negative {
                let (local, _) = addresses(v6, 40002);
                let (id, _) = a.connect_fast_open(40, local, remote, b"rejected").unwrap();
                let syn = packet(&mut a, 40);
                let mut rejected = cache_reply(&syn, 940, None);
                let seq = wire::parse(syn.0, &syn.1).unwrap().header.sequence;
                rejected.1[8..12].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
                repair_cache_checksum(rejected.0, &mut rejected.1);
                deliver(&mut a, 50, &rejected);
                drain(&mut a, 50);
                assert_eq!(a.state(id), Ok(State::Established));
            }
            // Includes identical, changed, absent, empty and bounded malformed cookies.
            for reply in [
                initial,
                cache_reply(&old_syn, 700, Some(&[3; 16])),
                cache_reply(&old_syn, 600, None),
                cache_reply(&old_syn, 500, Some(&[])),
                cache_reply(&old_syn, 400, Some(&[4; 3])),
            ] {
                deliver(&mut a, 100, &reply);
                drain(&mut a, 100);
            }
            let (local, _) = addresses(v6, 40003);
            let (_, n) = a.connect_fast_open(101, local, remote, &[7; 1000]).unwrap();
            assert_eq!(n, if negative { 0 } else { 900 });
            let syn = packet(&mut a, 101);
            if !negative {
                assert_eq!(
                    wire::parse(syn.0, &syn.1).unwrap().options.fast_open,
                    Some(FastOpenCookie::new(&[2; 8]).unwrap())
                );
            }
            if negative {
                let expiry = 50 + crate::fast_open::NEGATIVE_LIFETIME_US;
                assert!(
                    !a.can_defer_fast_open(expiry - 1, local.ip(), remote)
                        .unwrap()
                );
                assert!(a.can_defer_fast_open(expiry, local.ip(), remote).unwrap());
            }
            let expiry = 30 + crate::fast_open::LIFETIME_US;
            assert!(
                a.has_fast_open_cookie(expiry - 1, local.ip(), remote.ip())
                    .unwrap()
            );
            assert!(
                !a.has_fast_open_cookie(expiry, local.ip(), remote.ip())
                    .unwrap()
            );
            let (local, _) = addresses(v6, 40004);
            let mss_expiry = if negative { 50 } else { 30 } + crate::fast_open::LIFETIME_US;
            let (_, n) = a
                .connect_fast_open_with_server_cookie(
                    mss_expiry,
                    local,
                    remote,
                    &[8; 1000],
                    options,
                    Some(FastOpenCookie::new(&[2; 8]).unwrap()),
                )
                .unwrap();
            // Expired peer MSS restores conservative cold admission, rather
            // than keeping the newer or any spurious MSS alive.
            assert_eq!(n, 496);
        }
    }
}
