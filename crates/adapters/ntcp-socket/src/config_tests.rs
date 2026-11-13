// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

const BASE: &str = "io.interface=ntcp0\nio.address=10.73.0.2\n";

// The running boot and its transport time, from the real provider: a lease is
// checked against what the provider reads, so nothing here models that fact.
fn this_boot() -> (ntcp_clock::BootId, u64) {
    let mut clock = ntcp_clock::TransportClock::new().unwrap();
    let now = clock.sample().unwrap().ticks;
    (clock.characterization().boot_id, now)
}
// Another boot's id: this one with its first digit changed.
fn other_boot(boot: ntcp_clock::BootId) -> String {
    let text = boot.to_string();
    let first = if text.starts_with('0') { '1' } else { '0' };
    format!("{first}{}", &text[1..])
}
fn lease_lines(boot: impl std::fmt::Display, not_before: u64, issue: u64, accept: u64) -> String {
    format!(
        "socket.fast_open_key_boot_id={boot}\nsocket.fast_open_key_not_before_us={not_before}\nsocket.fast_open_key_issue_until_us={issue}\nsocket.fast_open_key_accept_until_us={accept}\n"
    )
}
const UNMANAGED: &str = "socket.fast_open_managed_keys=false\n";
const HOUR: u64 = 3_600_000_000;

#[test]
fn finite_cookie_lifetime_and_explicit_lease_configuration() {
    let (boot, now) = this_boot();
    let (not_before, issue_until, accept_until) = (now, now + HOUR, now + 2 * HOUR);
    let lease = lease_lines(boot, not_before, issue_until, accept_until);
    let config = SocketConfig::parse(&format!(
        "{BASE}{UNMANAGED}socket.fast_open_cookie_lifetime_us=100\n{lease}"
    ))
    .unwrap();
    assert_eq!(config.fast_open_managed_keys, Some(false));
    assert_eq!(config.fast_open_cookie_lifetime.as_micros(), 100);
    assert_eq!(config.fast_open_key_boot_id, Some(boot));
    assert_eq!(
        config.fast_open_key_lease.unwrap(),
        ntcp::FastOpenKeyLease {
            not_before,
            issue_until,
            accept_until,
            units_per_second: 1_000_000,
        }
    );
    let managed = lease_lines(boot, not_before, issue_until, accept_until);
    let id = format!("socket.fast_open_key_boot_id={boot}");
    let issue = format!("socket.fast_open_key_issue_until_us={issue_until}");
    let accept = format!("socket.fast_open_key_accept_until_us={accept_until}");
    let early = format!("socket.fast_open_key_accept_until_us={}", issue_until - 1);
    for suffix in [
        "socket.fast_open_cookie_lifetime_us=0".to_string(),
        "socket.fast_open_cookie_lifetime_us=18446744073709551615".to_string(),
        "socket.fast_open_managed_keys=1".to_string(),
        format!("{id}\n{issue}"),
        format!("{id}\n{issue}\n{early}"),
        format!("socket.fast_open_managed_keys=true\n{managed}"),
        format!("{id}\n{issue}\n{accept}"),
    ] {
        assert!(
            SocketConfig::parse(&format!("{BASE}{suffix}")).is_err(),
            "{suffix}"
        );
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-3
//= type=test
//= reason=Actual IPv4/IPv6 endpoints repeatedly reuse credentials before expiry, reject expired SYN data at admission and complete ordinary TCP byte delivery with fresh-cookie learning or no-cookie fallback. HMAC keeps current/previous epochs; LinuxSipHash24 keeps raw bytes under finite key leases. Raw epoch-independent codec vectors are not server acceptance evidence. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# 5. The rest of the connection proceeds like a normal TCP connection. The
//# client can repeat many Fast Open operations once it acquires a cookie
//# (until the cookie is expired by the server).
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Endpoint admission enforces finite HMAC current/previous epochs and LinuxSipHash24 key leases with absolute issue/accept deadlines, including delayed service, retiring keys and same-key no-renewal through the endpoint-owned identity registry across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux validation intentionally ignores epoch, including u64::MAX, to preserve wire bytes; that raw codec result is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# 5. The cookie expires after a certain amount of time. The reason for
//# cookie expiration is detailed in the "Security Considerations" section
//# (Section 5). This can be done by either periodically changing the server
//# key used to generate cookies or including a timestamp when generating
//# the cookie.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Passive admission authenticates both address families using current/retiring bounded key contexts consulting one endpoint-owned identity/deadline registry, finite HMAC epochs and LinuxSipHash24 leases. Traffic tests reject expired and invalid credentials exactly at deadlines and complete fallback; raw Linux epoch-independent codec validation alone is not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# - IsCookieValid(IP_Address, Cookie): checks if the cookie is valid,
//# i.e., it has not expired and the cookie authenticates the client IP
//# address.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=Repeated Fast Open, manual key revocation, finite HMAC epochs and LinuxSipHash24 key leases are exercised through actual endpoints in both IP families. Admission checks issue/accept deadlines without timer service; expired and invalid credentials complete ordinary TCP, fresh keys teach usable replacements, and same-key reinstalls cannot renew expired leases in the endpoint authority across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux epoch-independent codec tests are not server acceptance. External raw keys are accepted only with their original lease in CLOCK_BOOTTIME microseconds of the boot socket.fast_open_key_boot_id names: another boot's lease, an expired lease or an external key without one is refused at configuration, a restarted process reinstalling the same key keeps the original deadlines, and setsockopt(TCP_FASTOPEN_KEY) selects only a configured key under its lease. HMAC keys are per-process secrets whose epochs derive from transport time.
//# Once the client obtains the cookie from the target server, it can
//# perform subsequent TFO connections until the cookie is expired by the
//# server.
#[test]
fn a_lease_is_refused_unless_it_names_this_boot_and_is_unexpired() {
    let (boot, now) = this_boot();
    let (issue, accept) = (now + HOUR, now + 2 * HOUR);
    let parse = |lease: String| SocketConfig::parse(&format!("{BASE}{UNMANAGED}{lease}"));
    parse(lease_lines(boot, now, issue, accept)).unwrap();
    // Without a boot id these are the numbers of no named clock.
    let unnamed = lease_lines(boot, now, issue, accept);
    let unnamed = unnamed.split_once('\n').unwrap().1.to_string();
    assert!(parse(unnamed).is_err());
    // A boot id names the boot of a lease; without one it is inert.
    assert!(parse(format!("socket.fast_open_key_boot_id={boot}\n")).is_err());
    assert!(parse(lease_lines(other_boot(boot), now, issue, accept)).is_err());
    for malformed in ["x", "1", &boot.to_string().to_uppercase().replace('-', "_")] {
        assert!(parse(lease_lines(malformed, now, issue, accept)).is_err());
    }
    // Issuance over, acceptance not: the original lease still runs.
    parse(lease_lines(boot, now - 2, now - 1, accept)).unwrap();
    // Already expired, and not begun for the key installed at startup.
    assert!(parse(lease_lines(boot, now - 2, now - 1, now)).is_err());
    assert!(parse(lease_lines(boot, now + HOUR, issue + 1, accept)).is_err());
    // Today's process-relative numbers from before D5 are not reinterpreted.
    assert!(parse(lease_lines(boot, 10, 110, 210)).is_err());

    // The exact expiry boundary, against a stated reading of this boot.
    let config = parse(lease_lines(boot, now, issue, accept)).unwrap();
    config.check_fast_open_leases(boot, accept - 1).unwrap();
    assert!(config.check_fast_open_leases(boot, accept).is_err());
    assert!(
        config
            .check_fast_open_leases(ntcp_clock::BootId::parse(&other_boot(boot)).unwrap(), now)
            .is_err()
    );
}

#[cfg(feature = "tfo-linux-cookie")]
const RAW: &str = "socket.fast_open_cookie=linux-siphash24\nsocket.fast_open_key=00112233445566778899aabbccddeeff\n";

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn an_external_key_needs_its_lease_and_a_generated_one_does_not() {
    let (boot, now) = this_boot();
    let lease = lease_lines(boot, now, now + HOUR, now + HOUR);
    for suffix in ["", UNMANAGED] {
        assert!(SocketConfig::parse(&format!("{BASE}{RAW}{suffix}")).is_err());
        SocketConfig::parse(&format!("{BASE}{RAW}{suffix}{lease}")).unwrap();
    }
    // Managed keys and the per-process secret are the stack's own.
    SocketConfig::parse(&format!("{BASE}{RAW}socket.fast_open_managed_keys=true\n")).unwrap();
    SocketConfig::parse(&format!("{BASE}{UNMANAGED}")).unwrap();
    SocketConfig::parse(BASE).unwrap();
}

#[cfg(feature = "tfo-linux-cookie")]
#[test]
fn further_keys_are_configured_with_their_own_leases() {
    let (boot, now) = this_boot();
    let primary = lease_lines(boot, now, now + HOUR, now + HOUR);
    let key = |name: &str, hex: &str, (from, issue, accept): (u64, u64, u64)| {
        format!(
            "socket.fast_open_key.{name}={hex}\nsocket.fast_open_key.{name}.not_before_us={from}\nsocket.fast_open_key.{name}.issue_until_us={issue}\nsocket.fast_open_key.{name}.accept_until_us={accept}\n"
        )
    };
    let (a, b) = ("0102030405060708090a0b0c0d0e0f10", "1112131415161718191a1b1c1d1e1f20");
    let live = (now, now + HOUR, now + HOUR);
    // Waiting for its `not_before`: a scheduled rotation.
    let next = (now + HOUR, now + 2 * HOUR, now + 2 * HOUR);
    let config = SocketConfig::parse(&format!(
        "{BASE}{RAW}{primary}{}{}",
        key("next", a, live),
        key("later", b, next)
    ))
    .unwrap();
    assert_eq!(config.fast_open_keys.len(), 2);
    assert_eq!(
        config.fast_open_keys[0].key,
        ntcp::LinuxSipHash24Key::new(core::array::from_fn(|i| i as u8 + 1))
    );
    assert_eq!(config.fast_open_keys[1].lease.not_before, now + HOUR);
    // They stand beside managed primary keys, under the same boot id.
    let id = format!("socket.fast_open_key_boot_id={boot}\n");
    SocketConfig::parse(&format!("{BASE}{id}{}", key("next", a, live))).unwrap();
    let refused = [
        key("next", a, live), // No boot id.
        format!("{id}{}", key("next", a, (now - 2, now - 1, now))), // Expired.
        format!("{id}{}", key("next", a, (now, now + HOUR, now))), // Inverted.
        format!("{id}{}", key("next", "short", live)),
        format!("{id}socket.fast_open_key.next.issue_until_us={}\n", now + 1), // No key.
        format!("{id}socket.fast_open_key.next={a}\n"), // No lease.
        format!("{id}{}socket.fast_open_key.next.other=1\n", key("next", a, live)),
        format!("{id}{}{}", key("x", a, live), key("y", a, next)), // One key, two leases.
    ];
    for suffix in refused {
        assert!(SocketConfig::parse(&format!("{BASE}{suffix}")).is_err(), "{suffix}");
    }
    // The primary key has its one lease.
    let same = key("next", "00112233445566778899aabbccddeeff", live);
    assert!(SocketConfig::parse(&format!("{BASE}{RAW}{primary}{same}")).is_err());
}

#[cfg(not(feature = "tfo-linux-cookie"))]
#[test]
fn further_keys_need_the_raw_codec() {
    let suffix = "socket.fast_open_key.next=0102030405060708090a0b0c0d0e0f10\n";
    assert!(SocketConfig::parse(&format!("{BASE}{suffix}")).is_err());
}

#[test]
fn parser_and_typed_validation() {
    let default = SocketConfig::new("ntcp0", "10.73.0.2".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(
        format!("{:?}", SocketConfig::parse(BASE).unwrap()),
        format!("{default:?}")
    );
    assert_eq!(
        SocketConfig::parse(&format!(" # comment\n\n {BASE}io.prefix = 24\n"))
            .unwrap()
            .io
            .prefix,
        Some(24)
    );
    let config = SocketConfig::parse(&format!("{BASE}io.backend=af-packet\nio.next_hop_mac=02:00:00:00:00:01\ntcp.pacing=true\ntcp.pacing_gain_percent=150\ntcp.pacing_max_bytes_per_second=18446744073709551615\ntcp.pacing_burst_segments=3")).unwrap();
    assert_eq!(
        config.tcp.connection.pacing.unwrap(),
        ntcp::PacingConfig {
            rate_gain_percent: 150,
            max_bytes_per_second: Some(u64::MAX),
            max_burst_segments: 3,
            initial_window_burst: true,
        }
    );
    for suffix in [
        "unknown=x",
        "io.interface=other",
        "io.address=10.0.0.1",
        "io.prefix=33",
        "io.prefix=-1",
        "io.prefix=+1",
        "tcp.pacing=1",
        "tcp.pacing_initial_window_burst=false",
        "tcp.pacing=true\ntcp.pacing_initial_window_burst=1",
        "tcp.pacing=true # inline",
        "[section]",
        "io.backend=native",
        "io.next_hop_mac=02:00:00:00:00:01",
        "tcp.pacing_gain_percent=125",
        "tcp.pacing_burst_segments=2",
        "tcp.pacing_max_bytes_per_second=1",
        "tcp.pacing=true\ntcp.pacing_gain_percent=0",
        "tcp.pacing=true\ntcp.pacing_gain_percent=65536",
        "tcp.pacing=true\ntcp.pacing_max_bytes_per_second=0",
        "tcp.pacing=true\ntcp.pacing_max_bytes_per_second=18446744073709551616",
        "tcp.pacing=true\ntcp.pacing_burst_segments=0",
        "tcp.pacing=true\ntcp.pacing_burst_segments=4294967295",
        "io.backend=af-packet\nio.next_hop_mac=00:00:00:00:00:00",
        "io.backend=af-packet\nio.next_hop_mac=01:00:00:00:00:01",
        "io.backend=af-packet\nio.next_hop_mac=2:00:00:00:00:01",
        "io.backend=af-packet\nio.next_hop_mac=02:00:00:00:00:gg",
    ] {
        assert_eq!(
            SocketConfig::parse(&format!("{BASE}{suffix}"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput,
            "{suffix}"
        );
    }
    for text in [
        "io.interface=ntcp0",
        "io.address=10.73.0.2",
        "io.interface=\"ntcp0\"\nio.address=10.73.0.2",
        "io.interface=ntcp0\nio.address=::1",
        "io.interface=ntcp0\nio.address=127.0.0.1",
        "io.interface=ntcp0\nio.address=224.0.0.1",
    ] {
        assert!(SocketConfig::parse(text).is_err());
    }
    let mut typed = default;
    typed.tcp.connection.pacing = Some(ntcp::PacingConfig::default());
    assert!(typed.validate().is_ok());
    typed
        .tcp
        .connection
        .pacing
        .as_mut()
        .unwrap()
        .max_burst_segments = u32::MAX;
    assert!(typed.validate().is_err());
}

#[test]
fn bounded_regular_utf8_file() {
    let path = std::env::temp_dir().join(format!("ntcp-config-{}", std::process::id()));
    std::fs::write(&path, BASE).unwrap();
    assert_eq!(
        format!("{:?}", SocketConfig::from_file(&path).unwrap()),
        format!("{:?}", SocketConfig::parse(BASE).unwrap())
    );
    std::fs::write(&path, [0xff]).unwrap();
    assert_eq!(
        SocketConfig::from_file(&path).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let mut exact = BASE.to_owned();
    exact.push('#');
    exact.push_str(&"x".repeat(MAX_FILE_BYTES - exact.len()));
    std::fs::write(&path, &exact).unwrap();
    assert!(SocketConfig::from_file(&path).is_ok());
    exact.push('x');
    std::fs::write(&path, &exact).unwrap();
    assert!(SocketConfig::from_file(&path).is_err());
    assert!(SocketConfig::parse(&exact).is_err());
    std::fs::remove_file(&path).unwrap();
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert_eq!(
        SocketConfig::from_file(&path).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    std::fs::remove_file(&path).unwrap();
    assert!(SocketConfig::from_file(std::env::temp_dir()).is_err());
    assert_eq!(
        SocketConfig::from_file(&path).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn selection_subprocess() {
    const CHILD: &str = "NTCP_CONFIG_TEST_CHILD";
    let Ok(scenario) = std::env::var(CHILD) else {
        for scenario in [
            "native",
            "typed",
            "invalid",
            "missing",
            "malformed",
            "file",
            "race",
            "configure-race",
            "fork",
            "reentrant",
        ] {
            let path = std::env::temp_dir().join(format!("ntcp-selection-{}", std::process::id()));
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "config::tests::selection_subprocess",
                "--nocapture",
            ])
            .env(CHILD, scenario)
            .env_remove("NTCP_SOCKET_CONFIG");
            if matches!(scenario, "missing" | "malformed" | "file") {
                if scenario != "missing" {
                    std::fs::write(&path, if scenario == "file" { BASE } else { "invalid" })
                        .unwrap();
                }
                cmd.env("NTCP_SOCKET_CONFIG", &path);
            }
            // Legacy settings must have no influence, even when invalid.
            for key in [
                "BACKEND",
                "TUN",
                "IFACE",
                "ADDR",
                "PREFIX",
                "NEXT_HOP_MAC",
                "PACING",
            ] {
                cmd.env(format!("NTCP_SOCKET_{key}"), "invalid");
            }
            assert!(cmd.status().unwrap().success(), "{scenario}");
            if scenario == "malformed" || scenario == "file" {
                std::fs::remove_file(&path).unwrap();
            }
        }
        return;
    };
    let config = SocketConfig::parse(BASE).unwrap();
    let classify = || crate::ntcp_boundary_socket(libc::AF_INET, libc::SOCK_STREAM);
    match scenario.as_str() {
        "native" => {
            assert_eq!(classify(), 0);
            let fd = unsafe { crate::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            assert!(fd >= 0);
            assert_eq!(crate::ntcp_boundary_fd(fd), 0);
            unsafe {
                libc::syscall(libc::SYS_close, fd);
            }
            assert_eq!(
                crate::configure(config).unwrap_err().raw_os_error(),
                Some(libc::EALREADY)
            );
        }
        "file" => {
            assert_eq!(classify(), 1);
            assert_eq!(
                format!(
                    "{:?}",
                    crate::CONFIG
                        .get()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                ),
                format!("{config:?}")
            );
            assert_eq!(
                crate::configure(config).unwrap_err().raw_os_error(),
                Some(libc::EALREADY)
            );
        }
        "configure-race" => {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    let barrier = barrier.clone();
                    let config = config.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        crate::configure(config)
                    })
                })
                .collect();
            let mut winners = 0;
            for thread in threads {
                match thread.join().unwrap() {
                    Ok(()) => winners += 1,
                    Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EALREADY)),
                }
            }
            assert_eq!(winners, 1);
            assert_eq!(classify(), 1);
        }
        "fork" => {
            // Fork while another thread owns selection's OnceLock: the child
            // must reject before waiting on a thread which no longer exists.
            crate::PID.store(
                std::process::id() as i32,
                std::sync::atomic::Ordering::Release,
            );
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                crate::CONFIG.get_or_init(|| {
                    ready_tx.send(()).unwrap();
                    done_rx.recv().unwrap();
                    Ok(Some(config))
                });
            });
            ready_rx.recv().unwrap();
            let pid = unsafe { libc::syscall(libc::SYS_fork) };
            assert!(pid >= 0);
            if pid == 0 {
                let good = classify() == -1 && crate::errno() == libc::EOWNERDEAD;
                unsafe {
                    libc::syscall(libc::SYS_exit_group, if good { 0 } else { 1 });
                }
                unreachable!();
            }
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid as i32, &mut status, 0) },
                pid as i32
            );
            assert_eq!(status, 0);
            done_tx.send(()).unwrap();
            thread.join().unwrap();
        }
        "reentrant" => {
            crate::DEPTH.with(|depth| depth.set(1));
            assert_eq!(classify(), -1);
            assert_eq!(crate::errno(), libc::EDEADLK);
            crate::DEPTH.with(|depth| depth.set(0));
            let old = crate::set_internal(true);
            assert_eq!(
                crate::configure(config.clone()).unwrap_err().raw_os_error(),
                Some(libc::EDEADLK)
            );
            crate::set_internal(old);
            assert!(crate::CONFIG.get().is_none());
            crate::configure(config).unwrap();
        }
        "typed" => {
            crate::configure(config.clone()).unwrap();
            assert_eq!(classify(), 1);
            assert_eq!(
                crate::configure(config).unwrap_err().raw_os_error(),
                Some(libc::EALREADY)
            );
        }
        "invalid" => {
            let mut bad = config.clone();
            bad.tcp.connection.pacing = Some(ntcp::PacingConfig {
                rate_gain_percent: 0,
                ..Default::default()
            });
            assert_eq!(
                crate::configure(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(classify(), -1);
            assert_eq!(
                unsafe { crate::socket(libc::AF_INET, libc::SOCK_STREAM, 0) },
                -1
            );
            assert_eq!(crate::errno(), libc::EINVAL);
            assert_eq!(
                crate::configure(config).unwrap_err().raw_os_error(),
                Some(libc::EALREADY)
            );
        }
        "missing" | "malformed" => {
            for _ in 0..2 {
                assert_eq!(
                    unsafe { crate::socket(libc::AF_INET, libc::SOCK_STREAM, 0) },
                    -1
                );
                assert_eq!(
                    crate::errno(),
                    if scenario == "missing" {
                        libc::ENOENT
                    } else {
                        libc::EINVAL
                    }
                );
            }
            assert_eq!(
                crate::configure(config).unwrap_err().raw_os_error(),
                Some(libc::EALREADY)
            );
        }
        "race" => {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let other = barrier.clone();
            let thread = std::thread::spawn(move || {
                other.wait();
                crate::configure(config)
            });
            barrier.wait();
            let managed = classify();
            let configured = thread.join().unwrap();
            match managed {
                0 => assert_eq!(configured.unwrap_err().raw_os_error(), Some(libc::EALREADY)),
                1 => configured.unwrap(),
                _ => panic!("selection failed"),
            }
            assert_eq!(classify(), managed);
        }
        _ => unreachable!(),
    }
}

#[cfg(feature = "packet-test")]
#[test]
fn packet_profile_ignores_production_configuration() {
    const CHILD: &str = "NTCP_CONFIG_PACKET_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "config::tests::packet_profile_ignores_production_configuration"
                ])
                .env(CHILD, "1")
                .env("NTCP_SOCKET_CONFIG", "/nonexistent/ntcp-config")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    crate::packet_test::start((
        "192.0.2.1".parse::<std::net::IpAddr>().unwrap(),
        crate::packet_profile::Profile::Baseline,
    ))
    .unwrap();
    let fd = unsafe { crate::packet_test::packet_socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);
    assert_eq!(crate::ntcp_boundary_fd(fd), 1);
    assert!(crate::CONFIG.get().is_none());
    assert_eq!(unsafe { crate::close(fd) }, 0);
    crate::packet_test::stop();
}

#[test]
fn layering_order_defaults_and_adapter_constraints() {
    let base = SocketConfig::parse(BASE).unwrap();
    assert_eq!(base.tcp.max_connections, 512);
    assert_eq!(base.tcp.max_listeners, 512);
    assert_eq!(base.tcp.max_control_packets, 512);
    assert_eq!(base.tcp.max_buffer_bytes, 128 * 1024 * 1024);
    assert_eq!(base.tcp.connection.send_capacity, 65536);
    assert_eq!(base.tcp.connection.receive_capacity, 65536);
    assert_eq!(base.tcp.connection.mss, 1460);
    assert_eq!(base.tcp.connection.send_ip_payload_limit, 1480);
    // Native connections are Host-managed: their receive MSS offer comes
    // from the Host's receive capability, so no static receive limit is
    // configured and the raw-Endpoint legacy limit keeps its default.
    assert_eq!(
        base.tcp.connection.receive_ip_payload_limit,
        ntcp::ConnectionConfig::default().receive_ip_payload_limit
    );
    assert!(base.validate().is_ok());
    assert_eq!(base.tcp.connection.pacing, None);
    for tuning in [
        "tcp.pacing_gain_percent=150",
        "tcp.pacing_burst_segments=3",
        "tcp.pacing_max_bytes_per_second=4000",
    ] {
        for enabled in ["true", "false"] {
            for suffix in [
                format!("{tuning}\ntcp.pacing={enabled}"),
                format!("tcp.pacing={enabled}\n{tuning}"),
            ] {
                assert_eq!(
                    SocketConfig::parse(&format!("{BASE}{suffix}")).is_ok(),
                    enabled == "true"
                );
            }
        }
    }
    for key in [
        "backend",
        "interface",
        "address",
        "prefix",
        "next_hop_mac",
        "pacing",
        "pacing_gain_percent",
        "pacing_burst_segments",
        "pacing_max_bytes_per_second",
    ] {
        assert!(SocketConfig::parse(&format!("{BASE}{key}=1")).is_err());
    }
    let invalid: &[fn(&mut SocketConfig)] = &[
        |c| c.tcp.connection.timebase.units_per_second = 1_000_000_000,
        |c| c.tcp.connection.send_ip_payload_limit = 65516,
        |c| c.tcp.ipv4_options_enabled = true,
        |c| c.tcp.max_connections = 0,
        |c| c.tcp.max_listeners = 0,
        |c| c.tcp.preallocate_connections = 513,
        |c| {
            c.tcp.preallocate_connections = 1;
            c.tcp.max_buffer_bytes = 1;
        },
        |c| c.tcp.connection.send_capacity = 0,
        |c| c.tcp.connection.rto_min_us = 0,
        |c| c.tcp.connection.tlp = true,
        |c| c.tcp.dscp = 64,
        |c| {
            c.tcp.connection.keepalive = Some(ntcp::KeepaliveConfig {
                idle_us: 1,
                ..Default::default()
            })
        },
        |c| {
            c.tcp.connection.keepalive = Some(ntcp::KeepaliveConfig {
                send_garbage: true,
                ..Default::default()
            })
        },
    ];
    for mutate in invalid {
        let mut c = base.clone();
        mutate(&mut c);
        assert!(c.validate().is_err(), "{c:?}");
    }
    let mut ethernet = base.clone();
    ethernet.io.backend = Backend::AfPacket;
    ethernet.io.next_hop_mac = Some([2, 0, 0, 0, 0, 1]);
    assert!(ethernet.validate().is_ok());
    assert_eq!(format!("{:?}", ethernet.tcp), format!("{:?}", base.tcp));
}

#[test]
fn reservation_timeout_parser_and_typed_bounds() {
    assert_eq!(
        SocketConfig::parse(BASE)
            .unwrap()
            .io
            .output_reservation_timeout_ms,
        1000
    );
    for value in ["1", "1000", "4294967295"] {
        let c = SocketConfig::parse(&format!("{BASE}io.output_reservation_timeout_ms={value}"))
            .unwrap();
        assert_eq!(
            c.io.output_reservation_timeout_ms,
            value.parse::<u32>().unwrap()
        );
    }
    for value in ["0", "-1", "+1", "1.5", "4294967296", "", "1 # ms"] {
        assert!(
            SocketConfig::parse(&format!("{BASE}io.output_reservation_timeout_ms={value}"))
                .is_err()
        );
    }
    assert!(SocketConfig::parse(&format!("{BASE}output_reservation_timeout_ms=1")).is_err());
    assert!(
        SocketConfig::parse(&format!(
            "{BASE}io.output_reservation_timeout_ms=1\nio.output_reservation_timeout_ms=2"
        ))
        .is_err()
    );
    let mut c = SocketConfig::parse(BASE).unwrap();
    c.io.output_reservation_timeout_ms = 0;
    assert!(c.validate().is_err());
}

#[test]
fn egress_capacity_is_a_positive_resource_bound() {
    assert_eq!(SocketConfig::parse(BASE).unwrap().io.egress_capacity, 32);
    for capacity in [1, 2, 32, 128] {
        let config = SocketConfig::parse(&format!("{BASE}io.egress_capacity={capacity}")).unwrap();
        assert_eq!(config.io.egress_capacity, capacity);
        assert_eq!(config.tcp.max_buffer_bytes, 128 * 1024 * 1024);
    }
    for value in ["0", "-1", "+1", "1.5", "18446744073709551615"] {
        assert!(SocketConfig::parse(&format!("{BASE}io.egress_capacity={value}")).is_err());
    }
    let mut config = SocketConfig::parse(BASE).unwrap();
    config.io.egress_capacity = 0;
    assert!(config.validate().is_err());
}

#[test]
fn software_gso_bounds_are_optional_paired_and_fail_closed() {
    let original = SocketConfig::parse(BASE).unwrap();
    assert_eq!(original.io.gso, None);
    let config = SocketConfig::parse(&format!(
        "{BASE}io.gso_max_bytes=65536\nio.gso_max_segments=16"
    ))
    .unwrap();
    assert_eq!(
        config.io.gso,
        Some(ntcp::GsoLimits {
            max_bytes: 65536,
            max_segments: 16
        })
    );
    assert_eq!(
        config.tcp.connection.send_ip_payload_limit,
        original.tcp.connection.send_ip_payload_limit
    );
    assert_eq!(config.tcp.max_buffer_bytes, original.tcp.max_buffer_bytes);
    for suffix in [
        "io.gso_max_bytes=65536",
        "io.gso_max_segments=16",
        "io.gso_max_bytes=0\nio.gso_max_segments=2",
        "io.gso_max_bytes=65536\nio.gso_max_segments=1",
        "io.gso_max_bytes=2\nio.gso_max_segments=3",
        "io.gso_max_bytes=2147483648\nio.gso_max_segments=2",
        "io.gso_max_bytes=-1\nio.gso_max_segments=2",
        "io.gso_max_bytes=+2\nio.gso_max_segments=2",
        "io.gso_max_bytes=2\nio.gso_max_segments=2\nio.gso_max_segments=2",
    ] {
        assert!(
            SocketConfig::parse(&format!("{BASE}{suffix}")).is_err(),
            "{suffix}"
        );
    }
    for limits in [
        ntcp::GsoLimits {
            max_bytes: 0,
            max_segments: 2,
        },
        ntcp::GsoLimits {
            max_bytes: 65536,
            max_segments: 1,
        },
        ntcp::GsoLimits {
            max_bytes: 2,
            max_segments: 3,
        },
        ntcp::GsoLimits {
            max_bytes: usize::MAX,
            max_segments: 2,
        },
    ] {
        let mut config = original.clone();
        config.io.gso = Some(limits);
        assert!(config.validate().is_err());
    }
}

#[test]
fn socket_notsent_lowat_full_unsigned_range_and_strict_keys() {
    assert_eq!(
        SocketConfig::parse(BASE).unwrap().socket.notsent_lowat,
        u32::MAX
    );
    for value in [0, 1, 4000, i32::MAX as u32 + 1, u32::MAX] {
        let config = SocketConfig::parse(&format!("{BASE}socket.notsent_lowat={value}")).unwrap();
        assert_eq!(config.socket.notsent_lowat, value);
        config.validate().unwrap();
    }
    for suffix in [
        "socket.notsent_lowat=-1",
        "socket.notsent_lowat=+1",
        "socket.notsent_lowat=4294967296",
        "socket.notsent_lowat=1.0",
        "socket.notsent_lowat=0xffffffff",
        "socket.notsent_lowat=",
        "socket.notsent_lowat=4000\nsocket.notsent_lowat=4000",
        "socket.notsent_lowat=0\nsocket.notsent_lowat=1",
        "notsent_lowat=4000",
        "tcp.notsent_lowat=4000",
        "io.notsent_lowat=4000",
        "socket.unknown=4000",
    ] {
        assert!(
            SocketConfig::parse(&format!("{BASE}{suffix}")).is_err(),
            "{suffix}"
        );
    }
}

#[test]
fn client_tfo_permission_configuration_is_strict_and_defaults_to_allowed() {
    assert!(
        SocketConfig::parse(BASE)
            .unwrap()
            .socket
            .fast_open_client_enabled
    );
    for enabled in [false, true] {
        let parsed = SocketConfig::parse(&format!(
            "{BASE}socket.fast_open_client_enabled={enabled}\n"
        ))
        .unwrap();
        assert_eq!(parsed.socket.fast_open_client_enabled, enabled);
        assert!(parsed.validate().is_ok());
    }
    for value in [
        "0",
        "1",
        "TRUE",
        "false # comment",
        "false\nsocket.fast_open_client_enabled=true",
    ] {
        assert!(
            SocketConfig::parse(&format!("{BASE}socket.fast_open_client_enabled={value}\n"))
                .is_err()
        );
    }
}

#[test]
fn endpoint_connections_and_listeners_are_configured_without_a_runtime_cap() {
    let changed = SocketConfig::parse(&format!(
        "{BASE}tcp.max_connections=20000\ntcp.max_listeners=1024\n"
    ))
    .unwrap();
    assert_eq!(changed.tcp.max_connections, 20000);
    assert_eq!(changed.tcp.max_listeners, 1024);
    assert!(changed.validate().is_ok());
    for key in ["tcp.max_connections", "tcp.max_listeners"] {
        for value in ["0", "-1", "+5", "many"] {
            let config = SocketConfig::parse(&format!("{BASE}{key}={value}\n"));
            assert!(
                config.is_err() || config.unwrap().validate().is_err(),
                "{key}={value}"
            );
        }
    }
}

// tcp.wmem and tcp.rmem take Linux's "min initial max", tcp.mem its
// "low pressure high" (in bytes); the endpoint reports them as it took them.
// By default both are tuned up to Linux master's tcp_wmem[2] and
// tcp_rmem[2].
#[test]
fn buffer_sizes_and_memory_are_configured_as_the_sysctls() {
    let baseline = SocketConfig::parse(BASE).unwrap();
    assert_eq!(
        baseline.tcp.buffers().to_string(),
        "wmem=4096 65536 4194304 rmem=4096 65536 33554432 mem=67108864 89478485 134217728"
    );
    let changed = SocketConfig::parse(&format!(
        "{BASE}tcp.wmem=4096 16384 4194304\ntcp.rmem=4096\t131072  33554432\ntcp.mem=1000 2000 3000000\n"
    ))
    .unwrap();
    assert!(changed.validate().is_ok());
    assert_eq!(
        changed.tcp.buffers().to_string(),
        "wmem=4096 16384 4194304 rmem=4096 131072 33554432 mem=1000 2000 3000000"
    );
    assert_eq!(changed.tcp.connection.send_capacity, 16384);
    assert_eq!(changed.tcp.connection.receive_capacity, 131072);
    for (key, value) in [
        ("tcp.wmem", "4096 65536"),
        ("tcp.wmem", "4096 65536 65536 1"),
        ("tcp.wmem", "0 65536 65536"),
        ("tcp.wmem", "8192 4096 65536"),
        ("tcp.wmem", "4096 65536 4096"),
        ("tcp.wmem", "4096 65536 1073741824"),
        ("tcp.rmem", "4096 65536 1073725441"),
        ("tcp.rmem", "4096 -1 65536"),
        ("tcp.mem", "1 2"),
        ("tcp.mem", "1 2 x"),
        // low < pressure <= high, as EndpointConfig::validate requires.
        ("tcp.mem", "2000 2000 3000"),
        ("tcp.mem", "1000 4000 3000"),
    ] {
        assert!(
            SocketConfig::parse(&format!("{BASE}{key}={value}\n")).is_err(),
            "{key}={value}"
        );
    }
}

#[test]
fn advertised_receive_mss_config_is_independent_of_send_and_receive_capacity() {
    let baseline = SocketConfig::parse(BASE).unwrap();
    assert_eq!(baseline.tcp.connection.advertised_mss, None);
    for value in [1, 600, 1460, u16::MAX] {
        let mut changed =
            SocketConfig::parse(&format!("{BASE}tcp.advertised_mss={value}\n")).unwrap();
        assert_eq!(changed.tcp.connection.advertised_mss, Some(value));
        changed.tcp.connection.advertised_mss = None;
        assert_eq!(format!("{changed:?}"), format!("{baseline:?}"));
    }
    for value in [
        "0",
        "65536",
        "-1",
        "+600",
        "none",
        "600\ntcp.advertised_mss=700",
    ] {
        assert!(SocketConfig::parse(&format!("{BASE}tcp.advertised_mss={value}\n")).is_err());
    }
    let mut invalid = baseline;
    invalid.tcp.connection.advertised_mss = Some(0);
    assert!(invalid.validate().is_err());
}

#[test]
fn destination_route_parser_and_typed_bounds() {
    let config = SocketConfig::parse(&format!("{BASE}route.192.0.2.1.mtu=640\nroute.192.0.2.1.advertised_mss=600\nroute.192.0.2.1.initial_search_low=552\nroute.192.0.2.2.mtu=1400\n")).unwrap();
    assert_eq!(config.routes.len(), 2);
    assert_eq!(
        config.routes[0],
        (
            "192.0.2.1".parse::<std::net::IpAddr>().unwrap(),
            ntcp::RoutePolicy {
                mtu: Some(640),
                advertised_mss: Some(600),
                initial_search_low: Some(552),
                ..Default::default()
            }
        )
    );
    assert!(config.tcp.connection.pmtud.is_none()); // Actual first-hop comes from IO.
    for suffix in [
        "route.0.0.0.0.mtu=640",
        "route.127.0.0.1.mtu=640",
        "route.224.0.0.1.mtu=640",
        "route.192.0.2.1.mtu=0",
        "route.192.0.2.1.mtu=65536",
        "route.192.0.2.1.advertised_mss=0",
        "route.192.0.2.1.mtu=640\nroute.192.0.2.1.initial_search_low=700",
        "route.192.0.2.1.mtu=640\nroute.192.0.2.1.mtu=700",
        "route.192.0.2.1.unknown=640",
        "route.192.0.2.1.mtu=+640",
    ] {
        assert!(
            SocketConfig::parse(&format!("{BASE}{suffix}\n")).is_err(),
            "{suffix}"
        );
    }
    let mut bad = config.clone();
    bad.routes.push(bad.routes[0]);
    assert!(bad.validate().is_err());
    let mut bad = config;
    bad.tcp.max_route_policies = 1;
    assert!(bad.validate().is_err());
}

#[test]
fn destination_route_api_before_config_does_not_select_runtime() {
    const CHILD: &str = "NTCP_ROUTE_NO_CONFIG_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "config::tests::destination_route_api_before_config_does_not_select_runtime",
                    "--test-threads=1"
                ])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    assert_eq!(
        crate::set_destination_route("192.0.2.1".parse::<std::net::IpAddr>().unwrap(), None)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EINVAL)
    );
    assert!(crate::CONFIG.get().is_none() && crate::RUNTIME.get().is_none());
}

#[test]
fn receive_aggregation_is_explicit_native_socket_capability() {
    let base = SocketConfig::parse(BASE).unwrap();
    assert!(!base.io.receive_aggregation);
    assert!(SocketConfig::parse(&format!("{BASE}io.receive_aggregation=true\n")).is_err());
    let mut af = base.clone();
    af.io.backend = Backend::AfPacket;
    af.io.next_hop_mac = Some([2, 0, 0, 0, 0, 1]);
    af.io.receive_aggregation = true;
    assert!(af.validate().is_ok());
    for value in ["1", "on", "TRUE", ""] {
        assert!(SocketConfig::parse(&format!("{BASE}io.receive_aggregation={value}\n")).is_err());
    }
    assert!(SocketConfig::parse(&format!("{BASE}io.receive_aggregation=false\n")).is_ok());
}

#[test]
fn parser_initial_window_burst_opt_out_and_default() {
    for (setting, expected) in [
        ("", true),
        ("\ntcp.pacing_initial_window_burst=false", false),
        ("\ntcp.pacing_initial_window_burst=true", true),
    ] {
        let c = SocketConfig::parse(&format!("{BASE}tcp.pacing=true{setting}")).unwrap();
        assert_eq!(
            c.tcp.connection.pacing.unwrap().initial_window_burst,
            expected
        );
    }
}

#[test]
fn explicit_client_early_policy_parser_keeps_authenticated_default() {
    assert_eq!(
        SocketConfig::parse(BASE)
            .unwrap()
            .socket
            .fast_open_client_policy,
        ntcp::FastOpenClientPolicy::RequireCookie
    );
    assert_eq!(
        SocketConfig::parse(&format!(
            "{BASE}socket.fast_open_client_policy=application-protected\n"
        ))
        .unwrap()
        .socket
        .fast_open_client_policy,
        ntcp::FastOpenClientPolicy::ApplicationProtected
    );
    for value in ["true", "cookie-less", "unknown", ""] {
        assert!(
            SocketConfig::parse(&format!("{BASE}socket.fast_open_client_policy={value}\n"))
                .is_err()
        );
    }
}

#[test]
fn segment_routes_parse_separately_from_route_policies() {
    const BASE6: &str = "io.interface=ntcp0\nio.address=2001:db8:1::2\n";
    let default = SocketConfig::parse(BASE6).unwrap();
    assert!(default.segment_routes.is_empty());
    let config = SocketConfig::parse(&format!(
        "{BASE6}ipv6.srh.2001:db8:d::/48=2001:db8:5::1, 2001:db8:6::1\n\
         ipv6.srh.2001:db8:e::9/128=2001:db8:5::1\n\
         route.2001:db8:d::9.mtu=1400\n"
    ))
    .unwrap();
    let v6 = |s: &str| s.parse::<std::net::Ipv6Addr>().unwrap();
    assert_eq!(
        config.segment_routes,
        [
            crate::SegmentRoute {
                destination: "2001:db8:d::/48".parse().unwrap(),
                segments: vec![v6("2001:db8:5::1"), v6("2001:db8:6::1")],
            },
            crate::SegmentRoute {
                destination: "2001:db8:e::9/128".parse().unwrap(),
                segments: vec![v6("2001:db8:5::1")],
            },
        ]
    );
    assert_eq!(config.routes.len(), 1);
    let max = (0..126)
        .map(|i| format!("2001:db8:100:{i:x}::1"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        SocketConfig::parse(&format!("{BASE6}ipv6.srh.2001:db8:d::/48={max}\n"))
            .unwrap()
            .segment_routes[0]
            .segments
            .len(),
        126
    );
    for suffix in [
        // Duplicate and ambiguous definitions of one prefix.
        "ipv6.srh.2001:db8:d::/48=2001:db8:5::1\nipv6.srh.2001:db8:d::/48=2001:db8:6::1".to_string(),
        "ipv6.srh.2001:db8:d::/48=2001:db8:5::1\nipv6.srh.2001:db8:d:0::/48=2001:db8:6::1".to_string(),
        // IPv4, scoped, non-canonical or malformed prefixes.
        "ipv6.srh.192.0.2.0/24=2001:db8:5::1".to_string(),
        "ipv6.srh.fe80::/64=2001:db8:5::1".to_string(),
        "ipv6.srh.2001:db8:d::1/48=2001:db8:5::1".to_string(),
        "ipv6.srh.2001:db8:d::=2001:db8:5::1".to_string(),
        "ipv6.srh.2001:db8:d::/+48=2001:db8:5::1".to_string(),
        // Unsupported scoped, multicast, loopback, IPv4 or empty segments.
        "ipv6.srh.2001:db8:d::/48=fe80::1".to_string(),
        "ipv6.srh.2001:db8:d::/48=ff02::1".to_string(),
        "ipv6.srh.2001:db8:d::/48=::1".to_string(),
        "ipv6.srh.2001:db8:d::/48=::".to_string(),
        "ipv6.srh.2001:db8:d::/48=192.0.2.1".to_string(),
        "ipv6.srh.2001:db8:d::/48=2001:db8:5::1,".to_string(),
        // 127 segments exceed the 8-bit Hdr Ext Len.
        format!("ipv6.srh.2001:db8:d::/48={max},2001:db8:200::1"),
    ] {
        assert!(
            SocketConfig::parse(&format!("{BASE6}{suffix}\n")).is_err(),
            "{suffix}"
        );
    }
    // An IPv4 interface carries no SR route.
    assert!(SocketConfig::parse(&format!("{BASE}ipv6.srh.2001:db8:d::/48=2001:db8:5::1\n")).is_err());
}

#[test]
fn named_ports_parse_with_the_io_port_fields_and_validation() {
    let config = SocketConfig::parse(&format!(
        "{BASE}io.prefix=24\nport.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.prefix=24\nport.c-2.interface=ntcp2\nport.c-2.address=10.73.2.2\n"
    ))
    .unwrap();
    // The `io.*` port is unchanged; additional ports keep their order.
    assert_eq!(config.io.interface, "ntcp0");
    assert_eq!(config.io.address, "10.73.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(
        config.ports,
        vec![
            PortConfig {
                name: "b".into(),
                interface: "ntcp1".into(),
                address: "10.73.1.2".parse().unwrap(),
                prefix: Some(24),
                next_hop_mac: None,
                gateways: Vec::new(),
                neighbors: Vec::new(),
            },
            PortConfig {
                name: "c-2".into(),
                interface: "ntcp2".into(),
                address: "10.73.2.2".parse().unwrap(),
                prefix: None,
                next_hop_mac: None,
                gateways: Vec::new(),
                neighbors: Vec::new(),
            },
        ]
    );
    // Without port keys there are no additional ports.
    assert!(SocketConfig::parse(BASE).unwrap().ports.is_empty());
    let af = "io.backend=af-packet\nio.interface=eth0\nio.address=10.73.0.2\nio.next_hop_mac=02:00:00:00:00:01\n";
    let config = SocketConfig::parse(&format!(
        "{af}port.b.interface=eth1\nport.b.address=10.73.1.2\nport.b.next_hop_mac=02:00:00:00:00:02\n"
    ))
    .unwrap();
    assert_eq!(config.ports[0].next_hop_mac, Some([2, 0, 0, 0, 0, 2]));
    let v6 = "io.interface=ntcp0\nio.address=fe80::1\n";
    // A link-local address is unique only on its own link.
    let config =
        SocketConfig::parse(&format!("{v6}port.b.interface=ntcp1\nport.b.address=fe80::1\n")).unwrap();
    assert_eq!(config.ports[0].address, "fe80::1".parse::<IpAddr>().unwrap());
    // A TUN port and a fixed-next-hop port resolve no IP next hop, so an
    // otherwise valid gateway route on them could never carry traffic and
    // is refused.
    for gateway in [
        format!("{BASE}io.prefix=24\nport.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.prefix=24\nport.b.gateway.10.80.0.0/16=10.73.1.1\n"),
        format!("{v6}port.b.interface=ntcp1\nport.b.address=2001:db8:1::2\nport.b.prefix=64\nport.b.gateway.2001:db8:5::/48=fe80::fe\n"),
        format!("{af}port.b.interface=eth1\nport.b.address=10.73.1.2\nport.b.prefix=24\nport.b.next_hop_mac=02:00:00:00:00:02\nport.b.gateway.10.80.0.0/16=10.73.1.1\n"),
    ] {
        assert!(SocketConfig::parse(&gateway).is_err(), "{gateway}");
    }
    for suffix in [
        // Duplicate keys, a repeated interface and missing fields.
        "port.b.interface=ntcp1\nport.b.interface=ntcp2\nport.b.address=10.73.1.2",
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.c.interface=ntcp1\nport.c.address=10.73.2.2",
        "port.b.interface=ntcp0\nport.b.address=10.73.1.2",
        "port.b.address=10.73.1.2",
        "port.b.interface=ntcp1",
        // Unknown fields and malformed names.
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.mtu=1400",
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.backend=tun",
        "port.b!.interface=ntcp1\nport.b!.address=10.73.1.2",
        "port..interface=ntcp1",
        "port.b=ntcp1",
        // One global address on two ports.
        "port.b.interface=ntcp1\nport.b.address=10.73.0.2",
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.c.interface=ntcp2\nport.c.address=10.73.1.2",
        // The same validation as the io.* fields.
        "port.b.interface=nt/cp\nport.b.address=10.73.1.2",
        "port.b.interface=ntcp1\nport.b.address=224.0.0.1",
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.prefix=33",
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.next_hop_mac=02:00:00:00:00:02",
        "port.b.interface=ntcp1\nport.b.address=2001:db8::2",
        // Gateways on a TUN port are refused whatever they name (the
        // on-link, family, canonical-prefix, own-address and duplicate
        // checks are exercised on the resolving port below).
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.prefix=24\nport.b.gateway.10.80.0.0/16=10.74.0.1",
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.gateway.10.80.0.0/16=10.73.1.1",
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.prefix=24\nport.b.gateway.10.80.0.1/16=10.73.1.1",
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.prefix=24\nport.b.gateway.10.80.0.0/16=10.73.1.2",
        "port.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.prefix=24\nport.b.gateway.2001:db8::/32=10.73.1.1",
    ] {
        assert!(
            SocketConfig::parse(&format!("{BASE}{suffix}\n")).is_err(),
            "{suffix}"
        );
    }
    // An AF_PACKET port without a fixed next hop resolves its next hops:
    // IPv4 through static neighbors on its prefix, which every IPv4 gateway
    // needs, IPv6 by Neighbor Discovery (with link-local gateways).
    let resolving = SocketConfig::parse(&format!(
        "{af}port.b.interface=eth1\nport.b.address=10.73.1.2\nport.b.prefix=24\nport.b.neighbor.10.73.1.1=02:00:00:00:00:0a\nport.b.gateway.10.80.0.0/16=10.73.1.1\n"
    ))
    .unwrap();
    assert_eq!(resolving.ports[0].next_hop_mac, None);
    assert_eq!(
        resolving.ports[0].neighbors,
        vec![("10.73.1.1".parse().unwrap(), [2, 0, 0, 0, 0, 0xa])]
    );
    assert_eq!(resolving.ports[0].gateways.len(), 1);
    let af6 = "io.backend=af-packet\nio.interface=eth0\nio.address=2001:db8::2\nio.next_hop_mac=02:00:00:00:00:01\n";
    let resolving = SocketConfig::parse(&format!(
        "{af6}port.b.interface=eth1\nport.b.address=fe80::1\nport.b.prefix=64\nport.b.gateway.2001:db8:5::/48=fe80::fe\n"
    ))
    .unwrap();
    assert_eq!(resolving.ports[0].gateways.len(), 1);
    // An AF_PACKET `io.*` port without `io.next_hop_mac` resolves its next
    // hops like a named port (D3: the fixed MAC is the legacy forwarder).
    let io = SocketConfig::parse(
        "io.backend=af-packet\nio.interface=eth0\nio.address=10.73.0.2\nio.prefix=24\n",
    )
    .unwrap();
    assert!(io.io.resolves() && io.io.gateways.is_empty());
    // A resolving port owns its address on its configured subnet, which
    // startup needs: without a prefix it is refused here.
    for config in [
        "io.backend=af-packet\nio.interface=eth0\nio.address=10.73.0.2\n".to_string(),
        "io.backend=af-packet\nio.interface=eth0\nio.address=fe80::1\n".to_string(),
        format!("{af6}port.b.interface=eth1\nport.b.address=fe80::1\n"),
    ] {
        assert!(SocketConfig::parse(&config).is_err(), "{config}");
    }
    let port = "port.b.interface=eth1\nport.b.address=10.73.1.2\nport.b.prefix=24";
    for suffix in [
        // Gateways on a resolving port: on its own link, of its family,
        // canonical, not its own address, one route per destination, and an
        // IPv4 next hop needs its static neighbor.
        "port.b.neighbor.10.74.0.1=02:00:00:00:00:0a\nport.b.gateway.10.80.0.0/16=10.74.0.1",
        "port.b.neighbor.10.73.1.1=02:00:00:00:00:0a\nport.b.gateway.10.80.0.1/16=10.73.1.1",
        "port.b.gateway.10.80.0.0/16=10.73.1.2",
        "port.b.neighbor.10.73.1.1=02:00:00:00:00:0a\nport.b.gateway.2001:db8::/32=10.73.1.1",
        "port.b.gateway.10.80.0.0/16=10.73.1.1",
        "port.b.neighbor.10.73.1.1=02:00:00:00:00:0a\nport.b.gateway.10.80.0.0/16=10.73.1.1\nport.b.gateway.10.80.0.0/16=10.73.1.3",
        // Static neighbors: unicast on the port's prefix, not its own
        // address, a unicast MAC, one mapping per address.
        "port.b.neighbor.10.74.0.1=02:00:00:00:00:0a",
        "port.b.neighbor.10.73.1.2=02:00:00:00:00:0a",
        "port.b.neighbor.10.73.1.255=02:00:00:00:00:0a",
        "port.b.neighbor.10.73.1.1=01:00:5e:00:00:01",
        "port.b.neighbor.10.73.1.1=00:00:00:00:00:00",
        "port.b.neighbor.10.73.1.1=02:00:00:00:00:0a\nport.b.neighbor.10.73.1.1=02:00:00:00:00:0b",
        "port.b.neighbor.10.73.1.1=nonsense",
        // A fixed-next-hop port uses no static neighbors.
        "port.b.next_hop_mac=02:00:00:00:00:02\nport.b.neighbor.10.73.1.1=02:00:00:00:00:0a",
    ] {
        assert!(
            SocketConfig::parse(&format!("{af}{port}\n{suffix}\n")).is_err(),
            "{suffix}"
        );
    }
    // IPv6 resolves by Neighbor Discovery, never through static neighbors,
    // and a TUN port uses none.
    for config in [
        format!("{af6}port.b.interface=eth1\nport.b.address=fe80::1\nport.b.neighbor.fe80::fe=02:00:00:00:00:0a\n"),
        format!("{BASE}io.prefix=24\nport.b.interface=ntcp1\nport.b.address=10.73.1.2\nport.b.prefix=24\nport.b.neighbor.10.73.1.1=02:00:00:00:00:0a\n"),
    ] {
        assert!(SocketConfig::parse(&config).is_err(), "{config}");
    }
    // Typed configuration is validated the same way: duplicate names.
    let mut config = SocketConfig::parse(BASE).unwrap();
    let port = PortConfig {
        name: "b".into(),
        interface: "ntcp1".into(),
        address: "10.73.1.2".parse().unwrap(),
        prefix: None,
        next_hop_mac: None,
        gateways: Vec::new(),
        neighbors: Vec::new(),
    };
    config.ports = vec![
        port.clone(),
        PortConfig {
            interface: "ntcp2".into(),
            address: "10.73.2.2".parse().unwrap(),
            ..port.clone()
        },
    ];
    assert!(config.validate().is_err());
    config.ports[1].name = "c".into();
    config.validate().unwrap();
}

// The `io.*` port resolving its next hops: `io.gateway.<prefix>` and
// `io.neighbor.<address>` mirror the `port.<name>` keys with the same
// validation; a fixed `io.next_hop_mac` or a TUN `io.*` port refuses them,
// and Segment Routing routes need the fixed forwarder's default route.
#[test]
fn resolving_io_port_takes_gateways_and_static_neighbors() {
    let af = "io.backend=af-packet\nio.interface=eth0\nio.address=10.73.1.2\nio.prefix=24\n";
    let config = SocketConfig::parse(&format!(
        "{af}io.neighbor.10.73.1.1=02:00:00:00:00:0a\nio.gateway.10.80.0.0/16=10.73.1.1\n"
    ))
    .unwrap();
    assert_eq!(config.io.next_hop_mac, None);
    assert_eq!(
        config.io.neighbors,
        vec![("10.73.1.1".parse().unwrap(), [2, 0, 0, 0, 0, 0xa])]
    );
    assert_eq!(
        config.io.gateways,
        vec![("10.80.0.0/16".parse().unwrap(), "10.73.1.1".parse().unwrap())]
    );
    let af6 = "io.backend=af-packet\nio.interface=eth0\nio.address=fe80::1\nio.prefix=64\n";
    let config =
        SocketConfig::parse(&format!("{af6}io.gateway.2001:db8:5::/48=fe80::fe\n")).unwrap();
    assert_eq!(config.io.gateways.len(), 1);
    for suffix in [
        "io.neighbor.10.74.0.1=02:00:00:00:00:0a\nio.gateway.10.80.0.0/16=10.74.0.1",
        "io.neighbor.10.73.1.1=02:00:00:00:00:0a\nio.gateway.10.80.0.1/16=10.73.1.1",
        "io.gateway.10.80.0.0/16=10.73.1.2",
        "io.gateway.10.80.0.0/16=10.73.1.1",
        "io.neighbor.10.73.1.1=02:00:00:00:00:0a\nio.gateway.10.80.0.0/16=10.73.1.1\nio.gateway.10.80.0.0/16=10.73.1.3",
        "io.neighbor.10.73.1.2=02:00:00:00:00:0a",
        "io.neighbor.10.73.1.255=02:00:00:00:00:0a",
        "io.neighbor.10.73.1.1=01:00:5e:00:00:01",
        "io.neighbor.10.73.1.1=nonsense",
        "io.gateway.nonsense=10.73.1.1",
        // The legacy fixed forwarder resolves nothing.
        "io.next_hop_mac=02:00:00:00:00:02\nio.neighbor.10.73.1.1=02:00:00:00:00:0a",
        "io.next_hop_mac=02:00:00:00:00:02\nio.neighbor.10.73.1.1=02:00:00:00:00:0a\nio.gateway.10.80.0.0/16=10.73.1.1",
    ] {
        assert!(SocketConfig::parse(&format!("{af}{suffix}\n")).is_err(), "{suffix}");
    }
    for config in [
        // IPv6 uses Neighbor Discovery, never static neighbors.
        format!("{af6}io.neighbor.fe80::fe=02:00:00:00:00:0a\n"),
        // A TUN `io.*` port resolves nothing.
        format!("io.interface=ntcp0\nio.address=10.73.1.2\nio.prefix=24\nio.neighbor.10.73.1.1=02:00:00:00:00:0a\nio.gateway.10.80.0.0/16=10.73.1.1\n"),
        format!("io.interface=ntcp0\nio.address=2001:db8::2\nio.gateway.2001:db8:5::/48=fe80::fe\n"),
        // SR routes are installed through the fixed forwarder.
        format!("{af6}ipv6.srh.2001:db8:9::/48=2001:db8:7::1\n"),
    ] {
        assert!(SocketConfig::parse(&config).is_err(), "{config}");
    }
    // The legacy form keeps its SR routes.
    let legacy = "io.backend=af-packet\nio.interface=eth0\nio.address=2001:db8::2\nio.next_hop_mac=02:00:00:00:00:01\n";
    assert!(SocketConfig::parse(&format!("{legacy}ipv6.srh.2001:db8:9::/48=2001:db8:7::1\n")).is_ok());
}
