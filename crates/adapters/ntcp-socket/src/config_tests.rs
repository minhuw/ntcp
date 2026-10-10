// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

const BASE: &str = "io.interface=ntcp0\nio.address=10.73.0.2\n";

#[test]
fn parser_and_typed_validation() {
    let default = SocketConfig::new("ntcp0", "10.73.0.2".parse().unwrap());
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
        "tcp.pacing=true # inline",
        "[section]",
        "io.backend=native",
        "io.backend=af-packet",
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
        "192.0.2.1".parse().unwrap(),
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
    assert_eq!(base.tcp.connection.receive_ip_payload_limit, 65515);
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
        |c| c.tcp.connection.receive_ip_payload_limit = 65516,
        |c| c.tcp.ipv4_options_enabled = true,
        |c| c.tcp.max_connections = 513,
        |c| c.tcp.max_listeners = 513,
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
