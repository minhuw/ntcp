// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// The native runtime serves the opt-in path control socket from its owner
// loop: real ntcp-pathctl processes (this test binary re-executed as the
// utility, running the same `ntcp_path_control::cli`) administer the
// runtime's Host while its loop runs.
use super::*;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

const CHILD: &str = "NTCP_PATHCTL_CHILD_ARGS";

// Runs the utility when re-executed by `pathctl`; otherwise does nothing.
#[test]
fn pathctl_child() {
    let Some(args) = std::env::var_os(CHILD) else {
        return;
    };
    let args: Vec<String> = args
        .to_str()
        .unwrap()
        .split('\u{1f}')
        .map(String::from)
        .collect();
    let code = ntcp_path_control::cli::main(&args);
    use std::io::Write;
    let _ = std::io::stdout().flush();
    std::process::exit(i32::from(code));
}

// Run the utility as a separate process; its lines and exit code.
fn pathctl(socket: &std::path::Path, args: &[&str]) -> (String, String, i32) {
    let name = format!(
        "{}::pathctl_child",
        module_path!().split_once("::").unwrap().1
    );
    let mut joined = socket.to_str().unwrap().to_string();
    for arg in args {
        joined.push('\u{1f}');
        joined.push_str(arg);
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture", "--test-threads=1", "-q"])
        .env(CHILD, joined)
        .output()
        .unwrap();
    let lines: String = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|l| {
            ["route ", "path ", "client ", "applied", "plateaus=", "aging="]
                .iter()
                .any(|p| l.starts_with(p))
        })
        .map(|l| format!("{l}\n"))
        .collect();
    (
        lines,
        String::from_utf8(output.stderr).unwrap(),
        output.status.code().unwrap(),
    )
}

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.trim()
        .split(' ')
        .find_map(|kv| kv.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
        .unwrap_or_else(|| panic!("{key} missing in {line}"))
}

fn private_socket(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ntcp-socket-control-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir.join("control")
}

// A running native runtime over an external Ethernet fixture with one
// connecting TCP socket (so its path has a client), serving `control`.
fn runtime(v6: bool, control: ntcp_path_control::ControlConfig) -> Runtime {
    runtime_with(v6, control, None)
}

// With `held`, the fixture refuses every transmission (output stays held)
// and the owner keeps twice its socket limit of blocking reads pending, so
// every loop pass takes the held-output early continue.
fn runtime_with(
    v6: bool,
    control: ntcp_path_control::ControlConfig,
    held: Option<Arc<Mutex<State>>>,
) -> Runtime {
    Runtime::spawn(
        std::panic::AssertUnwindSafe(move || {
            let local: IpAddr = if v6 { "2001:db8::5" } else { "10.73.0.5" }.parse().unwrap();
            let peer: IpAddr = if v6 { "2001:db8::6" } else { "10.73.0.6" }.parse().unwrap();
            let mut config = SocketConfig::new("external", local);
            config.io.source_quiet = crate::SourceQuiet::Never;
            config.io.prefix = Some(if v6 { 64 } else { 24 });
            config.tcp.max_connections = 2;
            config.io.egress_capacity = 2;
            config.control = Some(control);
            if held.is_some() {
                // Held output outlives the test instead of expiring.
                config.io.output_reservation_timeout_ms = 120_000;
            }
            let state = held.clone().unwrap_or_else(|| {
                Arc::new(Mutex::new(State {
                    mtu: Some(1500),
                    max_packet_len: Some(2048),
                    ..Default::default()
                }))
            });
            let mut owner = Owner::external_backend(
                &config,
                crate::EthernetPacketIo {
                    io: Box::new(Fixture(state)),
                    local_mac: [2; 6],
                    next_hop_mac: Some([4; 6]),
                },
            )?;
            owner.start_control(config.control.as_ref())?;
            let socket = new(&mut owner, if held.is_some() { 0 } else { SOCK_NONBLOCK });
            let _ = owner.execute(socket, Op::Connect(SocketAddr::new(peer, 8080)));
            if held.is_some() {
                owner.service_egress()?;
                let (reply, _) = std::sync::mpsc::sync_channel(1);
                for _ in 0..2 * owner.socket_limit() {
                    owner.pending.push_back(Request {
                        id: socket,
                        op: Op::Read(16),
                        reply: reply.clone(),
                        deadline: None,
                        send: None,
                        closing: None,
                    });
                }
            }
            Ok(owner)
        }),
        false,
    )
    .unwrap()
}

#[test]
fn native_runtime_serves_pathctl_processes_from_its_owner_loop() {
    for v6 in [false, true] {
        let socket = private_socket(if v6 { "v6" } else { "v4" });
        let running = runtime(
            v6,
            ntcp_path_control::ControlConfig {
                socket: socket.clone(),
                allow_uids: Vec::new(),
            },
        );
        let (routes, _, code) = pathctl(&socket, &["routes"]);
        assert_eq!(code, 0);
        let token = field(&routes, "token").to_string();
        let (paths, _, _) = pathctl(&socket, &["paths"]);
        assert_eq!(field(&paths, "budget"), "1500");
        assert_eq!(field(&paths, "route"), token);
        let path = field(&paths, "token").to_string();
        let (clients, _, _) = pathctl(&socket, &["clients", &path]);
        assert!(clients.lines().any(|l| field(l, "kind") == "tcp"), "{clients}");
        // Disable discovery on the runtime's route: the existing path's
        // budget is the IPv6 minimum link MTU, or 576 for IPv4 behind the
        // runtime's forwarder next hop.
        let (applied, stderr, code) = pathctl(&socket, &["disable", "route", &token]);
        assert_eq!(code, 0, "{stderr}");
        assert_eq!(applied.trim(), "applied generation=1 affected_paths=1");
        let (paths, _, _) = pathctl(&socket, &["paths"]);
        assert_eq!(field(&paths, "effective_disabled"), "route");
        assert_eq!(field(&paths, "budget"), if v6 { "1280" } else { "576" });
        // A stale compare-and-set changes nothing.
        let (_, stderr, code) = pathctl(&socket, &["set", "route", &token, "0"]);
        assert_eq!((code, stderr.trim()), (1, "status=stale"));
        let (routes, _, _) = pathctl(&socket, &["routes"]);
        assert_eq!(field(&routes, "generation"), "1");
        assert_eq!(field(&routes, "disabled"), "1");
        drop(running);
        assert!(std::fs::symlink_metadata(&socket).is_err());
    }
    // A peer outside the allow-list is refused before dispatch.
    let socket = private_socket("denied");
    let me = unsafe { libc::geteuid() };
    let _running = runtime(
        false,
        ntcp_path_control::ControlConfig {
            socket: socket.clone(),
            allow_uids: vec![me.wrapping_add(1)],
        },
    );
    let (_, stderr, code) = pathctl(&socket, &["disable", "route", "0000000000000001"]);
    assert_eq!((code, stderr.trim()), (1, "status=unauthorized"));
}

#[test]
fn control_is_served_while_output_is_held() {
    let state = Arc::new(Mutex::new(State {
        mtu: Some(1500),
        max_packet_len: Some(2048),
        block: true,
        ..Default::default()
    }));
    let socket = private_socket("held");
    let _running = runtime_with(
        true,
        ntcp_path_control::ControlConfig {
            socket: socket.clone(),
            allow_uids: Vec::new(),
        },
        Some(state.clone()),
    );
    let (routes, _, code) = pathctl(&socket, &["routes"]);
    assert_eq!(code, 0);
    let token = field(&routes, "token").to_string();
    let (applied, stderr, code) = pathctl(&socket, &["disable", "route", &token]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(applied.trim(), "applied generation=1 affected_paths=1");
    let (paths, _, _) = pathctl(&socket, &["paths"]);
    assert_eq!(field(&paths, "budget"), "1280");
    // Output stayed held throughout: the SYN was offered and never sent.
    let state = state.lock().unwrap();
    assert!(!state.offered.is_empty());
    assert!(state.sent.is_empty());
}

#[test]
fn control_configuration_is_separate_from_route_keys() {
    let base = "io.interface=ntcp0\nio.address=10.73.0.2\n";
    let config = SocketConfig::parse(&format!(
        "{base}control.socket=/run/ntcp/control\ncontrol.allow_uids=1000,1001\nroute.10.0.0.1.mtu=1400\n"
    ))
    .unwrap();
    assert_eq!(
        config.control,
        Some(ntcp_path_control::ControlConfig {
            socket: "/run/ntcp/control".into(),
            allow_uids: vec![1000, 1001],
        })
    );
    assert_eq!(config.routes.len(), 1);
    assert_eq!(SocketConfig::parse(base).unwrap().control, None);
    for bad in [
        "control.socket=relative/control\n",
        "control.allow_uids=1000\n",
        "control.socket=/run/ntcp/control\ncontrol.allow_uids=x\n",
        "route.10.0.0.1.control=/run/ntcp/control\n",
    ] {
        assert!(SocketConfig::parse(&format!("{base}{bad}")).is_err(), "{bad}");
    }
}
