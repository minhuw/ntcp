// tun_echo serves the opt-in path control socket from its loop: real
// ntcp-pathctl processes (this test binary re-executed as the utility,
// running the same `ntcp_path_control::cli`) administer its Host.
use super::*;
use std::os::unix::fs::DirBuilderExt;
use std::time::Duration;

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

// Run the utility as a separate process while tun_echo's control pass
// serves it; its key=value lines, stderr and exit code.
fn pathctl(
    server: &mut ntcp_path_control::Server,
    network: &mut TunHost,
    endpoint: &mut Endpoint,
    args: &[&str],
) -> (String, String, i32) {
    let name = format!(
        "{}::pathctl_child",
        module_path!().split_once("::").unwrap().1
    );
    let mut joined = server.path().to_str().unwrap().to_string();
    for arg in args {
        joined.push('\u{1f}');
        joined.push_str(arg);
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture", "--test-threads=1", "-q"])
        .env(CHILD, joined)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let begin = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(begin.elapsed() < Duration::from_secs(20), "pathctl hung");
        server.service(&mut network.host, endpoint, 0);
        std::thread::sleep(Duration::from_millis(1));
    }
    let output = child.wait_with_output().unwrap();
    let lines: String = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|l| ["route ", "path ", "client ", "applied"].iter().any(|p| l.starts_with(p)))
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

#[test]
fn tun_echo_serves_pathctl_processes_and_control_is_opt_in() {
    for v6 in [false, true] {
        let local: IpAddr = if v6 { "fd00::2" } else { "10.0.0.2" }.parse().unwrap();
        let peer: SocketAddr = if v6 { "[fd00::1]:8080" } else { "10.0.0.1:8080" }
            .parse()
            .unwrap();
        let config = EndpointConfig::default();
        let mut endpoint = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut network = TunHost::attach(&mut endpoint, &config, local).unwrap();
        endpoint
            .connect_with_path_provider(
                0,
                SocketAddr::new(local, 1234),
                peer,
                ntcp::ManagedOpenOptions {
                    transport: ntcp::ActiveOpenOptions::from(&config.connection),
                    dscp: config.dscp,
                    ipv4_options: Default::default(),
                    registration: None,
                    receive_authority: None,
                },
                &mut network.host,
            )
            .unwrap();
        // Opt-in: nothing is served without a socket pathname, and an
        // allow-list alone is refused.
        assert!(control_server(&mut network.host, &endpoint, None, None)
            .unwrap()
            .is_none());
        assert!(control_server(&mut network.host, &endpoint, None, Some("1000".into())).is_err());
        let dir = std::env::temp_dir().join(format!(
            "tun-echo-control-{}-{}",
            std::process::id(),
            u8::from(v6)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let mut server = control_server(
            &mut network.host,
            &endpoint,
            Some(dir.join("control").into_os_string()),
            None,
        )
        .unwrap()
        .unwrap();
        let (routes, _, code) = pathctl(&mut server, &mut network, &mut endpoint, &["routes"]);
        assert_eq!(code, 0);
        let token = field(&routes, "token").to_string();
        assert_eq!(field(&routes, "next_hop"), "forwarder:1");
        let (applied, stderr, code) =
            pathctl(&mut server, &mut network, &mut endpoint, &["disable", "route", &token]);
        assert_eq!(code, 0, "{stderr}");
        assert_eq!(applied.trim(), "applied generation=1 affected_paths=1");
        // tun_echo reaches every destination through its forwarder: a
        // disabled IPv4 route sends at most 576 octets without an
        // administrative value, a disabled IPv6 path at most 1280.
        let (paths, _, _) = pathctl(&mut server, &mut network, &mut endpoint, &["paths"]);
        assert_eq!(field(&paths, "effective_disabled"), "route");
        assert_eq!(field(&paths, "budget"), if v6 { "1280" } else { "576" });
        let (clients, _, _) = pathctl(
            &mut server,
            &mut network,
            &mut endpoint,
            &["clients", field(&paths, "token")],
        );
        assert!(clients.lines().any(|l| field(l, "kind") == "tcp"), "{clients}");
        let (_, stderr, code) =
            pathctl(&mut server, &mut network, &mut endpoint, &["set", "route", &token, "0"]);
        assert_eq!((code, stderr.trim()), (1, "status=stale"));
        drop(server);
        assert!(std::fs::symlink_metadata(dir.join("control")).is_err());
    }
}
