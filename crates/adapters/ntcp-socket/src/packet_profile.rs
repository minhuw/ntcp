// SPDX-License-Identifier: GPL-2.0-or-later
// Packetdrill setup: local fixtures and one upstream baseline with fixed deltas.
use crate::*;
use ntcp::EndpointConfig;
pub const LIMIT: usize = 128;
pub const BYTES: usize = 65535;
pub fn diagnostic(kind: &str, reason: &str) {
    let message = format!("NTCP_PACKETDRILL_{kind}: {reason}\n");
    unsafe {
        syscall(SYS_write, STDERR_FILENO, message.as_ptr(), message.len());
    }
}
pub fn unsupported(reason: &str) -> i32 {
    diagnostic("UNSUPPORTED", reason);
    ENOSYS
}
// Raw socket-key bytes; sysctl word decoding belongs to the audited runner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CookieKey([u8; 16]);
impl std::fmt::Debug for CookieKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpstreamOptions {
    pub application_protected_tfo: bool,
    pub application_protected_tfo_client: bool,
    pub no_timestamps: bool,
    pub ecn: bool,
    pub adaptive_ack: bool,
    pub lowat4000: bool,
    pub linux_cookie: bool,
    pub cookie_key: Option<CookieKey>,
    pub tfo_listen: bool,
    pub early_response: bool,
    pub pmtud1500: bool,
    pub link_mtu: Option<u32>,
    pub budget128m: bool,
    pub budget224m: bool,
    pub prealloc3: bool,
    pub prealloc4: bool,
    pub immediate_ack: bool,
    pub peer_ack_delay200ms: bool,
    // Records an explicit, idempotent request; upstream already enables this by default.
    pub abort_with_ack: bool,
    // Records an explicit, idempotent request; upstream already enables this by default.
    pub coalesce_read_window: bool,
    pub reno: bool,
    pub paced: bool,
    pub no_gso: bool,
    pub receive64k: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Baseline,
    Pipeline,
    PipelinePaced,
    PipelineGso,
    PipelinePacedGso,
    Sack,
    Upstream(UpstreamOptions),
}
impl Profile {
    pub fn flags(self) -> String {
        match self {
            Self::Baseline => "baseline".into(),
            Self::Pipeline => "pipeline".into(),
            Self::PipelinePaced => "pipeline-paced".into(),
            Self::PipelineGso => "pipeline-gso".into(),
            Self::PipelinePacedGso => "pipeline-paced-gso".into(),
            Self::Sack => "sack".into(),
            Self::Upstream(options) => {
                let mut flags = String::from("upstream");
                if let Some(mtu) = options.link_mtu {
                    flags.push_str(&format!(",link-mtu={mtu}"));
                }
                for (enabled, token) in [
                    (options.no_timestamps, "no-timestamps"),
                    (options.ecn, "ecn"),
                    (options.adaptive_ack, "adaptive-ack"),
                    (options.lowat4000, "lowat4000"),
                    (options.linux_cookie, "linux-cookie"),
                    (options.tfo_listen, "tfo-listen"),
                    (
                        options.application_protected_tfo,
                        "application-protected-tfo",
                    ),
                    (
                        options.application_protected_tfo_client,
                        "application-protected-tfo-client",
                    ),
                    (options.early_response, "early-response"),
                    (options.pmtud1500, "pmtud1500"),
                    (options.budget128m, "budget128m"),
                    (options.budget224m, "budget224m"),
                    (options.prealloc3, "prealloc3"),
                    (options.prealloc4, "prealloc4"),
                    (options.immediate_ack, "immediate-ack"),
                    (options.peer_ack_delay200ms, "peer-ack-delay200ms"),
                    (options.abort_with_ack, "abort-with-ack"),
                    (options.coalesce_read_window, "coalesce-read-window"),
                    (options.reno, "reno"),
                    (options.paced, "paced"),
                    (options.no_gso, "no-gso"),
                    (options.receive64k, "receive64k"),
                ] {
                    if enabled {
                        flags.push(',');
                        flags.push_str(token);
                    }
                }
                if let Some(key) = options.cookie_key {
                    flags.push_str(",tfo-key=");
                    for byte in key.0 {
                        use std::fmt::Write;
                        write!(flags, "{byte:02x}").unwrap();
                    }
                }
                flags
            }
        }
    }
}
pub fn profile(flags: &str) -> Result<(IpAddr, Profile)> {
    let mut local = None;
    let mut selected = None;
    let mut options = UpstreamOptions::default();
    let mut has_options = false;
    for flag in flags.split(',') {
        if let Some(ip) = flag.strip_prefix("local=") {
            if local.is_some() {
                return Err(unsupported("duplicate local in so_flags"));
            }
            local = Some(
                ip.parse()
                    .map_err(|_| unsupported("invalid local IP in so_flags"))?,
            );
            continue;
        }
        if let Some(text) = flag.strip_prefix("link-mtu=") {
            let mtu: u32 = text.parse().map_err(|_| unsupported("invalid link MTU"))?;
            if options.link_mtu.replace(mtu).is_some()
                || text != mtu.to_string()
                || !(68..=65535).contains(&mtu)
            {
                return Err(unsupported("invalid or duplicate link MTU"));
            }
            has_options = true;
            continue;
        }
        if let Some(hex) = flag.strip_prefix("tfo-key=") {
            if options.cookie_key.is_some()
                || hex.len() != 32
                || !hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(unsupported("invalid or duplicate raw TFO key in so_flags"));
            }
            let mut bytes = [0; 16];
            for (byte, digits) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
                *byte = u8::from_str_radix(std::str::from_utf8(digits).unwrap(), 16).unwrap();
            }
            options.cookie_key = Some(CookieKey(bytes));
            has_options = true;
            continue;
        }
        let selection = match flag {
            "baseline" => Some(Profile::Baseline),
            "pipeline" => Some(Profile::Pipeline),
            "pipeline-paced" => Some(Profile::PipelinePaced),
            "pipeline-gso" => Some(Profile::PipelineGso),
            "pipeline-paced-gso" => Some(Profile::PipelinePacedGso),
            "sack" => Some(Profile::Sack),
            "upstream" => Some(Profile::Upstream(UpstreamOptions::default())),
            _ => None,
        };
        if let Some(selection) = selection {
            if selected.replace(selection).is_some() {
                return Err(unsupported("duplicate or conflicting profiles in so_flags"));
            }
        } else {
            let option = match flag {
                "no-timestamps" => &mut options.no_timestamps,
                "ecn" => &mut options.ecn,
                "adaptive-ack" => &mut options.adaptive_ack,
                "lowat4000" => &mut options.lowat4000,
                "linux-cookie" => &mut options.linux_cookie,
                "tfo-listen" => &mut options.tfo_listen,
                "application-protected-tfo" => &mut options.application_protected_tfo,
                "application-protected-tfo-client" => &mut options.application_protected_tfo_client,
                "early-response" => &mut options.early_response,
                "pmtud1500" => &mut options.pmtud1500,
                "budget128m" => &mut options.budget128m,
                "budget224m" => &mut options.budget224m,
                "prealloc3" => &mut options.prealloc3,
                "prealloc4" => &mut options.prealloc4,
                "immediate-ack" => &mut options.immediate_ack,
                "peer-ack-delay200ms" => &mut options.peer_ack_delay200ms,
                "abort-with-ack" => &mut options.abort_with_ack,
                "coalesce-read-window" => &mut options.coalesce_read_window,
                "reno" => &mut options.reno,
                "paced" => &mut options.paced,
                "no-gso" => &mut options.no_gso,
                "receive64k" => &mut options.receive64k,
                _ => return Err(unsupported("unknown so_flags token")),
            };
            if *option {
                return Err(unsupported("duplicate option in so_flags"));
            }
            *option = true;
            has_options = true;
        }
    }
    let mut selected =
        selected.ok_or_else(|| unsupported("so_flags requires exactly one profile"))?;
    if matches!(selected, Profile::Upstream(_)) {
        if options.budget128m && options.budget224m
            || options.adaptive_ack && options.immediate_ack
            || options.prealloc3 && options.prealloc4
            || options.pmtud1500 && options.link_mtu.is_some()
            || options.cookie_key.is_some() && !options.linux_cookie
        {
            return Err(unsupported("conflicting upstream options"));
        }
        #[cfg(not(feature = "tfo-linux-cookie"))]
        if options.linux_cookie {
            return Err(unsupported("option requires tfo-linux-cookie feature"));
        }
        selected = Profile::Upstream(options);
    } else if has_options {
        return Err(unsupported("options require upstream baseline"));
    }
    let local = local.ok_or_else(|| unsupported("so_flags requires local=<IP>"))?;
    if !crate::ip::global_unicast(local)
        || local.is_ipv6() && options.link_mtu.is_some_and(|mtu| mtu < 1280)
    {
        return Err(unsupported("invalid local unicast IP"));
    }
    Ok((local, selected))
}
pub(crate) fn config(profile: Profile) -> EndpointConfig {
    let mut config = EndpointConfig {
        max_connections: LIMIT,
        max_listeners: LIMIT,
        max_control_packets: LIMIT,
        max_buffer_bytes: 32 * 1024 * 1024,
        ..EndpointConfig::default()
    };
    let c = &mut config.connection;
    c.receive_capacity = 65535;
    c.mss = 1460;
    c.initial_window = ntcp::InitialWindow::Rfc5681;
    c.congestion_algorithm = ntcp::CongestionAlgorithm::Reno;
    c.pacing = matches!(profile, Profile::PipelinePaced | Profile::PipelinePacedGso)
        .then(ntcp::PacingConfig::default);
    c.sack = profile == Profile::Sack;
    c.ecn = false;
    c.coalesce_read_window_updates = false;
    c.send_ip_payload_limit = 65515;
    if let Profile::Upstream(o) = profile {
        config.max_buffer_bytes = if o.budget224m {
            224
        } else if o.budget128m {
            128
        } else {
            32
        } * 1024
            * 1024;
        // First-touch storage before timed events, still charged to the bounded budget.
        config.preallocate_connections = if o.prealloc4 {
            4
        } else if o.prealloc3 {
            3
        } else {
            1
        };
        c.receive_capacity = if o.receive64k { 65535 } else { 8 * 1024 * 1024 };
        c.initial_window = ntcp::InitialWindow::Iw10;
        c.congestion_algorithm = if o.reno {
            ntcp::CongestionAlgorithm::Reno
        } else {
            ntcp::CongestionAlgorithm::Cubic
        };
        c.pacing = o.paced.then(ntcp::PacingConfig::default);
        c.fast_open_early_response = o.early_response;
        c.cubic_hystart = true;
        c.cubic_fast_convergence = true;
        c.timestamps = !o.no_timestamps;
        c.sack = true;
        c.rack = true;
        c.tlp = true;
        c.prr = true;
        c.prr_pacing = o.paced;
        c.rto_min_us = 200_000;
        c.ecn = o.ecn;
        c.abort_with_ack = true;
        c.coalesce_read_window_updates =
            ntcp::ConnectionConfig::default().coalesce_read_window_updates;
        c.output_group_flush = true;
        if o.peer_ack_delay200ms {
            c.peer_max_ack_delay_us = 200_000;
        }
        c.adaptive_ack = !o.immediate_ack;
        c.delayed_ack_us = if o.immediate_ack { 0 } else { 200_000 };
        if let Some(mtu) = o.link_mtu {
            c.pmtud = Some(ntcp::PmtudConfig::new(mtu));
        } else if o.pmtud1500 {
            c.pmtud = Some(ntcp::PmtudConfig::new(1500));
        }
    }
    config
}
// Linux defaults key unless an explicit raw key was configured before startup.
pub(crate) fn cookie_policy(profile: Profile) -> ntcp::FastOpenCookiePolicy {
    #[cfg(feature = "tfo-linux-cookie")]
    if let Profile::Upstream(UpstreamOptions {
        linux_cookie: true,
        cookie_key,
        ..
    }) = profile
    {
        let key = cookie_key.map_or(
            [
                0xa1, 0xa1, 0xa1, 0xa1, 0xb2, 0xb2, 0xb2, 0xb2, 0xc3, 0xc3, 0xc3, 0xc3, 0xd4, 0xd4,
                0xd4, 0xd4,
            ],
            |key| key.0,
        );
        return ntcp::FastOpenCookiePolicy::LinuxSipHash24(ntcp::LinuxSipHash24Key::new(key));
    }
    let _ = profile;
    ntcp::FastOpenCookiePolicy::HmacSha256
}
pub(crate) fn gso(profile: Profile) -> Option<ntcp::GsoLimits> {
    if matches!(profile, Profile::PipelineGso | Profile::PipelinePacedGso)
        || matches!(profile, Profile::Upstream(o) if !o.no_gso)
    {
        Some(ntcp::GsoLimits {
            max_bytes: 65536,
            max_segments: 16,
        })
    } else {
        None
    }
}
// Injection admits only the ICMP feedback understood by production input_ip.
// Keep parse_frame TCP-only: its callers consume the payload as TCP.
pub(crate) fn validate_injection(bytes: &[u8]) -> Result<()> {
    if bytes.first().is_some_and(|b| b >> 4 == 4) {
        parse_ipv4(bytes)?;
    }
    let p = crate::ip::parse(bytes).map_err(|_| EINVAL)?;
    if p.protocol == 6 {
        return parse_frame(bytes).map(|_| ());
    }
    if p.protocol != if p.ip.source.is_ipv4() { 1 } else { 58 } {
        return Err(unsupported("packet: unsupported IP protocol"));
    }
    ntcp_icmp::decode_icmp(bytes).map_err(|error| match error {
        ntcp_icmp::Error::ProtocolUnsupported => {
            unsupported("packet: unsupported ICMP error type/code")
        }
        _ => EINVAL,
    })?;
    Ok(())
}
pub(crate) fn parse_frame(bytes: &[u8]) -> Result<crate::ip::Packet<'_>> {
    if bytes.first().is_some_and(|b| b >> 4 == 4) {
        parse_ipv4(bytes)?;
    }
    let p = crate::ip::parse(bytes).map_err(|_| EINVAL)?;
    if p.ip.source.is_ipv4() {
        parse_ipv4(bytes)?;
    }
    if p.protocol != 6 {
        return Err(unsupported("packet: only TCP"));
    }
    ntcp::wire::parse(p.ip, p.payload).map_err(|_| EINVAL)?;
    Ok(p)
}
fn parse_ipv4(bytes: &[u8]) -> Result<ntcp_ip::Packet<'_>> {
    if bytes.len() < 20 {
        return Err(EINVAL);
    }
    if bytes[0] >> 4 != 4 {
        return Err(unsupported("packet: only IPv4"));
    }
    if bytes[0] & 15 != 5 {
        return Err(unsupported("IPv4 options"));
    }
    if u16::from_be_bytes([bytes[6], bytes[7]]) & 0xbfff != 0 {
        return Err(unsupported("IPv4 fragmentation/reserved flag"));
    }
    ntcp_ip::parse(bytes, false).map_err(|_| EINVAL)
}

pub(crate) fn notsent_lowat(profile: Profile) -> u32 {
    if matches!(
        profile,
        Profile::Upstream(UpstreamOptions {
            lowat4000: true,
            ..
        })
    ) {
        4000
    } else {
        u32::MAX
    }
}

#[cfg(test)]
mod setup_profile_tests {
    use super::*;
    fn selected(options: &str) -> Profile {
        profile(&format!("upstream,local=192.0.2.1{options}"))
            .unwrap()
            .1
    }
    #[test]
    fn removed_legacy_prr_option_is_rejected() {
        assert!(profile("upstream,local=192.0.2.1,legacy-prr").is_err());
    }

    #[test]
    fn common_baseline_and_independent_options() {
        let base = config(selected(""));
        let c = &base.connection;
        assert_eq!(c.congestion_algorithm, ntcp::CongestionAlgorithm::Cubic);
        assert_eq!(c.pacing, None);
        assert!(!c.prr_pacing);
        assert!(c.timestamps && c.sack && c.rack && c.tlp);
        assert!(!c.fast_open_early_response);
        assert_eq!(c.initial_window, ntcp::InitialWindow::Iw10);
        assert_eq!(c.receive_capacity, 8 * 1024 * 1024);
        assert_eq!(c.rto_min_us, 200_000);
        assert_eq!(c.tlp_timer_margin_us, 2000);
        assert!(c.adaptive_ack);
        assert!(c.coalesce_read_window_updates);
        assert!(c.abort_with_ack);
        assert!(c.output_group_flush);
        assert_eq!(c.delayed_ack_us, 200_000);
        assert_eq!(base.max_buffer_bytes, 32 * 1024 * 1024);
        assert_eq!(base.preallocate_connections, 1);
        for (token, field) in [
            ("no-timestamps", 0),
            ("ecn", 1),
            ("immediate-ack", 2),
            ("budget128m", 3),
            ("prealloc3", 4),
            ("early-response", 5),
        ] {
            let p = selected(&format!(",{token}"));
            assert_eq!(
                profile(&format!("{},local=192.0.2.1", p.flags()))
                    .unwrap()
                    .1,
                p
            );
            let mut changed = config(p);
            match field {
                0 => changed.connection.timestamps = true,
                1 => changed.connection.ecn = false,
                2 => {
                    changed.connection.delayed_ack_us = c.delayed_ack_us;
                    changed.connection.adaptive_ack = c.adaptive_ack;
                }
                3 => changed.max_buffer_bytes = base.max_buffer_bytes,
                4 => changed.preallocate_connections = 1,
                5 => changed.connection.fast_open_early_response = false,
                _ => unreachable!(),
            }
            assert_eq!(format!("{changed:?}"), format!("{base:?}"), "{token}");
        }
        assert!(gso(selected("")).is_some());
        assert!(profile("upstream,local=192.0.2.1,push2").is_err());
        assert_eq!(notsent_lowat(selected(",lowat4000")), 4000);
    }
    #[test]
    fn upstream_ack_policy_is_valid_with_immediate_override_and_pacing() {
        for options in [
            "",
            ",adaptive-ack",
            ",immediate-ack",
            ",paced",
            ",paced,adaptive-ack",
            ",paced,immediate-ack",
        ] {
            let c = config(selected(options)).connection;
            assert_eq!(c.adaptive_ack, !options.contains("immediate-ack"));
            assert_eq!(c.delayed_ack_us, if c.adaptive_ack { 200_000 } else { 0 });
            assert!(c.validate(true).is_ok(), "{options}");
        }
    }

    #[test]
    fn every_fixed_option_is_isolated_or_explicit_default() {
        let baseline = config(selected(""));
        for token in [
            "no-timestamps",
            "ecn",
            "adaptive-ack",
            "lowat4000",
            "pmtud1500",
            "budget128m",
            "budget224m",
            "prealloc3",
            "immediate-ack",
            "peer-ack-delay200ms",
            "abort-with-ack",
            "coalesce-read-window",
            "reno",
            "paced",
            "receive64k",
        ] {
            let option = selected(&format!(",{token}"));
            assert_eq!(
                profile(&format!("{},local=192.0.2.1", option.flags()))
                    .unwrap()
                    .1,
                option
            );
            let mut actual = config(option);
            let c = &mut actual.connection;
            match token {
                "no-timestamps" => {
                    assert!(!c.timestamps);
                    c.timestamps = true;
                }
                "ecn" => {
                    assert!(c.ecn);
                    c.ecn = false;
                }
                "adaptive-ack" => {
                    assert!(c.adaptive_ack);
                    assert_eq!(c.delayed_ack_us, 200_000);
                }
                "lowat4000" => assert_eq!(notsent_lowat(option), 4000),
                "pmtud1500" => assert_eq!(
                    format!("{:?}", c.pmtud.take().unwrap()),
                    format!("{:?}", ntcp::PmtudConfig::new(1500))
                ),
                "budget128m" | "budget224m" => {
                    assert_eq!(
                        actual.max_buffer_bytes,
                        if token == "budget128m" { 128 } else { 224 } * 1024 * 1024
                    );
                    actual.max_buffer_bytes = baseline.max_buffer_bytes;
                }
                "prealloc3" => {
                    assert_eq!(actual.preallocate_connections, 3);
                    actual.preallocate_connections = 1;
                }
                "immediate-ack" => {
                    assert_eq!(c.delayed_ack_us, 0);
                    assert!(!c.adaptive_ack);
                    c.delayed_ack_us = baseline.connection.delayed_ack_us;
                    c.adaptive_ack = baseline.connection.adaptive_ack;
                }
                "peer-ack-delay200ms" => {
                    assert_eq!(c.peer_max_ack_delay_us, 200_000);
                    c.peer_max_ack_delay_us = baseline.connection.peer_max_ack_delay_us;
                }
                "abort-with-ack" => assert!(c.abort_with_ack),
                "coalesce-read-window" => assert!(c.coalesce_read_window_updates),
                "reno" => {
                    assert_eq!(c.congestion_algorithm, ntcp::CongestionAlgorithm::Reno);
                    c.congestion_algorithm = ntcp::CongestionAlgorithm::Cubic;
                }
                "paced" => {
                    assert_eq!(c.pacing, Some(ntcp::PacingConfig::default()));
                    assert!(c.prr_pacing);
                    assert!(c.adaptive_ack);
                    c.pacing = None;
                    c.prr_pacing = false;
                }
                "receive64k" => {
                    assert_eq!(c.receive_capacity, 65535);
                    c.receive_capacity = baseline.connection.receive_capacity;
                }
                _ => unreachable!(),
            }
            assert_eq!(format!("{actual:?}"), format!("{baseline:?}"), "{token}");
            assert!(matches!(
                cookie_policy(option),
                ntcp::FastOpenCookiePolicy::HmacSha256
            ));
            assert!(gso(option).is_some());
        }
        #[cfg(feature = "tfo-linux-cookie")]
        {
            let option = selected(",linux-cookie");
            assert!(matches!(
                cookie_policy(option),
                ntcp::FastOpenCookiePolicy::LinuxSipHash24(_)
            ));
            assert_eq!(format!("{:?}", config(option)), format!("{baseline:?}"));
        }
    }

    #[test]
    fn common_and_paced_startup_output_and_hystart_ack_growth() {
        use ntcp::wire::{self, ACK, SYN};
        for (paced, initial_burst) in [(false, false), (true, false), (true, true)] {
            let mut config = config(selected(if paced { ",paced" } else { "" }));
            if let Some(p) = &mut config.connection.pacing {
                p.initial_window_burst = initial_burst;
            }
            assert_eq!(config.connection.prr_pacing, paced);
            assert_eq!(config.connection.pacing.is_some(), paced);
            let mut endpoint = ntcp::Endpoint::new(config, [42; 32], 0, ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never }, |_| true).unwrap();
            let id = endpoint
                .connect(
                    0,
                    "192.0.2.1:40000".parse().unwrap(),
                    "192.0.2.2:8080".parse().unwrap(),
                )
                .unwrap();
            let mut bytes = [0; 1500];
            let tx = endpoint
                .poll_transmit(0, &mut bytes, 32)
                .unwrap()
                .packet
                .unwrap();
            let syn = wire::parse(tx.ip, &bytes[..tx.len]).unwrap().header;
            let ip = ntcp::IpMetadata {
                source: tx.ip.destination,
                destination: tx.ip.source,
            };
            let mut ack = wire::Header {
                source_port: syn.destination_port,
                destination_port: syn.source_port,
                sequence: 100,
                acknowledgment: syn.sequence.wrapping_add(1),
                flags: SYN | ACK,
                window: 65535,
                urgent_pointer: 0,
            };
            let n = wire::encode(ip, ack, &[2, 4, 3, 232], &[], &mut bytes).unwrap();
            endpoint.input(10_000, ip, &bytes[..n]).unwrap();
            endpoint.write(id, &[7; 20_000]).unwrap();
            assert_eq!(endpoint.transport_info(id).unwrap().cwnd, 10_000);
            let mut now = 10_000;
            let mut sent = 0;
            loop {
                while let Some(tx) = endpoint.poll_transmit(now, &mut bytes, 32).unwrap().packet {
                    let segment = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
                    if !segment.payload.is_empty() {
                        assert_eq!(segment.header.sequence, syn.sequence.wrapping_add(1 + sent));
                        assert_eq!(segment.payload.len(), 1000);
                        sent += segment.payload.len() as u32;
                    }
                }
                if now == 10_000 {
                    assert_eq!(
                        sent,
                        if paced && !initial_burst {
                            2000
                        } else {
                            10_000
                        }
                    );
                }
                if sent == 10_000 {
                    break;
                }
                assert!(paced);
                let deadline = endpoint.next_deadline().unwrap();
                assert!(deadline > now && deadline < 110_000, "{deadline}");
                now = deadline;
                endpoint.on_timeout(now, 32).unwrap();
            }
            // No ACKs have opened cwnd and the peer's receive window is larger than IW10.
            assert!(
                endpoint
                    .poll_transmit(now, &mut bytes, 32)
                    .unwrap()
                    .packet
                    .is_none()
            );
            ack.sequence += 1;
            ack.flags = ACK;
            ack.acknowledgment = syn.sequence.wrapping_add(10_001);
            let n = wire::encode(ip, ack, &[], &[], &mut bytes).unwrap();
            endpoint.input(110_000, ip, &bytes[..n]).unwrap();
            // Ten delivered MSS fit both the finite tuned L16 and paced
            // infinity; the measured departure times above distinguish pacing.
            assert_eq!(endpoint.transport_info(id).unwrap().cwnd, 20_000);
        }
    }

    #[test]
    fn native_fixture_settings_are_unchanged() {
        for profile in [
            Profile::Baseline,
            Profile::Sack,
            Profile::Pipeline,
            Profile::PipelinePaced,
            Profile::PipelineGso,
            Profile::PipelinePacedGso,
        ] {
            let mut expected = EndpointConfig {
                max_connections: LIMIT,
                max_listeners: LIMIT,
                max_control_packets: LIMIT,
                max_buffer_bytes: 32 * 1024 * 1024,
                ..EndpointConfig::default()
            };
            expected.connection.receive_capacity = 65535;
            expected.connection.mss = 1460;
            expected.connection.pacing =
                matches!(profile, Profile::PipelinePaced | Profile::PipelinePacedGso)
                    .then(ntcp::PacingConfig::default);
            expected.connection.sack = profile == Profile::Sack;
            expected.connection.coalesce_read_window_updates = false;
            expected.connection.send_ip_payload_limit = 65515;
            expected.connection.ecn = false;
            assert_eq!(format!("{:?}", config(profile)), format!("{expected:?}"));
            assert_eq!(notsent_lowat(profile), u32::MAX);
        }
    }

    #[test]
    fn parser_fails_closed() {
        for flags in [
            "upstream-basic,local=192.0.2.1",
            "upstream,unpaced,local=192.0.2.1",
            "upstream,unpaced-prr,local=192.0.2.1",
            "upstream,paced,paced,local=192.0.2.1",
            "upstream,paced,unpaced,local=192.0.2.1",
            "upstream,baseline,local=192.0.2.1",
            "upstream,ecn,ecn,local=192.0.2.1",
            "upstream,immediate-ack,adaptive-ack,local=192.0.2.1",
            "upstream,budget128m,budget224m,local=192.0.2.1",
            "baseline,ecn,local=192.0.2.1",
            "ecn,local=192.0.2.1",
            "upstream,local=192.0.2.1,",
            "upstream,budget=123,local=192.0.2.1",
        ] {
            assert!(profile(flags).is_err(), "{flags}");
        }
        let result = profile("upstream,linux-cookie,local=192.0.2.1");
        assert_eq!(result.is_ok(), cfg!(feature = "tfo-linux-cookie"));
    }
    #[test]
    fn fast_open_budget_admits_seven_retained_connections_but_not_eight() {
        let config = config(selected(",budget224m,prealloc3"));
        assert_eq!(config.preallocate_connections, 3);
        let preallocate = config.preallocate_connections;
        let budget = config.max_buffer_bytes;
        let mut endpoint = ntcp::Endpoint::new(config, [42; 32], 0, ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never }, |_| true).unwrap();
        let reserved = endpoint.buffer_bytes();
        let charge = reserved / preallocate;
        // The smallest 32 MiB budget step that covers the corpus maximum.
        assert!(7 * charge > budget - 32 * 1024 * 1024);
        assert!(7 * charge <= budget);
        assert!(8 * charge > budget);
        endpoint.enable_fast_open().unwrap();
        let cache_charge = endpoint.buffer_bytes() - reserved;
        let remote = "192.0.2.2:8080".parse().unwrap();
        for index in 0..7 {
            let local = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 40000 + index);
            let (_, accepted) = endpoint.connect_fast_open(0, local, remote, &[]).unwrap();
            assert_eq!(accepted, 0);
            assert_eq!(
                endpoint.buffer_bytes(),
                (usize::from(index) + 1).max(preallocate) * charge + cache_charge
            );
        }
        assert_eq!(
            endpoint.connect_fast_open(0, "192.0.2.1:40007".parse().unwrap(), remote, &[]),
            Err(ntcp::EndpointError::LimitReached)
        );
        assert_eq!(endpoint.buffer_bytes(), 7 * charge + cache_charge);
    }

    #[test]
    fn fast_open_three_retained_opens_transfer_reserved_charges_once() {
        for preallocate in [
            1,
            2,
            config(selected(",budget224m,prealloc3")).preallocate_connections,
        ] {
            let mut config = config(selected(",budget224m,prealloc3"));
            config.preallocate_connections = preallocate;
            let mut endpoint = ntcp::Endpoint::new(config, [42; 32], 0, ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never }, |_| true).unwrap();
            let reserved = endpoint.buffer_bytes();
            let charge = reserved / preallocate;
            endpoint.enable_fast_open().unwrap();
            let initial = endpoint.buffer_bytes();
            for index in 0..3 {
                let local = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 40000 + index);
                endpoint
                    .connect_fast_open(0, local, "192.0.2.2:8080".parse().unwrap(), &[])
                    .unwrap();
                // Transfer each reserve once; only opens beyond the reserve
                // count need newly charged storage.
                assert_eq!(
                    endpoint.buffer_bytes(),
                    initial + (usize::from(index) + 1).saturating_sub(preallocate) * charge
                );
            }
        }
    }

    #[test]
    fn fast_open_preallocated_constructor_failure_preserves_charge() {
        let mut config = config(selected(",budget224m,prealloc3"));
        assert_eq!(config.preallocate_connections, 3);
        let attempts = config.preallocate_connections + 1;
        config.connection.mss = 0;
        let mut endpoint = ntcp::Endpoint::new(config, [42; 32], 0, ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never }, |_| true).unwrap();
        endpoint.enable_fast_open().unwrap();
        let initial = endpoint.buffer_bytes();
        for _ in 0..attempts {
            assert_eq!(
                endpoint.connect_fast_open(
                    0,
                    "192.0.2.1:40000".parse().unwrap(),
                    "192.0.2.2:8080".parse().unwrap(),
                    &[],
                ),
                Err(ntcp::EndpointError::Connection(
                    ntcp::Error::InvalidArgument
                ))
            );
            assert_eq!(endpoint.buffer_bytes(), initial);
        }
    }
}

#[cfg(test)]
mod early_response_pool_tests {
    use super::*;
    #[test]
    fn four_charged_pools_and_early_response_are_independent_options() {
        let (_, selected) =
            profile("upstream,local=192.0.2.1,budget224m,prealloc4,early-response").unwrap();
        let config = config(selected);
        assert_eq!(config.preallocate_connections, 4);
        assert_eq!(config.max_buffer_bytes, 224 * 1024 * 1024);
        assert!(config.connection.fast_open_early_response);
        assert_eq!(
            profile(&format!("{},local=192.0.2.1", selected.flags()))
                .unwrap()
                .1,
            selected
        );
        assert!(profile("upstream,local=192.0.2.1,prealloc3,prealloc4").is_err());
    }
}

#[cfg(test)]
mod custom_cookie_key_tests {
    use super::*;

    #[test]
    fn raw_key_requires_explicit_policy_and_feature_and_is_redacted() {
        let key = "00112233445566778899aabbccddeeff";
        let base = "upstream,local=192.0.2.1";
        let flags = format!("{base},linux-cookie,tfo-key={key}");
        let result = profile(&flags);
        assert_eq!(result.is_ok(), cfg!(feature = "tfo-linux-cookie"));
        if let Ok((_, selected)) = result {
            assert!(!format!("{selected:?}").contains(key));
            assert!(format!("{selected:?}").contains("[REDACTED]"));
            assert_eq!(
                profile(&format!("{},local=192.0.2.1", selected.flags()))
                    .unwrap()
                    .1,
                selected
            );
            let base = config(profile(&format!("{base},linux-cookie")).unwrap().1);
            assert_eq!(format!("{:?}", config(selected)), format!("{base:?}"));
        }
        for invalid in [
            format!("{base},tfo-key={key}"),
            format!("{flags},tfo-key={key}"),
            format!("{flags},tfo-key={}", "0".repeat(32)),
            flags.replace("upstream", "baseline"),
            flags.replace(key, ""),
            flags.replace(key, "00112233445566778899AABBCCDDEEFF"),
            flags.replace(key, "00112233445566778899aabbccddeefg"),
            flags.replace(key, "00112233445566778899aabbccddeef"),
            format!("{flags}0"),
        ] {
            assert!(profile(&invalid).is_err(), "{invalid}");
        }
    }

    #[cfg(feature = "tfo-linux-cookie")]
    #[test]
    fn custom_default_key_issues_three_address_bound_vectors() {
        let selected = profile(
            "upstream,local=192.168.0.2,linux-cookie,tfo-key=f763bfa0813d80ed301d64cd904abcce",
        )
        .unwrap()
        .1;
        for (local, remote, expected) in [
            (
                "192.168.0.2",
                "10.248.0.2",
                [0x00, 0xab, 0xaa, 0xab, 0xe8, 0xe9, 0x54, 0xc2],
            ),
            (
                "192.168.0.2",
                "10.248.0.3",
                [0x13, 0x13, 0xa2, 0xda, 0x99, 0x4a, 0x09, 0x51],
            ),
            (
                "192.168.0.3",
                "10.248.0.3",
                [0x76, 0xd2, 0xc1, 0xc5, 0x30, 0xf5, 0x1f, 0x79],
            ),
        ] {
            let mut endpoint =
                ntcp::Endpoint::new(EndpointConfig::default(), [42; 32], 0, ntcp::Lifecycle { boot_age: Some(u64::MAX), continuity: ntcp::SourceContinuity::Never }, |_| true).unwrap();
            endpoint.set_fast_open_cookie_policy(cookie_policy(selected));
            endpoint.enable_fast_open().unwrap();
            let local: IpAddr = local.parse().unwrap();
            let listener = endpoint.listen(SocketAddr::new(local, 8080), 1).unwrap();
            endpoint.set_listener_fast_open(listener, 1).unwrap();
            let ip = ntcp::IpMetadata {
                source: remote.parse().unwrap(),
                destination: local,
            };
            let mut bytes = [0; 2048];
            let n = ntcp::wire::encode(
                ip,
                ntcp::wire::Header {
                    source_port: 40000,
                    destination_port: 8080,
                    sequence: 1,
                    acknowledgment: 0,
                    flags: ntcp::wire::SYN,
                    window: 10000,
                    urgent_pointer: 0,
                },
                &[34, 2, 1, 1],
                &[],
                &mut bytes,
            )
            .unwrap();
            endpoint.input(0, ip, &bytes[..n]).unwrap();
            let output = endpoint
                .poll_transmit(0, &mut bytes, 64)
                .unwrap()
                .packet
                .unwrap();
            let synack = ntcp::wire::parse(output.ip, &bytes[..output.len]).unwrap();
            assert_eq!(synack.options.fast_open.unwrap().as_bytes(), expected);
        }
    }
}

#[cfg(test)]
mod no_gso_tests {
    use super::*;
    #[test]
    fn explicit_scalar_backend_leaves_transport_policy_unchanged() {
        let base = profile("upstream,local=192.0.2.1").unwrap().1;
        let scalar = profile("upstream,local=192.0.2.1,no-gso").unwrap().1;
        assert!(gso(base).is_some());
        assert_eq!(gso(scalar), None);
        assert_eq!(
            format!("{:?}", config(base)),
            format!("{:?}", config(scalar))
        );
        assert_eq!(
            profile(&format!("{},local=192.0.2.1", scalar.flags()))
                .unwrap()
                .1,
            scalar
        );
    }
}

#[cfg(test)]
mod link_mtu_tests {
    use super::*;
    #[test]
    fn explicit_synthetic_link_mtu_is_bounded_and_keeps_family_minimum() {
        for (local, mtu) in [("192.0.2.1", 9000), ("2001:db8::1", 1520)] {
            let (address, p) = profile(&format!("upstream,local={local},link-mtu={mtu}")).unwrap();
            let c = config(p);
            assert_eq!(c.connection.pmtud.unwrap().first_hop_mtu, mtu);
            assert_eq!(
                profile(&format!("{},local={address}", p.flags()))
                    .unwrap()
                    .1,
                p
            );
        }
        for flags in [
            "upstream,local=2001:db8::1,link-mtu=660",
            "upstream,local=192.0.2.1,link-mtu=67",
            "upstream,local=192.0.2.1,link-mtu=65536",
            "upstream,local=192.0.2.1,link-mtu=01520",
            "upstream,local=192.0.2.1,link-mtu=1520,link-mtu=1520",
            "upstream,local=192.0.2.1,link-mtu=1520,pmtud1500",
            "baseline,local=192.0.2.1,link-mtu=1520",
        ] {
            assert!(profile(flags).is_err(), "{flags}");
        }
    }
}
