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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpstreamOptions {
    pub no_timestamps: bool,
    pub ecn: bool,
    pub adaptive_ack: bool,
    pub lowat4000: bool,
    pub linux_cookie: bool,
    pub pmtud1500: bool,
    pub budget128m: bool,
    pub budget224m: bool,
    pub prealloc3: bool,
    pub immediate_ack: bool,
    pub peer_ack_delay200ms: bool,
    // Records an explicit, idempotent request; upstream already enables this by default.
    pub abort_with_ack: bool,
    // Records an explicit, idempotent request; upstream already enables this by default.
    pub coalesce_read_window: bool,
    pub legacy_prr: bool,
    pub reno: bool,
    pub paced: bool,
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
                for (enabled, token) in [
                    (options.no_timestamps, "no-timestamps"),
                    (options.ecn, "ecn"),
                    (options.adaptive_ack, "adaptive-ack"),
                    (options.lowat4000, "lowat4000"),
                    (options.linux_cookie, "linux-cookie"),
                    (options.pmtud1500, "pmtud1500"),
                    (options.budget128m, "budget128m"),
                    (options.budget224m, "budget224m"),
                    (options.prealloc3, "prealloc3"),
                    (options.immediate_ack, "immediate-ack"),
                    (options.peer_ack_delay200ms, "peer-ack-delay200ms"),
                    (options.abort_with_ack, "abort-with-ack"),
                    (options.coalesce_read_window, "coalesce-read-window"),
                    (options.legacy_prr, "legacy-prr"),
                    (options.reno, "reno"),
                    (options.paced, "paced"),
                    (options.receive64k, "receive64k"),
                ] {
                    if enabled {
                        flags.push(',');
                        flags.push_str(token);
                    }
                }
                flags
            }
        }
    }
}
pub fn profile(flags: &str) -> Result<(Ipv4Addr, Profile)> {
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
                    .map_err(|_| unsupported("invalid local IPv4 in so_flags"))?,
            );
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
                "pmtud1500" => &mut options.pmtud1500,
                "budget128m" => &mut options.budget128m,
                "budget224m" => &mut options.budget224m,
                "prealloc3" => &mut options.prealloc3,
                "immediate-ack" => &mut options.immediate_ack,
                "peer-ack-delay200ms" => &mut options.peer_ack_delay200ms,
                "abort-with-ack" => &mut options.abort_with_ack,
                "coalesce-read-window" => &mut options.coalesce_read_window,
                "legacy-prr" => &mut options.legacy_prr,
                "reno" => &mut options.reno,
                "paced" => &mut options.paced,
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
        if options.budget128m && options.budget224m || options.adaptive_ack && options.immediate_ack
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
    Ok((
        local.ok_or_else(|| unsupported("so_flags requires local=<IPv4>"))?,
        selected,
    ))
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
    c.receive_ip_payload_limit = 65515;
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
        config.preallocate_connections = if o.prealloc3 { 3 } else { 1 };
        c.receive_capacity = if o.receive64k { 65535 } else { 8 * 1024 * 1024 };
        c.initial_window = ntcp::InitialWindow::Iw10;
        c.congestion_algorithm = if o.reno {
            ntcp::CongestionAlgorithm::Reno
        } else {
            ntcp::CongestionAlgorithm::Cubic
        };
        c.pacing = o.paced.then(ntcp::PacingConfig::default);
        c.cubic_hystart = true;
        c.cubic_fast_convergence = true;
        c.timestamps = !o.no_timestamps;
        c.sack = true;
        c.rack = true;
        c.tlp = true;
        c.prr = true;
        c.prr_algorithm = if o.legacy_prr {
            ntcp::PrrAlgorithm::LegacyInitialCredit
        } else {
            ntcp::PrrAlgorithm::Rfc9937
        };
        c.prr_pacing = o.paced;
        c.rto_min_us = 200_000;
        c.ecn = o.ecn;
        c.abort_with_ack = true;
        c.coalesce_read_window_updates =
            ntcp::ConnectionConfig::default().coalesce_read_window_updates;
        c.output_push_batch_segments = 0;
        c.output_group_flush = true;
        c.output_push_batch_retransmissions = false;
        if o.peer_ack_delay200ms {
            c.peer_max_ack_delay_us = 200_000;
        }
        c.adaptive_ack = !o.immediate_ack;
        c.delayed_ack_us = if o.immediate_ack { 0 } else { 200_000 };
        if o.pmtud1500 {
            c.pmtud = Some(ntcp::PmtudConfig::new(1500));
        }
    }
    config
}
// Fixed defaults.sh key is opt-in and restricted to exact scripts by the runner.
pub(crate) fn cookie_policy(profile: Profile) -> ntcp::FastOpenCookiePolicy {
    #[cfg(feature = "tfo-linux-cookie")]
    if matches!(
        profile,
        Profile::Upstream(UpstreamOptions {
            linux_cookie: true,
            ..
        })
    ) {
        return ntcp::FastOpenCookiePolicy::LinuxSipHash24(ntcp::LinuxSipHash24Key::new([
            0xa1, 0xa1, 0xa1, 0xa1, 0xb2, 0xb2, 0xb2, 0xb2, 0xc3, 0xc3, 0xc3, 0xc3, 0xd4, 0xd4,
            0xd4, 0xd4,
        ]));
    }
    let _ = profile;
    ntcp::FastOpenCookiePolicy::HmacSha256
}
pub(crate) fn gso(profile: Profile) -> Option<ntcp::GsoLimits> {
    matches!(
        profile,
        Profile::PipelineGso | Profile::PipelinePacedGso | Profile::Upstream(_)
    )
    .then_some(ntcp::GsoLimits {
        max_bytes: 65536,
        max_segments: 16,
    })
}
// Injection admits only the ICMP feedback understood by production input_ip.
// Keep parse_frame TCP-only: its callers consume the payload as TCP.
pub(crate) fn validate_injection(bytes: &[u8]) -> Result<()> {
    if bytes.get(9) != Some(&1) {
        return parse_frame(bytes).map(|_| ());
    }
    parse_ipv4(bytes)?;
    ntcp_icmp::decode_icmp(bytes).map_err(|error| match error {
        ntcp_icmp::Error::ProtocolUnsupported => {
            unsupported("packet: unsupported ICMP error type/code")
        }
        _ => EINVAL,
    })?;
    Ok(())
}
pub(crate) fn parse_frame(bytes: &[u8]) -> Result<ntcp_ip::Packet<'_>> {
    if bytes.len() < 20 {
        return Err(EINVAL);
    }
    if bytes[0] >> 4 != 4 || bytes[9] != 6 {
        return Err(unsupported("packet: only IPv4 TCP"));
    }
    let packet = parse_ipv4(bytes)?;
    ntcp::wire::parse(packet.ip, packet.payload).map_err(|_| EINVAL)?;
    Ok(packet)
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
    fn common_baseline_and_independent_options() {
        let base = config(selected(""));
        let c = &base.connection;
        assert_eq!(c.congestion_algorithm, ntcp::CongestionAlgorithm::Cubic);
        assert_eq!(c.pacing, None);
        assert_eq!(c.prr_algorithm, ntcp::PrrAlgorithm::Rfc9937);
        assert!(!c.prr_pacing);
        assert!(c.timestamps && c.sack && c.rack && c.tlp);
        assert_eq!(c.initial_window, ntcp::InitialWindow::Iw10);
        assert_eq!(c.receive_capacity, 8 * 1024 * 1024);
        assert_eq!(c.rto_min_us, 200_000);
        assert!(c.adaptive_ack);
        assert!(c.coalesce_read_window_updates);
        assert!(c.abort_with_ack);
        assert_eq!(c.output_push_batch_segments, 0);
        assert!(c.output_group_flush);
        assert!(!c.output_push_batch_retransmissions);
        assert_eq!(c.delayed_ack_us, 200_000);
        assert_eq!(base.max_buffer_bytes, 32 * 1024 * 1024);
        assert_eq!(base.preallocate_connections, 1);
        for (token, field) in [
            ("no-timestamps", 0),
            ("ecn", 1),
            ("immediate-ack", 2),
            ("budget128m", 3),
            ("prealloc3", 4),
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
            "legacy-prr",
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
                "legacy-prr" => {
                    assert_eq!(c.prr_algorithm, ntcp::PrrAlgorithm::LegacyInitialCredit);
                    c.prr_algorithm = ntcp::PrrAlgorithm::Rfc9937;
                }
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
        for paced in [false, true] {
            let config = config(selected(if paced { ",paced" } else { "" }));
            assert_eq!(config.connection.prr_pacing, paced);
            assert_eq!(config.connection.pacing.is_some(), paced);
            let mut endpoint = ntcp::Endpoint::new(config, [42; 32], 0, |_| true).unwrap();
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
                    assert_eq!(sent, if paced { 2000 } else { 10_000 });
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
            // An actually unpaced flight must not acquire the paced infinity tag.
            assert_eq!(
                endpoint.transport_info(id).unwrap().cwnd,
                if paced { 20_000 } else { 18_000 }
            );
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
            expected.connection.receive_ip_payload_limit = 65515;
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
        let mut endpoint = ntcp::Endpoint::new(config, [42; 32], 0, |_| true).unwrap();
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
            let mut endpoint = ntcp::Endpoint::new(config, [42; 32], 0, |_| true).unwrap();
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
        let mut endpoint = ntcp::Endpoint::new(config, [42; 32], 0, |_| true).unwrap();
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
