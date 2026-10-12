// SPDX-License-Identifier: GPL-2.0-or-later
// Packetdrill compatibility profiles, separate from normal TUN startup.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Baseline,
    Pipeline,
    PipelinePaced,
    PipelineGso,
    PipelinePacedGso,
    UpstreamWindow8,
    UpstreamHttps,
    UpstreamGlobalLowat,
    Sack,
    UpstreamSack,
    UpstreamCubic,
    UpstreamCubicEcn,
    UpstreamEcn,
    UpstreamBasic,
    UpstreamFastOpen,
    UpstreamFastOpenPmtud,
    UpstreamFastOpenAdaptiveAck,
    #[cfg(feature = "tfo-linux-cookie")]
    UpstreamFastOpenLinuxCookie,
}
pub fn profile(flags: &str) -> Result<(Ipv4Addr, Profile)> {
    let mut local = None;
    let mut selected = None;
    for flag in flags.split(',') {
        if let Some(ip) = flag.strip_prefix("local=") {
            if local.is_some() {
                return Err(unsupported("duplicate local in so_flags"));
            }
            local = Some(
                ip.parse()
                    .map_err(|_| unsupported("invalid local IPv4 in so_flags"))?,
            );
        } else {
            let profile = match flag {
                "baseline" => Profile::Baseline,
                "pipeline" => Profile::Pipeline,
                "pipeline-paced" => Profile::PipelinePaced,
                "pipeline-gso" => Profile::PipelineGso,
                "pipeline-paced-gso" => Profile::PipelinePacedGso,
                "upstream-window8" => Profile::UpstreamWindow8,
                "upstream-https" => Profile::UpstreamHttps,
                "upstream-global-lowat" => Profile::UpstreamGlobalLowat,
                "sack" => Profile::Sack,
                "upstream-sack" => Profile::UpstreamSack,
                "upstream-cubic" => Profile::UpstreamCubic,
                "upstream-cubic-ecn" => Profile::UpstreamCubicEcn,
                "upstream-ecn" => Profile::UpstreamEcn,
                "upstream-basic" => Profile::UpstreamBasic,
                "upstream-fastopen" => Profile::UpstreamFastOpen,
                "upstream-fastopen-adaptive-ack" => Profile::UpstreamFastOpenAdaptiveAck,
                "upstream-fastopen-pmtud" => Profile::UpstreamFastOpenPmtud,
                #[cfg(feature = "tfo-linux-cookie")]
                "upstream-fastopen-linux-cookie" => Profile::UpstreamFastOpenLinuxCookie,
                #[cfg(not(feature = "tfo-linux-cookie"))]
                "upstream-fastopen-linux-cookie" => {
                    return Err(unsupported("profile requires tfo-linux-cookie feature"));
                }
                _ => return Err(unsupported("unknown so_flags token")),
            };
            if selected.replace(profile).is_some() {
                return Err(unsupported("duplicate or conflicting profiles in so_flags"));
            }
        }
    }
    Ok((
        local.ok_or_else(|| unsupported("so_flags requires local=<IPv4>"))?,
        selected.ok_or_else(|| unsupported("so_flags requires exactly one profile"))?,
    ))
}

pub(crate) fn config(profile: Profile) -> EndpointConfig {
    if profile == Profile::UpstreamFastOpenAdaptiveAck {
        let mut config = config(Profile::UpstreamFastOpen);
        config.connection.adaptive_ack = true;
        config.connection.delayed_ack_us = 200_000;
        return config;
    }
    if profile == Profile::UpstreamFastOpenPmtud {
        let mut config = config(Profile::UpstreamFastOpen);
        config.connection.pmtud = Some(ntcp::PmtudConfig::new(1500));
        return config;
    }
    let profile = match profile {
        #[cfg(feature = "tfo-linux-cookie")]
        Profile::UpstreamFastOpenLinuxCookie => Profile::UpstreamFastOpen,
        other => other,
    };
    let https = profile == Profile::UpstreamHttps;
    let fast_open = profile == Profile::UpstreamFastOpen;
    let profile = match profile {
        Profile::UpstreamHttps => Profile::UpstreamWindow8,
        Profile::UpstreamGlobalLowat | Profile::UpstreamFastOpen => Profile::UpstreamBasic,
        other => other,
    };
    let pacing = matches!(profile, Profile::PipelinePaced | Profile::PipelinePacedGso);
    let profile = match profile {
        Profile::Pipeline
        | Profile::PipelinePaced
        | Profile::PipelineGso
        | Profile::PipelinePacedGso => Profile::Baseline,
        other => other,
    };
    let cubic = matches!(profile, Profile::UpstreamCubic | Profile::UpstreamCubicEcn);
    let upstream = matches!(
        profile,
        Profile::UpstreamSack
            | Profile::UpstreamCubic
            | Profile::UpstreamCubicEcn
            | Profile::UpstreamEcn
            | Profile::UpstreamBasic
    );
    let mut config = EndpointConfig {
        max_connections: LIMIT,
        max_listeners: LIMIT,
        max_control_packets: LIMIT,
        max_buffer_bytes: if fast_open {
            // Seven retained connections in valid-cookie-format; each charges
            // receive, send, scoreboard and RACK storage. Keep a bounded budget
            // in 32 MiB units without changing per-connection wire policy.
            224 * 1024 * 1024
        } else if cubic {
            128 * 1024 * 1024
        } else {
            32 * 1024 * 1024
        },
        ..EndpointConfig::default()
    };
    config.connection.receive_capacity = match profile {
        Profile::Baseline | Profile::Sack => 65535,
        // Real receive storage: 8 MiB requires scale 8, not 7 (65535 << 7).
        Profile::UpstreamWindow8
        | Profile::UpstreamSack
        | Profile::UpstreamCubic
        | Profile::UpstreamCubicEcn
        | Profile::UpstreamEcn
        | Profile::UpstreamBasic => 8 * 1024 * 1024,
        _ => unreachable!(),
    };
    // Reserve owned receive storage before packetdrill starts timed events.
    // Its mlockall(MCL_FUTURE) makes first-touch allocation synchronous.
    config.preallocate_connections = if fast_open {
        // Warmup and both test connections retain storage through the short trace.
        3
    } else {
        usize::from(upstream || profile == Profile::UpstreamWindow8)
    };
    config.connection.mss = 1460;
    config.connection.pacing = pacing.then(ntcp::PacingConfig::default);
    if matches!(profile, Profile::UpstreamWindow8 | Profile::UpstreamBasic) {
        // Immediate-ACK compatibility policy, not Linux quickACK emulation.
        config.connection.delayed_ack_us = 0;
    }
    if profile == Profile::UpstreamBasic {
        // Linux tcp_schedule_loss_probe adds its 200ms minimum RTO for
        // a single packet; RFC8985 section7.2 permits this peer ACK budget.
        // Multi-packet full-sized flights retain the ordinary 2*SRTT PTO.
        config.connection.peer_max_ack_delay_us = 200_000;
    }
    config.connection.initial_window = if upstream {
        ntcp::InitialWindow::Iw10
    } else {
        ntcp::InitialWindow::Rfc5681
    };
    // Explicit synchronized local-abort formatting, not a reactive RST policy.
    config.connection.abort_with_ack = profile == Profile::UpstreamBasic;
    config.connection.congestion_algorithm = if cubic {
        ntcp::CongestionAlgorithm::Cubic
    } else {
        ntcp::CongestionAlgorithm::Reno
    };
    // Only setup policy: clients/listeners still opt in through socket options/flags.
    config.connection.timestamps = upstream && !fast_open;
    config.connection.rack = upstream;
    config.connection.prr = upstream;
    if upstream && !cubic {
        config.connection.prr_algorithm = ntcp::PrrAlgorithm::LegacyInitialCredit;
    }
    // Both CUBIC profiles keep RFC 9937 accounting and exit cwnd.
    config.connection.prr_pacing = !cubic;
    // Explicit logical PUSH grouping for wire captures, independent of GSO/TSO.
    config.connection.output_push_batch_segments = if cubic || https { 2 } else { 0 };
    config.connection.tlp = upstream;
    if upstream {
        // Explicit Linux timing compatibility; the core keeps RFC 6298's
        // recommended one-second floor as its default.
        config.connection.rto_min_us = 200_000;
    }
    config.connection.sack = upstream || profile == Profile::Sack || https;
    config.connection.coalesce_read_window_updates = profile == Profile::UpstreamBasic;
    config.connection.recovery_algorithm = if profile == Profile::UpstreamBasic {
        ntcp::RecoveryAlgorithm::Reno
    } else {
        ntcp::RecoveryAlgorithm::NewReno
    };
    config.connection.receive_ip_payload_limit = 65515;
    config.connection.send_ip_payload_limit = 65515;
    config.connection.ecn = matches!(profile, Profile::UpstreamEcn | Profile::UpstreamCubicEcn);
    config
}
// Fixed upstream defaults key is confined to this explicit test profile.
pub(crate) fn cookie_policy(profile: Profile) -> ntcp::FastOpenCookiePolicy {
    match profile {
        #[cfg(feature = "tfo-linux-cookie")]
        Profile::UpstreamFastOpenLinuxCookie => {
            ntcp::FastOpenCookiePolicy::LinuxSipHash24(ntcp::LinuxSipHash24Key::new([
                0xa1, 0xa1, 0xa1, 0xa1, 0xb2, 0xb2, 0xb2, 0xb2, 0xc3, 0xc3, 0xc3, 0xc3, 0xd4, 0xd4,
                0xd4, 0xd4,
            ]))
        }
        _ => ntcp::FastOpenCookiePolicy::HmacSha256,
    }
}
pub(crate) fn gso(profile: Profile) -> Option<ntcp::GsoLimits> {
    matches!(profile, Profile::PipelineGso | Profile::PipelinePacedGso).then_some(ntcp::GsoLimits {
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
    let feedback = ntcp_icmp::decode_icmp(bytes).map_err(|error| match error {
        ntcp_icmp::Error::ProtocolUnsupported => unsupported("packet: only ICMP PacketTooBig"),
        _ => EINVAL,
    })?;
    if feedback.kind != ntcp_icmp::FeedbackKind::PacketTooBig {
        return Err(unsupported("packet: only ICMP PacketTooBig"));
    }
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

// Runtime-global default, deliberately separate from raw per-socket zero/inherit.
pub(crate) fn notsent_lowat(profile: Profile) -> u32 {
    if profile == Profile::UpstreamGlobalLowat {
        4000
    } else {
        u32::MAX
    }
}

#[cfg(test)]
mod setup_profile_tests {
    use super::*;

    #[test]
    fn adaptive_ack_profile_changes_only_ack_policy() {
        let selected = profile("upstream-fastopen-adaptive-ack,local=192.0.2.1")
            .unwrap()
            .1;
        assert_eq!(selected, Profile::UpstreamFastOpenAdaptiveAck);
        let mut actual = config(selected);
        assert!(actual.connection.adaptive_ack);
        assert_eq!(actual.connection.delayed_ack_us, 200_000);
        actual.connection.adaptive_ack = false;
        actual.connection.delayed_ack_us = 0;
        assert_eq!(
            format!("{actual:?}"),
            format!("{:?}", config(Profile::UpstreamFastOpen))
        );
        for other in [
            Profile::Baseline,
            Profile::UpstreamBasic,
            Profile::UpstreamFastOpen,
            Profile::UpstreamFastOpenPmtud,
        ] {
            assert!(!config(other).connection.adaptive_ack);
        }
        #[cfg(feature = "tfo-linux-cookie")]
        assert!(
            !config(Profile::UpstreamFastOpenLinuxCookie)
                .connection
                .adaptive_ack
        );
        assert!(matches!(
            cookie_policy(selected),
            ntcp::FastOpenCookiePolicy::HmacSha256
        ));
        assert_eq!(notsent_lowat(selected), u32::MAX);
        assert!(gso(selected).is_none());
        assert!(
            profile("upstream-fastopen-adaptive-ack,upstream-fastopen,local=192.0.2.1").is_err()
        );
    }

    #[test]
    fn fast_open_pmtud_profile_changes_only_opt_in_pmtud() {
        let selected = profile("upstream-fastopen-pmtud,local=192.0.2.1")
            .unwrap()
            .1;
        assert_eq!(selected, Profile::UpstreamFastOpenPmtud);
        let mut actual = config(selected);
        assert_eq!(
            format!("{:?}", actual.connection.pmtud.take().unwrap()),
            format!("{:?}", ntcp::PmtudConfig::new(1500))
        );
        assert_eq!(
            format!("{actual:?}"),
            format!("{:?}", config(Profile::UpstreamFastOpen))
        );
        for other in [
            Profile::Baseline,
            Profile::UpstreamBasic,
            Profile::UpstreamFastOpen,
        ] {
            assert!(config(other).connection.pmtud.is_none());
        }
        #[cfg(feature = "tfo-linux-cookie")]
        assert!(
            config(Profile::UpstreamFastOpenLinuxCookie)
                .connection
                .pmtud
                .is_none()
        );
        assert!(matches!(
            cookie_policy(selected),
            ntcp::FastOpenCookiePolicy::HmacSha256
        ));
        assert_eq!(notsent_lowat(selected), u32::MAX);
        assert!(gso(selected).is_none());
    }

    #[test]
    fn linux_cookie_profile_is_opt_in() {
        let selected = profile("upstream-fastopen-linux-cookie,local=192.168.0.1");
        #[cfg(not(feature = "tfo-linux-cookie"))]
        assert_eq!(selected, Err(ENOSYS));
        #[cfg(feature = "tfo-linux-cookie")]
        {
            let selected = selected.unwrap().1;
            assert_eq!(selected, Profile::UpstreamFastOpenLinuxCookie);
            assert_eq!(
                format!("{:?}", config(selected)),
                format!("{:?}", config(Profile::UpstreamFastOpen))
            );
            assert!(matches!(
                cookie_policy(selected),
                ntcp::FastOpenCookiePolicy::LinuxSipHash24(_)
            ));
            assert_eq!(notsent_lowat(selected), u32::MAX);
            assert!(gso(selected).is_none());
        }
        for selected in [
            Profile::Baseline,
            Profile::UpstreamBasic,
            Profile::UpstreamFastOpen,
        ] {
            assert!(matches!(
                cookie_policy(selected),
                ntcp::FastOpenCookiePolicy::HmacSha256
            ));
        }
    }

    #[test]
    fn fast_open_setup_changes_only_timestamps_budget_and_preallocation() {
        let selected = profile("upstream-fastopen,local=192.0.2.1").unwrap().1;
        assert_eq!(selected, Profile::UpstreamFastOpen);
        let mut actual = config(selected);
        assert!(!actual.connection.timestamps);
        actual.connection.timestamps = true;
        assert_eq!(actual.max_buffer_bytes, 224 * 1024 * 1024);
        assert_eq!(
            config(Profile::UpstreamBasic).max_buffer_bytes,
            32 * 1024 * 1024
        );
        actual.max_buffer_bytes = 32 * 1024 * 1024;
        assert_eq!(actual.preallocate_connections, 3);
        actual.preallocate_connections = 1;
        assert_eq!(
            format!("{actual:?}"),
            format!("{:?}", config(Profile::UpstreamBasic))
        );
        assert_eq!(notsent_lowat(selected), u32::MAX);
        assert!(gso(selected).is_none());
    }

    #[test]
    fn fast_open_budget_admits_seven_retained_connections_but_not_eight() {
        let config = config(Profile::UpstreamFastOpen);
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
    fn non_fast_open_preallocation_is_unchanged() {
        assert_eq!(EndpointConfig::default().preallocate_connections, 0);
        for selected in [
            Profile::Baseline,
            Profile::Pipeline,
            Profile::PipelinePaced,
            Profile::PipelineGso,
            Profile::PipelinePacedGso,
            Profile::Sack,
        ] {
            assert_eq!(config(selected).preallocate_connections, 0);
        }
        for selected in [
            Profile::UpstreamWindow8,
            Profile::UpstreamHttps,
            Profile::UpstreamGlobalLowat,
            Profile::UpstreamSack,
            Profile::UpstreamCubic,
            Profile::UpstreamCubicEcn,
            Profile::UpstreamEcn,
            Profile::UpstreamBasic,
        ] {
            assert_eq!(config(selected).preallocate_connections, 1);
        }
    }

    #[test]
    fn fast_open_three_retained_opens_transfer_reserved_charges_once() {
        for preallocate in [
            1,
            2,
            config(Profile::UpstreamFastOpen).preallocate_connections,
        ] {
            let mut config = config(Profile::UpstreamFastOpen);
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
        let mut config = config(Profile::UpstreamFastOpen);
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

    #[test]
    fn audited_setup_profiles_keep_transport_and_global_options_separate() {
        for (token, selected, lowat) in [
            ("upstream-https", Profile::UpstreamHttps, u32::MAX),
            ("upstream-global-lowat", Profile::UpstreamGlobalLowat, 4000),
        ] {
            assert_eq!(
                profile(&format!("{token},local=192.0.2.1")).unwrap().1,
                selected
            );
            assert_eq!(notsent_lowat(selected), lowat);
            assert!(gso(selected).is_none());
            let config = config(selected);
            assert!(config.connection.pacing.is_none());
            assert!(config.connection.sack);
            assert_eq!(
                config.connection.timestamps,
                selected == Profile::UpstreamGlobalLowat
            );
            assert_eq!(
                config.connection.output_push_batch_segments,
                if selected == Profile::UpstreamHttps {
                    2
                } else {
                    0
                }
            );
            assert_eq!(config.connection.receive_capacity, 8 * 1024 * 1024);
            assert_eq!(config.connection.delayed_ack_us, 0);
        }
        assert_eq!(notsent_lowat(Profile::UpstreamBasic), u32::MAX);
        assert!(!config(Profile::UpstreamWindow8).connection.sack);
    }
}
