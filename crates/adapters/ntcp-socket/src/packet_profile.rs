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
    UpstreamWindow8,
    Sack,
    UpstreamSack,
    UpstreamCubic,
    UpstreamEcn,
    UpstreamBasic,
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
                "upstream-window8" => Profile::UpstreamWindow8,
                "sack" => Profile::Sack,
                "upstream-sack" => Profile::UpstreamSack,
                "upstream-cubic" => Profile::UpstreamCubic,
                "upstream-ecn" => Profile::UpstreamEcn,
                "upstream-basic" => Profile::UpstreamBasic,
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
    let upstream = matches!(
        profile,
        Profile::UpstreamSack
            | Profile::UpstreamCubic
            | Profile::UpstreamEcn
            | Profile::UpstreamBasic
    );
    let mut config = EndpointConfig {
        max_connections: LIMIT,
        max_listeners: LIMIT,
        max_control_packets: LIMIT,
        max_buffer_bytes: 32 * 1024 * 1024,
        ..EndpointConfig::default()
    };
    config.connection.receive_capacity = match profile {
        Profile::Baseline | Profile::Sack => 65535,
        // Real receive storage: 8 MiB requires scale 8, not 7 (65535 << 7).
        Profile::UpstreamWindow8
        | Profile::UpstreamSack
        | Profile::UpstreamCubic
        | Profile::UpstreamEcn
        | Profile::UpstreamBasic => 8 * 1024 * 1024,
    };
    // Reserve owned receive storage before packetdrill starts timed events.
    // Its mlockall(MCL_FUTURE) makes first-touch allocation synchronous.
    config.preallocate_connections = usize::from(upstream);
    config.connection.mss = 1460;
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
    config.connection.congestion_algorithm = if profile == Profile::UpstreamCubic {
        ntcp::CongestionAlgorithm::Cubic
    } else {
        ntcp::CongestionAlgorithm::Reno
    };
    config.connection.timestamps = upstream;
    config.connection.rack = upstream;
    config.connection.prr = upstream;
    if upstream && profile != Profile::UpstreamCubic {
        config.connection.prr_algorithm = ntcp::PrrAlgorithm::LegacyInitialCredit;
    }
    // UpstreamCubic keeps RFC 9937 accounting and exit cwnd.
    config.connection.prr_pacing = profile != Profile::UpstreamCubic;
    config.connection.output_push_batch_segments = if profile == Profile::UpstreamCubic {
        2
    } else {
        0
    };
    config.connection.tlp = upstream;
    if upstream {
        // Explicit Linux timing compatibility; the core keeps RFC 6298's
        // recommended one-second floor as its default.
        config.connection.rto_min_us = 200_000;
    }
    config.connection.sack = upstream || profile == Profile::Sack;
    config.connection.coalesce_read_window_updates = profile == Profile::UpstreamBasic;
    config.connection.recovery_algorithm = if profile == Profile::UpstreamBasic {
        ntcp::RecoveryAlgorithm::Reno
    } else {
        ntcp::RecoveryAlgorithm::NewReno
    };
    config.connection.receive_ip_payload_limit = 65515;
    config.connection.send_ip_payload_limit = 65515;
    config.connection.ecn = profile == Profile::UpstreamEcn;
    config
}
pub(crate) fn parse_frame(bytes: &[u8]) -> Result<ntcp_ip::Packet<'_>> {
    if bytes.len() < 20 {
        return Err(EINVAL);
    }
    if bytes[0] >> 4 != 4 || bytes[9] != 6 {
        return Err(unsupported("packet: only IPv4 TCP"));
    }
    if bytes[0] & 15 != 5 {
        return Err(unsupported("IPv4 options"));
    }
    if u16::from_be_bytes([bytes[6], bytes[7]]) & 0xbfff != 0 {
        return Err(unsupported("IPv4 fragmentation/reserved flag"));
    }
    let packet = ntcp_ip::parse(bytes, false).map_err(|_| EINVAL)?;
    ntcp::wire::parse(packet.ip, packet.payload).map_err(|_| EINVAL)?;
    Ok(packet)
}
