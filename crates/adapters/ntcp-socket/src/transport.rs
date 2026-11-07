// SPDX-License-Identifier: GPL-2.0-or-later
use crate::runtime::unsupported_option as unsupported;
use crate::*;
use ntcp::State;
// Pinned stock _tcp_info is 280 bytes. Only the fields explicitly written
// below are supported; every other field is reserved zero, NOT a metric.
// Embedded-code assertions require the runner's field capability allowlist.
const TCP_INFO_SIZE: usize = 280;
#[cfg(test)]
pub(crate) fn transport_option(info: ntcp::TransportInfo, option: i32) -> Result<Vec<u8>> {
    transport_option_prefix(info, option, TCP_INFO_SIZE)
}

pub(crate) fn transport_option_prefix(
    info: ntcp::TransportInfo,
    option: i32,
    requested: usize,
) -> Result<Vec<u8>> {
    if option == 2 {
        return Ok(Vec::new());
    } // Reno/NewReno have no CC-specific data.
    if option != 1 {
        return Err(unsupported("transport option"));
    }
    let mut bytes = vec![0; TCP_INFO_SIZE];
    let mut put = |offset: usize, value: u64| {
        let value = value.min(u32::MAX as u64) as u32;
        bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    };
    // optlen is the caller's capacity, not a demand for every trailing metric.
    // A short reply exposes the available prefix without inventing delivery
    // values. Callers needing later fields must inspect the returned length.
    let available = if !info.ledger_valid {
        24 // The first unavailable segment counter is tcpi_unacked.
    } else if !info.delivered_segments_valid {
        192
    } else {
        TCP_INFO_SIZE
    };
    if info.send_window_scale > 14 || info.receive_window_scale > 14 {
        return Err(EIO);
    }
    if info.mss == 0 {
        return Err(EIO);
    }
    if info.delivered_segments_valid {
        put(192, info.delivered_segments);
    }
    put(8, info.rto_us);
    put(16, info.mss as u64);
    put(20, info.received_mss as u64);
    put(24, info.unacked as u64);
    put(28, info.sacked as u64);
    put(32, info.lost as u64);
    put(36, info.retransmitted as u64);
    put(52, info.last_data_recv_ms as u64);
    put(144, info.notsent_bytes as u64);
    put(148, info.min_rtt_us.unwrap_or(u64::from(u32::MAX)));
    put(220, info.reordering_events);
    put(68, info.rtt_us.unwrap_or(0));
    put(72, info.rttvar_us);
    put(76, (info.ssthresh / info.mss) as u64);
    put(80, (info.cwnd / info.mss) as u64);
    put(84, u64::from(info.advertised_mss));
    put(88, info.reordering as u64);
    for (offset, value) in [
        (168, info.busy_time_us),
        (176, info.rwnd_limited_us),
        (184, info.sndbuf_limited_us),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
    bytes[3] = info.resource_probes.min(u32::from(u8::MAX)) as u8;
    bytes[4] = info.rto_backoff.min(u32::from(u8::MAX)) as u8;
    bytes[5] = u8::from(info.timestamps_negotiated)
        | (u8::from(info.sack_negotiated) << 1)
        | (u8::from(info.window_scaling_negotiated) << 2)
        | (u8::from(info.ecn_negotiated) << 3)
        | (u8::from(info.syn_data_fully_acked) << 5);
    if info.window_scaling_negotiated {
        bytes[6] = info.send_window_scale | (info.receive_window_scale << 4);
    }
    bytes[0] = match info.state {
        State::Established => 1,
        State::SynSent => 2,
        State::SynReceived => 3,
        State::FinWait1 => 4,
        State::FinWait2 => 5,
        State::TimeWait => 6,
        State::Closed => 7,
        State::CloseWait => 8,
        State::LastAck => 9,
        State::Closing => 11,
    };
    bytes[1] = if info.loss {
        4
    } else if info.recovery {
        3
    } else if info.ecn_response {
        2 // TCP_CA_CWR; loss/recovery supersede overlapping ECN epochs.
    } else if info.ledger_valid && info.sacked > 0 {
        1
    } else {
        0
    };
    // Never return unavailable delivery bytes, even as reserved zero.
    bytes.truncate(requested.min(available));
    Ok(bytes)
}

// No Connection exists on a fresh/bound/deferred-connect socket or listener.
// Their counters really are zero; listener queue occupancy uses Linux's
// special tcpi_unacked/tcpi_sacked meanings rather than data-segment counts.
pub(crate) fn idle_transport_option(
    listener: Option<(usize, usize)>,
    option: i32,
    requested: usize,
) -> Result<Vec<u8>> {
    if option == 2 {
        return Ok(Vec::new());
    }
    if option != 1 {
        return Err(unsupported("transport option"));
    }
    let mut bytes = vec![0; TCP_INFO_SIZE];
    bytes[0] = if listener.is_some() { 10 } else { 7 }; // LISTEN/CLOSE.
    if let Some((pending, backlog)) = listener {
        bytes[24..28].copy_from_slice(&(pending.min(u32::MAX as usize) as u32).to_ne_bytes());
        bytes[28..32].copy_from_slice(&(backlog.min(u32::MAX as usize) as u32).to_ne_bytes());
    } else {
        // Ordinary sockets have no RTT sample yet. LISTEN returns the
        // zero-filled diagnostic prefix before this metric in Linux.
        bytes[148..152].copy_from_slice(&u32::MAX.to_ne_bytes());
    }
    bytes.truncate(requested.min(TCP_INFO_SIZE));
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_info_handshake_evidence_not_configuration_or_tfo_attempt() {
        use ntcp::wire::{self, ACK, ECE, SYN};
        use ntcp::{ConnectionConfig, Endpoint, EndpointConfig};

        for negotiated in [false, true] {
            for ack_payload in [false, true] {
                let mut endpoint = Endpoint::new(
                    EndpointConfig {
                        connection: ConnectionConfig {
                            timestamps: true,
                            sack: true,
                            ecn: true,
                            receive_capacity: 1 << 20,
                            ..ConnectionConfig::default()
                        },
                        ..EndpointConfig::default()
                    },
                    [1; 32],
                    0,
                    |_| true,
                )
                .unwrap();
                endpoint.enable_fast_open().unwrap();
                // First handshake obtains a cookie; second really sends SYN data.
                for attempt in 0..2 {
                    let now = attempt * 100_000;
                    let (id, accepted) = endpoint
                        .connect_fast_open(
                            now,
                            format!("192.0.2.1:{}", 1000 + attempt).parse().unwrap(),
                            "192.0.2.2:2000".parse().unwrap(),
                            &[42; 100],
                        )
                        .unwrap();
                    assert_eq!(accepted, if attempt == 0 { 0 } else { 100 });
                    let before = transport_option(endpoint.transport_info(id).unwrap(), 1).unwrap();
                    assert_eq!(&before[5..7], &[0, 0]);
                    let mut out = [0; 2048];
                    let tx = endpoint
                        .poll_transmit(now, &mut out, 16)
                        .unwrap()
                        .packet
                        .unwrap();
                    let syn = wire::parse(tx.ip, &out[..tx.len]).unwrap();
                    assert_eq!(syn.payload.len(), accepted);
                    let mut options = vec![34, 10, 7, 7, 7, 7, 7, 7, 7, 7];
                    if negotiated {
                        options.extend_from_slice(&[4, 2, 3, 3, 3, 1, 8, 10]);
                        options.extend_from_slice(&123u32.to_be_bytes());
                        options.extend_from_slice(&syn.options.timestamps.unwrap().0.to_be_bytes());
                    }
                    while !options.len().is_multiple_of(4) {
                        options.push(1);
                    }
                    let ip = ntcp::IpMetadata {
                        source: tx.ip.destination,
                        destination: tx.ip.source,
                    };
                    let header = wire::Header {
                        source_port: syn.header.destination_port,
                        destination_port: syn.header.source_port,
                        sequence: 100,
                        acknowledgment: syn
                            .header
                            .sequence
                            .wrapping_add(1 + if ack_payload { accepted as u32 } else { 0 }),
                        flags: SYN | ACK | if negotiated { ECE } else { 0 },
                        window: 32000,
                        urgent_pointer: 0,
                    };
                    let local_scale = syn.options.window_scale.unwrap();
                    let mut input = [0; 128];
                    let len = wire::encode(ip, header, &options, &[], &mut input).unwrap();
                    endpoint.input(now + 20_000, ip, &input[..len]).unwrap();
                    let info = endpoint.transport_info(id).unwrap();
                    let bytes = transport_option(info, 1).unwrap();
                    assert_eq!(
                        bytes[5],
                        if negotiated { 15 } else { 0 }
                            | if attempt == 1 && ack_payload { 32 } else { 0 }
                    );
                    assert_eq!(bytes[6], if negotiated { 3 | local_scale << 4 } else { 0 });
                    assert_eq!(&bytes[68..72], &20_000u32.to_ne_bytes());
                    assert_eq!(&bytes[192..196], &1u32.to_ne_bytes());
                    // Drain the handshake ACK before creating another connection.
                    endpoint.poll_transmit(now + 20_000, &mut out, 16).unwrap();
                }
            }
        }
    }

    #[test]
    fn linux_info_ecn_epoch_exit_reports_open() {
        use ntcp::wire::{self, ACK, ECE, SYN};
        use ntcp::{
            CongestionAlgorithm, ConnectionConfig, Endpoint, EndpointConfig, InitialWindow,
        };

        for mode in ["fast", "sack", "fin", "timeout"] {
            let config = EndpointConfig {
                connection: ConnectionConfig {
                    ecn: true,
                    sack: mode == "sack",
                    mss: 1000,
                    initial_window: InitialWindow::Iw10,
                    congestion_algorithm: CongestionAlgorithm::Cubic,
                    prr_pacing: false,
                    ..ConnectionConfig::default()
                },
                ..EndpointConfig::default()
            };
            let mut endpoint = Endpoint::new(config, [1; 32], 0, |_| true).unwrap();
            let id = endpoint
                .connect(
                    0,
                    "192.0.2.1:1000".parse().unwrap(),
                    "192.0.2.2:2000".parse().unwrap(),
                )
                .unwrap();
            let mut out = [0; 2048];
            let tx = endpoint
                .poll_transmit(0, &mut out, 16)
                .unwrap()
                .packet
                .unwrap();
            let syn = wire::parse(tx.ip, &out[..tx.len]).unwrap().header;
            let base = syn.sequence.wrapping_add(1);
            let ip = ntcp::IpMetadata {
                source: tx.ip.destination,
                destination: tx.ip.source,
            };
            let mut ack = wire::Header {
                source_port: syn.destination_port,
                destination_port: syn.source_port,
                sequence: 100,
                acknowledgment: base,
                flags: SYN | ACK | ECE,
                window: 32_000,
                urgent_pointer: 0,
            };
            let input = |endpoint: &mut Endpoint, now, header, options: &[u8]| {
                let mut bytes = [0; 64];
                let len = wire::encode(ip, header, options, &[], &mut bytes).unwrap();
                endpoint.input(now, ip, &bytes[..len]).unwrap();
            };
            let state = |endpoint: &Endpoint| {
                transport_option(endpoint.transport_info(id).unwrap(), 1).unwrap()[1]
            };
            input(&mut endpoint, 10, ack, &[2, 4, 3, 232, 1, 1, 4, 2]);
            endpoint.poll_transmit(20, &mut out, 16).unwrap();
            assert_eq!(state(&endpoint), 0);
            endpoint.write(id, &[1; 6000]).unwrap();
            for _ in 0..6 {
                let tx = endpoint
                    .poll_transmit(30, &mut out, 16)
                    .unwrap()
                    .packet
                    .unwrap();
                assert_eq!(
                    wire::parse(tx.ip, &out[..tx.len]).unwrap().payload.len(),
                    1000
                );
            }
            ack.sequence = 101;
            ack.acknowledgment = base.wrapping_add(3000);
            ack.flags = ACK | ECE;
            input(&mut endpoint, 40, ack, &[]);
            assert_eq!(state(&endpoint), 2); // CWR, not just ECN negotiation.
            ack.flags = ACK;
            if mode == "fin" {
                ack.acknowledgment = base.wrapping_add(6000);
                input(&mut endpoint, 50, ack, &[]);
                assert_eq!(state(&endpoint), 2); // Equality retains the epoch.
                endpoint.shutdown(id).unwrap();
                let tx = endpoint
                    .poll_transmit(60, &mut out, 16)
                    .unwrap()
                    .packet
                    .unwrap();
                let fin = wire::parse(tx.ip, &out[..tx.len]).unwrap();
                assert!(fin.payload.is_empty());
                assert_ne!(fin.header.flags & wire::FIN, 0);
                ack.acknowledgment = ack.acknowledgment.wrapping_add(1);
                input(&mut endpoint, 70, ack, &[]);
            } else if mode == "timeout" {
                let deadline = 40 + endpoint.transport_info(id).unwrap().rto_us;
                endpoint.on_timeout(deadline, 16).unwrap();
                assert_eq!(state(&endpoint), 4); // Loss supersedes CWR.
                ack.acknowledgment = base.wrapping_add(6000);
                input(&mut endpoint, deadline + 1, ack, &[]);
            } else {
                endpoint.write(id, &[2; 1000]).unwrap();
                endpoint
                    .poll_transmit(50, &mut out, 16)
                    .unwrap()
                    .packet
                    .unwrap();
                if mode == "sack" {
                    let mut sack = vec![5, 10];
                    sack.extend_from_slice(&base.wrapping_add(4000).to_be_bytes());
                    sack.extend_from_slice(&base.wrapping_add(7000).to_be_bytes());
                    sack.extend_from_slice(&[1, 1]);
                    input(&mut endpoint, 60, ack, &sack);
                } else {
                    for _ in 0..3 {
                        input(&mut endpoint, 60, ack, &[]);
                    }
                }
                assert_eq!(state(&endpoint), 3); // Recovery supersedes overlapping CWR.
                ack.acknowledgment = base.wrapping_add(7000);
                input(&mut endpoint, 70, ack, &[]);
            }
            assert_eq!(state(&endpoint), 0, "{mode}: Open, not stale CWR");
        }
    }

    #[test]
    fn linux_info_metrics_offsets_preserve_existing_fields() {
        let info = ntcp::TransportInfo {
            state: State::Established,
            recovery: false,
            ecn_response: false,
            loss: false,
            ledger_valid: true,
            timestamps_negotiated: true,
            sack_negotiated: true,
            window_scaling_negotiated: true,
            send_window_scale: 3,
            receive_window_scale: 14,
            ecn_negotiated: true,
            syn_data_acked: true,
            syn_data_fully_acked: true,
            delivered_segments: 0x12345678,
            delivered_segments_valid: true,
            unacked: 3,
            sacked: 1,
            lost: 1,
            retransmitted: 2,
            reordering: 3,
            reordering_events: 0xabcdef01,
            resource_probes: 0,
            rto_backoff: 0,
            cwnd: 10000,
            ssthresh: 8000,
            mss: 1000,
            received_mss: 900,
            advertised_mss: 1200,
            max_send_window: 32000,
            rtt_us: Some(12000),
            min_rtt_us: Some(10000),
            rttvar_us: 3000,
            rto_us: 200000,
            notsent_bytes: 4000,
            last_data_recv_ms: 789,
            busy_time_us: 0x1122334455667788,
            rwnd_limited_us: 0x2233445566778899,
            sndbuf_limited_us: 0x33445566778899aa,
            send_used: 5000,
            send_capacity: 65536,
            send_space: 65536,
            receive_used: 42,
            receive_capacity: 65536,
        };
        for (loss, recovery, ecn_response, sacked, state) in [
            (false, false, false, 0, 0),
            (false, false, false, 1, 1),
            (false, false, true, 0, 2),
            (false, false, true, 1, 2),
            (false, true, true, 1, 3),
            (true, true, true, 1, 4),
            (true, false, true, 0, 4),
        ] {
            let sample = ntcp::TransportInfo {
                loss,
                recovery,
                ecn_response,
                sacked,
                ..info
            };
            assert_eq!(transport_option(sample, 1).unwrap()[1], state);
        }
        for (state, code) in [
            (State::Established, 1),
            (State::SynSent, 2),
            (State::SynReceived, 3),
            (State::FinWait1, 4),
            (State::FinWait2, 5),
            (State::TimeWait, 6),
            (State::Closed, 7),
            (State::CloseWait, 8),
            (State::LastAck, 9),
            (State::Closing, 11),
        ] {
            let bytes = transport_option(ntcp::TransportInfo { state, ..info }, 1).unwrap();
            assert_eq!(bytes.len(), 280);
            assert_eq!(bytes[0], code);
            assert_eq!(&bytes[148..152], &10000u32.to_ne_bytes());
            assert_eq!(&bytes[220..224], &0xabcdef01u32.to_ne_bytes());
        }
        let error = if cfg!(feature = "packet-test") {
            ENOSYS
        } else {
            EOPNOTSUPP
        };
        for option in [0, 3, i32::MAX] {
            assert_eq!(transport_option(info, option).err(), Some(error));
        }
        assert!(transport_option(info, 2).unwrap().is_empty());
        let bytes = transport_option(info, 1).unwrap();
        assert_eq!(bytes.len(), TCP_INFO_SIZE);
        for (offset, value) in [
            (8, 200000u32),
            (16, 1000),
            (20, 900),
            (24, 3),
            (28, 1),
            (52, 789),
            (68, 12000),
            (80, 10),
            (84, 1200),
            (144, 4000),
            (148, 10000),
            (192, 0x12345678),
            (220, 0xabcdef01),
        ] {
            assert_eq!(&bytes[offset..offset + 4], &value.to_ne_bytes());
        }
        for (offset, value) in [
            (168, 0x1122334455667788u64),
            (176, 0x2233445566778899),
            (184, 0x33445566778899aa),
        ] {
            assert_eq!(&bytes[offset..offset + 8], &value.to_ne_bytes());
        }
        assert_eq!(bytes[5], 1 | 2 | 4 | 8 | 32);
        assert_eq!(bytes[6], 0xe3);
        let supported = [
            0..2,
            5..7,
            8..12,
            16..24,
            24..40,
            52..56,
            68..88,
            88..92,
            144..152,
            168..196,
            220..224,
        ];
        for (offset, byte) in bytes.iter().enumerate() {
            if !supported.iter().any(|range| range.contains(&offset)) {
                assert_eq!(*byte, 0, "unsupported byte {offset}");
            }
        }
        for minimum in [
            None,
            Some(0),
            Some(20_000),
            Some(u32::MAX as u64),
            Some(u64::MAX),
        ] {
            for count in [0, 2, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
                let metrics = transport_option(
                    ntcp::TransportInfo {
                        min_rtt_us: minimum,
                        reordering_events: count,
                        ..info
                    },
                    1,
                )
                .unwrap();
                let expected_min =
                    minimum.unwrap_or(u64::from(u32::MAX)).min(u32::MAX as u64) as u32;
                assert_eq!(&metrics[148..152], &expected_min.to_ne_bytes());
                assert_eq!(
                    &metrics[220..224],
                    &(count.min(u32::MAX as u64) as u32).to_ne_bytes()
                );
            }
        }
        for requested in 0..=TCP_INFO_SIZE + 1 {
            assert_eq!(
                transport_option_prefix(info, 1, requested).unwrap(),
                bytes[..requested.min(TCP_INFO_SIZE)]
            );
        }
        let mut sample = info;
        sample.timestamps_negotiated = false;
        sample.sack_negotiated = false;
        sample.window_scaling_negotiated = false;
        sample.ecn_negotiated = false;
        sample.syn_data_acked = false;
        sample.syn_data_fully_acked = false;
        assert_eq!(&transport_option(sample, 1).unwrap()[5..7], &[0, 0]);
        for bit in [1, 2, 4, 8, 32] {
            let single = ntcp::TransportInfo {
                timestamps_negotiated: bit == 1,
                sack_negotiated: bit == 2,
                window_scaling_negotiated: bit == 4,
                ecn_negotiated: bit == 8,
                syn_data_acked: bit == 32,
                syn_data_fully_acked: bit == 32,
                ..sample
            };
            assert_eq!(transport_option(single, 1).unwrap()[5], bit);
        }
        for count in [0, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
            sample.delivered_segments = count;
            assert_eq!(
                &transport_option(sample, 1).unwrap()[192..196],
                &(count.min(u32::MAX as u64) as u32).to_ne_bytes()
            );
        }
        for (probes, backoff, expected_probes, expected_backoff) in
            [(6, 0, 6, 0), (u32::MAX, u32::MAX, 255, 255)]
        {
            let metrics = transport_option(
                ntcp::TransportInfo {
                    resource_probes: probes,
                    rto_backoff: backoff,
                    ..info
                },
                1,
            )
            .unwrap();
            assert_eq!(metrics[3], expected_probes);
            assert_eq!(metrics[4], expected_backoff);
        }
        for (send, receive) in [(15, 0), (0, 15), (255, 255)] {
            sample.send_window_scale = send;
            sample.receive_window_scale = receive;
            assert_eq!(transport_option(sample, 1).err(), Some(EIO));
        }
        sample = info;
        sample.delivered_segments_valid = false;
        assert_eq!(transport_option(sample, 1).unwrap(), bytes[..192]);
        assert!(transport_option(sample, 2).unwrap().is_empty());
        for requested in [0, 1, 6, 7, 9, 148, 151, 152, 153, 191, 192] {
            assert_eq!(
                transport_option_prefix(sample, 1, requested).unwrap(),
                bytes[..requested]
            );
        }
        for requested in [193, 195, 196, 220, 223, 224, 225, 280, 512, usize::MAX] {
            assert_eq!(
                transport_option_prefix(sample, 1, requested).unwrap(),
                bytes[..192]
            );
            assert_eq!(
                transport_option_prefix(info, 1, requested).unwrap(),
                bytes[..requested.min(TCP_INFO_SIZE)]
            );
        }
        for delivered_valid in [false, true] {
            sample.ledger_valid = false;
            sample.delivered_segments_valid = delivered_valid;
            for requested in [0, 1, 192, 193, 280] {
                let prefix = transport_option_prefix(sample, 1, requested).unwrap();
                assert_eq!(prefix.len(), requested.min(24));
                assert_eq!(prefix.get(5), (requested > 5).then_some(&bytes[5]));
                assert!(
                    transport_option_prefix(sample, 2, requested)
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }
}

#[cfg(test)]
#[test]
fn idle_minimum_rtt_distinguishes_unknown_from_listener_zero() {
    for listener in [None, Some((0, 16)), Some((usize::MAX, usize::MAX))] {
        let bytes = idle_transport_option(listener, 1, usize::MAX).unwrap();
        assert_eq!(bytes.len(), TCP_INFO_SIZE);
        assert_eq!(
            &bytes[148..152],
            &if listener.is_some() { 0u32 } else { u32::MAX }.to_ne_bytes()
        );
        assert_eq!(&bytes[220..224], &0u32.to_ne_bytes());
        if let Some((pending, backlog)) = listener {
            assert_eq!(
                &bytes[24..28],
                &(pending.min(u32::MAX as usize) as u32).to_ne_bytes()
            );
            assert_eq!(
                &bytes[28..32],
                &(backlog.min(u32::MAX as usize) as u32).to_ne_bytes()
            );
        }
        for requested in 0..=TCP_INFO_SIZE + 1 {
            assert_eq!(
                idle_transport_option(listener, 1, requested).unwrap(),
                bytes[..requested.min(TCP_INFO_SIZE)]
            );
        }
    }
}
