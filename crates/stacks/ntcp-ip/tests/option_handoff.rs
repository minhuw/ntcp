use ntcp::{Endpoint, EndpointConfig, IpMetadata, Ipv4Options, OutgoingIpv4Options, State};
use ntcp_ip::{checksum, encode, parse};

fn with_options(frame: &mut Vec<u8>, options: &[u8]) {
    assert!(options.len() <= 40 && options.len().is_multiple_of(4));
    frame.splice(20..20, options.iter().copied());
    frame[0] = 0x45 + (options.len() / 4) as u8;
    let total = frame.len() as u16;
    frame[2..4].copy_from_slice(&total.to_be_bytes());
    frame[10..12].fill(0);
    let sum = checksum(&frame[..20 + options.len()]);
    frame[10..12].copy_from_slice(&sum.to_be_bytes());
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# All IP options (except NOP or END-OF-LIST) received in datagrams MUST be
//# passed to the transport layer (or to ICMP processing when the datagram is
//# an ICMP message). The IP and transport layer MUST each interpret those IP
//# options that they understand and silently ignore the others.
#[test]
fn checksummed_frames_carry_opaque_options_through_tcp_handshake_and_data() {
    for enabled in [false, true] {
        for unknown in [
            &[30, 2, 158, 3, 255, 1, 0, 255][..],
            &[
                158, 40, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0,
                255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255,
            ][..],
        ] {
            let config = EndpointConfig {
                ipv4_options_enabled: enabled,
                ..Default::default()
            };
            let mut client = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
            let mut server = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
            let local = "192.0.2.1:1234".parse().unwrap();
            let remote = "192.0.2.2:8080".parse().unwrap();
            let listener = server.listen(remote, 1).unwrap();
            let id = client.connect(0, local, remote).unwrap();
            let mut raw = unknown.to_vec();
            // Record Route and Timestamp are retained metadata in both profiles.
            if raw.len() < 32 {
                raw.splice(0..0, [7, 7, 4, 0, 0, 0, 0, 1, 68, 8, 5, 0, 0, 0, 0, 0]);
            }
            let expected = Ipv4Options::parse(&raw, false).unwrap();
            let transfer = |from: &mut Endpoint, to: &mut Endpoint, opaque: bool| {
                let mut frame = vec![0; 1500];
                let tx = from
                    .poll_transmit(0, &mut frame[20..], 32)
                    .unwrap()
                    .packet
                    .unwrap();
                assert_eq!(tx.ipv4_options, OutgoingIpv4Options::default());
                let len = encode(&mut frame, tx, 0).unwrap();
                frame.truncate(len);
                assert_eq!(
                    frame[0], 0x45,
                    "incoming metadata does not add outgoing bytes"
                );
                if opaque {
                    with_options(&mut frame, &raw);
                }
                let packet = parse(&frame, false).unwrap();
                assert!(ntcp::wire::parse(packet.ip, packet.payload).is_ok());
                assert_eq!(
                    packet.ipv4_options,
                    if opaque {
                        expected
                    } else {
                        Ipv4Options::default()
                    }
                );
                assert_eq!(
                    to.input_with_ipv4_options(
                        0,
                        packet.ip,
                        packet.traffic_class,
                        packet.ipv4_options,
                        packet.payload
                    )
                    .unwrap(),
                    ntcp::InputDisposition::Processed
                );
            };
            transfer(&mut client, &mut server, true);
            transfer(&mut server, &mut client, false);
            transfer(&mut client, &mut server, true);
            let accepted = server.accept(listener).unwrap();
            assert_eq!(client.state(id).unwrap(), State::Established);
            assert_eq!(
                server.received_ipv4_options(accepted).unwrap(),
                Some(expected)
            );
            client.write(id, b"real TCP payload").unwrap();
            transfer(&mut client, &mut server, true);
            assert_eq!(
                server.received_ipv4_options(accepted).unwrap(),
                Some(expected)
            );
            let mut out = [0; 32];
            let n = server.read(accepted, &mut out).unwrap();
            assert_eq!(&out[..n], b"real TCP payload");
        }
    }
}

#[test]
fn opaque_options_on_non_tcp_packets_and_malformed_frame_lengths() {
    let mut frame = vec![0; 40];
    let tx = ntcp::Transmit {
        connection: None,
        tx_timestamp: None,
        ip: IpMetadata {
            source: "192.0.2.1".parse().unwrap(),
            destination: "192.0.2.2".parse().unwrap(),
        },
        len: 20,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
        ipv4_options: OutgoingIpv4Options::default(),
        mark: 0,
    };
    encode(&mut frame, tx, 0).unwrap();
    with_options(&mut frame, &[30, 2, 158, 3, 0, 1, 0, 255]);
    frame[9] = 1;
    frame[10..12].fill(0);
    let sum = checksum(&frame[..28]);
    frame[10..12].copy_from_slice(&sum.to_be_bytes());
    let packet = parse(&frame, false).unwrap();
    assert_eq!(packet.protocol, 1);
    assert_eq!(packet.ipv4_options.as_bytes(), &[30, 2, 158, 3, 0]);
    assert_eq!(packet.payload, &[0; 20]);
    // Validation still precedes handoff even for opaque kinds.
    for len in [0, 1, 9, 255] {
        let mut bad = frame.clone();
        bad[21] = len;
        bad[10..12].fill(0);
        let sum = checksum(&bad[..28]);
        bad[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(parse(&bad, false).unwrap_err(), ntcp_ip::Error::Options);
    }
}
