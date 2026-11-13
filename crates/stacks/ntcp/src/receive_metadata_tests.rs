use crate::*;
use alloc::{vec, vec::Vec};
use core::{net::IpAddr, num::NonZeroU16};
struct Receiver {
    e: Endpoint,
    id: ConnectionId,
    ip: IpMetadata,
    ack: u32,
    seq: u32,
    now: u64,
}
impl Receiver {
    fn new(ipv4: bool) -> Self {
        let (local, remote): (IpAddr, IpAddr) = if ipv4 {
            ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap())
        } else {
            (
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            )
        };
        let mut e = Endpoint::new(
            EndpointConfig {
                connection: ConnectionConfig {
                    timestamps: false,
                    sack: false,
                    receive_capacity: 65536,
                    mss: 1460,
                    delayed_ack_us: 200000,
                    adaptive_ack: false,
                    ..Default::default()
                },
                ..Default::default()
            },
            [9; 32],
            0,
            |_| true,
        )
        .unwrap();
        let listener = e.listen((local, 8080).into(), 1).unwrap();
        let ip = IpMetadata {
            source: remote,
            destination: local,
        };
        let header = wire::Header {
            source_port: 40000,
            destination_port: 8080,
            sequence: 0,
            acknowledgment: 0,
            flags: wire::SYN,
            window: 32000,
            urgent_pointer: 0,
        };
        let mut b = [0; 128];
        let n = wire::encode(ip, header, &[2, 4, 4, 76], &[], &mut b).unwrap();
        e.input(1, ip, &b[..n]).unwrap();
        let p = e.poll_transmit(1, &mut b, 64).unwrap().packet.unwrap();
        let ack = wire::parse(p.ip, &b[..p.len])
            .unwrap()
            .header
            .sequence
            .wrapping_add(1);
        let n = wire::encode(
            ip,
            wire::Header {
                sequence: 1,
                acknowledgment: ack,
                flags: wire::ACK,
                ..header
            },
            &[],
            &[],
            &mut b,
        )
        .unwrap();
        e.input(2, ip, &b[..n]).unwrap();
        let id = e.accept(listener).unwrap();
        Self {
            e,
            id,
            ip,
            ack,
            seq: 1,
            now: 2,
        }
    }
    fn packet(&self, len: usize, flags: u8, sequence: u32) -> Vec<u8> {
        let mut b = vec![0; len + 20];
        wire::encode(
            self.ip,
            wire::Header {
                source_port: 40000,
                destination_port: 8080,
                sequence,
                acknowledgment: self.ack,
                flags,
                window: 32000,
                urgent_pointer: 0,
            },
            &[],
            &vec![0x53; len],
            &mut b,
        )
        .unwrap();
        b
    }
    fn feed(&mut self, len: usize, size: Option<u16>, push: bool) {
        self.now += 1;
        let b = self.packet(len, wire::ACK | if push { wire::PSH } else { 0 }, self.seq);
        assert_eq!(
            self.e
                .input_with_metadata(
                    self.now,
                    self.ip,
                    0,
                    Ipv4Options::default(),
                    &b,
                    RxPacketMetadata {
                        timestamps: Default::default(),
                        tcp_segment_size: size.and_then(NonZeroU16::new),
                        ..Default::default()
                    }
                )
                .unwrap(),
            InputDisposition::Processed
        );
        self.seq = self.seq.wrapping_add(len as u32);
    }
    fn estimate(&self) -> u32 {
        self.e.transport_info(self.id).unwrap().received_mss
    }
}
#[test]
fn receive_segment_estimate_distinguishes_raw_gro_and_direction_in_both_families() {
    for ipv4 in [true, false] {
        for (length, size, expected) in [
            (1000, None, 1000),
            (10000, Some(1000), 1000),
            (10037, Some(1000), 1000),
            (10000, None, 1460),
        ] {
            let mut r = Receiver::new(ipv4);
            assert_eq!(r.estimate(), 536);
            assert_eq!(r.e.transport_info(r.id).unwrap().mss, 1100);
            r.feed(length, size, false);
            assert_eq!(r.estimate(), expected);
            assert_eq!(r.e.transport_info(r.id).unwrap().advertised_mss, 1460);
            let mut b = vec![0; length];
            assert_eq!(r.e.read(r.id, &mut b).unwrap(), length);
            assert!(b.iter().all(|&x| x == 0x53));
            if length >= 2920 {
                let mut b = [0; 128];
                let p =
                    r.e.poll_transmit(r.now, &mut b, 64)
                        .unwrap()
                        .packet
                        .unwrap();
                assert_eq!(
                    wire::parse(p.ip, &b[..p.len])
                        .unwrap()
                        .header
                        .acknowledgment,
                    r.seq
                );
                assert!(
                    r.e.poll_transmit(r.now, &mut b, 64)
                        .unwrap()
                        .packet
                        .is_none()
                );
            }
        }
    }
}
#[test]
fn measured_receive_size_adapts_without_treating_short_push_as_path_change() {
    let mut r = Receiver::new(true);
    r.feed(1000, None, false);
    assert_eq!(r.estimate(), 1000);
    r.feed(64, None, true);
    r.feed(64, None, true);
    assert_eq!(r.estimate(), 1000);
    r.feed(600, None, false);
    assert_eq!(r.estimate(), 1000);
    r.feed(600, None, false);
    assert_eq!(r.estimate(), 600);
    r.feed(1100, None, false);
    assert_eq!(r.estimate(), 1100);
    r.feed(2500, Some(500), true);
    assert_eq!(r.estimate(), 500);
}
#[test]
fn aggregation_counts_actual_segments_for_delayed_ack_without_splitting_input() {
    for size in [None, Some(100)] {
        let mut r = Receiver::new(true);
        r.feed(200, size, false);
        let mut b = [0; 128];
        let p = r.e.poll_transmit(r.now, &mut b, 64).unwrap().packet;
        assert_eq!(p.is_some(), size.is_some());
        if let Some(p) = p {
            assert_eq!(
                wire::parse(p.ip, &b[..p.len])
                    .unwrap()
                    .header
                    .acknowledgment,
                201
            );
        }
    }
}
#[test]
fn invalid_receive_metadata_and_bad_checksum_do_not_mutate_clock_or_estimate() {
    let mut r = Receiver::new(true);
    let original = r.e.transport_info(r.id).unwrap();
    for (length, size, flags) in [
        (100, 101, wire::ACK),
        (0, 1, wire::ACK),
        (100, 100, wire::SYN | wire::ACK),
        (100, 100, wire::RST | wire::ACK),
        (100, 100, wire::URG | wire::ACK),
        (100, 100, 0),
    ] {
        let b = r.packet(length, flags, r.seq);
        assert_eq!(
            r.e.input_with_metadata(
                10000,
                r.ip,
                0,
                Ipv4Options::default(),
                &b,
                RxPacketMetadata {
                    timestamps: Default::default(),
                    tcp_segment_size: NonZeroU16::new(size),
                    ..Default::default()
                }
            ),
            Err(EndpointError::Connection(Error::InvalidArgument))
        );
        assert_eq!(r.e.transport_info(r.id).unwrap(), original);
    }
    let mut b = r.packet(1000, wire::ACK, r.seq);
    b[20] ^= 1;
    assert_eq!(
        r.e.input_with_metadata(
            10000,
            r.ip,
            0,
            Ipv4Options::default(),
            &b,
            RxPacketMetadata {
                timestamps: Default::default(),
                tcp_segment_size: NonZeroU16::new(1000),
                ..Default::default()
            }
        )
        .unwrap(),
        InputDisposition::Dropped
    );
    r.feed(1000, None, false);
    assert_eq!(r.estimate(), 1000);
    let b = r.packet(1400, wire::ACK, r.seq.wrapping_add(1_000_000));
    r.e.input(r.now + 1, r.ip, &b).unwrap();
    assert_eq!(r.estimate(), 1000);
}
