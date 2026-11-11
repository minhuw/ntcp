use super::*;

unsafe extern "C" {
    fn ntcp_test_tso_gate();
    fn ntcp_test_check_tso(l3: u32, l4: u32, mss: u32, length: u32);
    fn ntcp_test_init() -> i32;
    fn ntcp_test_pool() -> *mut c_void;
    fn ntcp_test_available() -> u32;
    fn ntcp_test_tx_count() -> u32;
    fn ntcp_test_loopback() -> u32;
    fn ntcp_test_register_tx_timestamp();
    fn ntcp_test_check_scheduled(value: u64, length: u32);
    fn ntcp_test_hold(leave: u32);
    fn ntcp_test_release();
    fn ntcp_test_finish();
}

#[test]
fn scheduled_mbuf_encoding_and_rejection_not_live_launch() {
    unsafe {
        let port = ntcp_test_init();
        assert!(port >= 0);
        struct Host;
        impl Drop for Host {
            fn drop(&mut self) {
                unsafe { ntcp_test_finish() }
            }
        }
        let _host = Host;
        let mut io = Dpdk::from_borrowed(port as u16, 0, 0, ntcp_test_pool()).unwrap();
        shared::ring_test(&mut io);
        ntcp_test_tso_gate();
        assert_eq!(io.tcp_segmentation_capabilities(), None);
        let request = TcpSegmentationRequest {
            segment_payload_len: 100,
        };
        assert!(matches!(
            io.transmit_segmented(&[], request),
            Err(TcpSegmentationError::Unsupported)
        ));
        assert!(io.enable_tcp_segmentation().is_err()); // ring PMD has no TSO.
        assert_eq!(io.tcp_segmentation_capabilities(), None);
        // Inject cached configuration only inside this private fixture. Real
        // ring mbufs exercise encoding/ownership, NOT actual NIC segmentation.
        io.tso = Some(TsoConfig {
            mtu: 1500,
            room: 128,
            max_descriptors: 512,
        });
        let caps = io.tcp_segmentation_capabilities().unwrap();
        assert!(!caps.allow_psh && !caps.allow_cwr);
        // No options, timestamps (data offset 8), and the 60-byte maximum.
        for (v6, l4) in [false, true]
            .into_iter()
            .flat_map(|v6| [20, 32, 60].map(|l4| (v6, l4)))
        {
            let l3 = if v6 { 40 } else { 20 };
            let mut packet = vec![0; 14 + l3 + l4 + 300];
            packet[12..14].copy_from_slice(&(if v6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
            if v6 {
                packet[14] = 0x60;
                packet[20] = 6;
                packet[18..20].copy_from_slice(&((l4 + 300) as u16).to_be_bytes());
            } else {
                packet[14] = 0x45;
                packet[23] = 6;
                packet[16..18].copy_from_slice(&((20 + l4 + 300) as u16).to_be_bytes());
            }
            packet[14 + l3 + 12] = (l4 as u8 / 4) << 4;
            packet[14 + l3 + 13] = 0x10;
            packet[14 + l3 + 20..14 + l3 + l4].fill(1); // NOP padding
            for _ in 0..7 {
                assert_eq!(
                    io.transmit_segmented(&packet, request).unwrap(),
                    TxOutcome::Submitted
                );
            }
            let available = ntcp_test_available();
            assert_eq!(
                io.transmit_segmented(&packet, request).unwrap(),
                TxOutcome::WouldBlock
            );
            assert_eq!(ntcp_test_available(), available);
            for _ in 0..7 {
                ntcp_test_check_tso(l3 as u32, l4 as u32, 100, packet.len() as u32);
            }
            assert_eq!(ntcp_test_available(), 1023);
            for leave in [0, 1, 2] {
                ntcp_test_hold(leave);
                assert_eq!(
                    io.transmit_segmented(&packet, request).unwrap(),
                    TxOutcome::WouldBlock
                );
                assert_eq!(ntcp_test_available(), leave);
                ntcp_test_release();
            }
            io.tso.as_mut().unwrap().max_descriptors = 1;
            assert!(matches!(
                io.transmit_segmented(&packet, request),
                Err(TcpSegmentationError::InvalidInput)
            ));
            assert_eq!(ntcp_test_tx_count(), 0);
            assert_eq!(ntcp_test_available(), 1023);
            io.tso.as_mut().unwrap().max_descriptors = 512;
            // Headers must fit the head mbuf; the device cannot take them split.
            io.tso.as_mut().unwrap().room = (14 + l3 + l4 - 1) as u16;
            assert!(matches!(
                io.transmit_segmented(&packet, request),
                Err(TcpSegmentationError::Unsupported)
            ));
            assert_eq!(ntcp_test_available(), 1023);
            io.tso.as_mut().unwrap().room = 128;
        }
        io.tso = None;
        let clock = ClockDescriptor {
            domain: ClockDomain::Device(17),
            unit: TimestampUnit::RawTicks { identity: 23 },
        };
        let when = TransmitTime { value: 123, clock };
        assert_eq!(io.tx_scheduling_capabilities(), None);
        assert_eq!(
            io.transmit_at(&[7; 64], when, None).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        for domain in [ClockDomain::Monotonic, ClockDomain::Realtime] {
            assert_eq!(
                io.enable_tx_scheduling(ClockDescriptor { domain, ..clock })
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            io.enable_tx_scheduling(clock).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let (mut offset, mut flag) = (-1, 0);
        assert!(ntcp_dpdk_tx_timestamp_lookup(&mut offset, &mut flag) < 0);
        ntcp_test_register_tx_timestamp();
        assert_eq!(ntcp_dpdk_tx_timestamp_lookup(&mut offset, &mut flag), 0);
        assert!(offset >= 0 && flag.is_power_of_two());
        assert_eq!(
            io.enable_tx_scheduling(clock).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(io.tx_scheduling_capabilities(), None); // Registry is not offload evidence.
        eprintln!(
            "SKIP live launch verification: ring PMD has no SEND_ON_TIMESTAMP hardware offload"
        );

        // PRIVATE unit-test fixture only. Bypass capability discovery solely to
        // inspect real mbufs; no production/test-pmd public enable bypass exists.
        io.tx_scheduling = Some(TimestampConfig {
            clock,
            offset,
            flag,
        });
        assert_eq!(io.tx_scheduling_capabilities().unwrap().clock, clock);
        for bad_clock in [
            ClockDescriptor {
                domain: ClockDomain::Device(18),
                ..clock
            },
            ClockDescriptor {
                domain: ClockDomain::Monotonic,
                ..clock
            },
            ClockDescriptor {
                unit: TimestampUnit::Nanoseconds,
                ..clock
            },
            ClockDescriptor {
                unit: TimestampUnit::RawTicks { identity: 24 },
                ..clock
            },
        ] {
            assert_eq!(
                io.transmit_at(
                    &[7; 64],
                    TransmitTime {
                        clock: bad_clock,
                        ..when
                    },
                    None
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for (software, hardware) in [(true, false), (false, true), (true, true), (false, false)] {
            let error = io
                .transmit_at(
                    &[7; 64],
                    when,
                    Some(TxTimestampRequest {
                        cookie: 1,
                        software,
                        hardware,
                    }),
                )
                .unwrap_err();
            assert_eq!(
                error.kind(),
                if software || hardware {
                    io::ErrorKind::Unsupported
                } else {
                    io::ErrorKind::InvalidInput
                }
            );
        }
        assert!(io.transmit_at(&[], when, None).is_err());
        assert!(
            io.transmit_at(&vec![7; MAX_PACKET_LEN + 1], when, None)
                .is_err()
        );
        assert_eq!(
            io.poll_tx_scheduling_error().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(ntcp_test_tx_count(), 0);
        assert_eq!(ntcp_test_available(), 1023);

        for value in [0, 123456789, u64::MAX] {
            for length in [64, 129, MAX_PACKET_LEN] {
                assert_eq!(
                    io.transmit_at(&vec![7; length], TransmitTime { value, clock }, None)
                        .unwrap(),
                    TxOutcome::Submitted
                );
                ntcp_test_check_scheduled(value, length as u32);
                assert_eq!(ntcp_test_available(), 1023);
            }
        }
        for _ in 0..7 {
            assert_eq!(
                io.transmit_at(&[7; 64], when, None).unwrap(),
                TxOutcome::Submitted
            );
        }
        let available = ntcp_test_available();
        assert_eq!(
            io.transmit_at(&[7; 129], when, None).unwrap(),
            TxOutcome::WouldBlock
        );
        assert_eq!(ntcp_test_available(), available);
        for _ in 0..7 {
            ntcp_test_check_scheduled(when.value, 64);
        }
        for leave in [0, 1] {
            ntcp_test_hold(leave);
            assert_eq!(
                io.transmit_at(&[7; 129], when, None).unwrap(),
                TxOutcome::WouldBlock
            );
            assert_eq!(ntcp_test_available(), leave);
            ntcp_test_release();
        }
        // Recycled mbufs do not retain the launch flag for ordinary transmit.
        assert_eq!(io.transmit(&[7; 64]).unwrap(), TxOutcome::Submitted);
        ntcp_test_loopback(); // Asserts every segment has zero offload flags.
        assert_eq!(io.receive(&mut [0; 64]).unwrap(), Some(64));
        assert_eq!(ntcp_test_available(), 1023);
    }
}
