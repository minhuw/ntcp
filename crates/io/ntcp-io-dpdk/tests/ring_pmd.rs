use ntcp_io::{
    ClockDescriptor, ClockDomain, PacketIo, PacketLayer, PacketTimestamp, PacketTimestamps,
    TimestampCapabilities, TimestampPoint, TimestampSource, TimestampUnit, TxOutcome,
    TxTimestampRequest,
};
use ntcp_io_dpdk::{Dpdk, MAX_PACKET_LEN};
use std::ffi::c_void;

unsafe extern "C" {
    fn ntcp_test_mtu(port: u16) -> i32;
    fn ntcp_test_emsgsize() -> i32;
    fn ntcp_test_init() -> i32;
    fn ntcp_test_pool() -> *mut c_void;
    fn ntcp_test_available() -> u32;
    fn ntcp_test_loopback() -> u32;
    fn ntcp_test_corrupt();
    fn ntcp_test_register_timestamp();
    fn ntcp_test_timestamp(value: u64, valid: i32, corrupt: i32);
    fn ntcp_test_tx_count() -> u32;
    fn ntcp_test_transformed(kind: u32);
    fn ntcp_test_hold(leave: u32);
    fn ntcp_test_release();
    fn ntcp_test_finish();
}

// Explicit test-pmd opt-in builds this fixture, not a replacement backend.
// It owns EAL/port/pool as a host would; all adapter calls use real DPDK APIs.
#[test]
fn real_ring_pmd_copy_and_ownership() {
    unsafe {
        let port = ntcp_test_init();
        assert!(port >= 0, "ring PMD host setup failed: {port}");
        struct Host;
        impl Drop for Host {
            fn drop(&mut self) {
                unsafe { ntcp_test_finish() }
            }
        }
        let _host = Host;
        let pool = ntcp_test_pool();
        assert!(Dpdk::from_borrowed(port as u16, 0, 0, std::ptr::null_mut()).is_err());
        assert!(Dpdk::from_borrowed(u16::MAX, 0, 0, pool).is_err());
        let mut out = vec![0xa5; MAX_PACKET_LEN];
        {
            let mut io = Dpdk::from_borrowed(port as u16, 0, 0, pool).unwrap();
            assert_eq!(io.layer(), PacketLayer::Ethernet);
            assert_eq!(io.max_packet_len(), Some(MAX_PACKET_LEN));
            let mtu = ntcp_test_mtu(port as u16);
            assert!(mtu > 0);
            assert_eq!(io.local_ip_mtu().unwrap(), Some(mtu as u32));
            assert_ne!(mtu as usize, MAX_PACKET_LEN);
            assert_eq!(io.receive(&mut out).unwrap(), None);
            assert!(io.transmit(&[]).is_err());
            assert_eq!(
                io.transmit(&vec![0; MAX_PACKET_LEN + 1])
                    .unwrap_err()
                    .raw_os_error(),
                Some(ntcp_test_emsgsize())
            );
            assert_eq!(ntcp_test_tx_count(), 0);
            assert_eq!(ntcp_test_available(), 1023);

            let clock = ClockDescriptor {
                domain: ClockDomain::Device(17),
                unit: TimestampUnit::RawTicks { identity: 23 },
            };
            assert_eq!(
                io.timestamp_capabilities(),
                TimestampCapabilities::default()
            );
            let status = io.rx_timestamp_status().unwrap();
            assert!(!status.supported); // Ring PMD is NOT physical timestamp evidence.
            assert_eq!(status.queue_enabled, None); // Ring lacks queue-info op.
            assert!(io.enable_rx_timestamps(clock).is_err()); // Host has not registered field.
            assert_eq!(
                io.timestamp_capabilities(),
                TimestampCapabilities::default()
            );
            ntcp_test_register_timestamp();
            ntcp_test_timestamp(99, 1, 0);
            assert_eq!(
                io.receive_with_metadata(&mut out)
                    .unwrap()
                    .unwrap()
                    .timestamps,
                PacketTimestamps::default()
            ); // Disabled even though field/flag exist.
            for bad_clock in [
                ClockDescriptor {
                    unit: TimestampUnit::Nanoseconds,
                    ..clock
                },
                ClockDescriptor {
                    domain: ClockDomain::Realtime,
                    ..clock
                },
            ] {
                assert_eq!(
                    io.enable_rx_timestamps(bad_clock).unwrap_err().kind(),
                    std::io::ErrorKind::InvalidInput
                );
            }
            io.enable_rx_timestamps(clock).unwrap();
            io.enable_rx_timestamps(clock).unwrap(); // Cached, idempotent opt-in.
            assert_eq!(
                io.timestamp_capabilities(),
                TimestampCapabilities {
                    rx_hardware: true,
                    ..TimestampCapabilities::default()
                }
            );
            assert_eq!(io.rx_timestamp_status().unwrap(), status); // No configuration mutation.
            for value in [0, 123456789, u64::MAX] {
                ntcp_test_timestamp(value, 1, 0);
                let packet = io.receive_with_metadata(&mut out).unwrap().unwrap();
                assert_eq!(packet.len, 64);
                assert_eq!(&out[..64], &[0x42; 64]);
                assert_eq!(packet.timestamps.software, None);
                assert_eq!(
                    packet.timestamps.hardware,
                    Some(PacketTimestamp {
                        value,
                        source: TimestampSource::Hardware,
                        point: TimestampPoint::DeviceReceive,
                        clock,
                    })
                );
                assert_eq!(ntcp_test_available(), 1023); // Metadata copied before free.
                ntcp_test_timestamp(value, 0, 0);
                assert_eq!(
                    io.receive_with_metadata(&mut out)
                        .unwrap()
                        .unwrap()
                        .timestamps,
                    PacketTimestamps::default()
                ); // Stale field is not a timestamp.
                assert_eq!(io.receive_with_metadata(&mut out).unwrap(), None);
            }
            for corrupt in [0, 1] {
                ntcp_test_timestamp(123, 1, corrupt);
                out.fill(0xa5);
                let capacity = if corrupt == 0 { 63 } else { out.len() };
                assert!(io.receive_with_metadata(&mut out[..capacity]).is_err());
                assert!(out.iter().all(|&byte| byte == 0xa5));
                assert_eq!(ntcp_test_available(), 1023);
                assert_eq!(io.receive_with_metadata(&mut out).unwrap(), None);
            }
            for (software, hardware) in [(true, false), (false, true), (true, true)] {
                assert_eq!(
                    io.transmit_with_timestamp(
                        &[7; 64],
                        TxTimestampRequest {
                            cookie: 42,
                            software,
                            hardware,
                        }
                    )
                    .unwrap_err()
                    .kind(),
                    std::io::ErrorKind::Unsupported
                );
                assert_eq!(ntcp_test_tx_count(), 0);
                assert_eq!(ntcp_test_available(), 1023);
            }
            assert_eq!(
                io.poll_tx_timestamp().unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            );

            assert_eq!(
                io.cancel_tx_timestamp(42).unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            );
            assert_eq!(ntcp_test_tx_count(), 0);
            assert_eq!(ntcp_test_available(), 1023);

            for length in [64, 128, 129, 4096, MAX_PACKET_LEN] {
                let mut packet: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
                let expected = packet.clone();
                assert_eq!(io.transmit(&packet).unwrap(), TxOutcome::Submitted);
                packet.fill(0); // Submitted retained no caller borrow.
                assert!(ntcp_test_available() < 1023); // Not freed while queued.
                let segments = ntcp_test_loopback();
                assert_eq!(segments as usize, length.div_ceil(128));
                assert_eq!(io.receive(&mut out).unwrap(), Some(length));
                assert_eq!(&out[..length], &expected);
                assert_eq!(ntcp_test_available(), 1023);
            }

            for kind in 0..3 {
                ntcp_test_transformed(kind);
                assert_eq!(ntcp_test_available(), 1022);
                out.fill(0xa5);
                let error = io.receive(&mut out).unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
                assert!(out.iter().all(|&byte| byte == 0xa5));
                assert_eq!(ntcp_test_available(), 1023);
                assert_eq!(io.receive(&mut out).unwrap(), None);
            }
            // In-band VLAN and QinQ tags are ordinary frame bytes, not offloads.
            for tags in [
                &[0x81, 0x00, 0x00, 42][..],
                &[0x88, 0xa8, 0x00, 43, 0x81, 0x00, 0x00, 42][..],
            ] {
                let mut packet = vec![0x11; 12];
                packet.extend_from_slice(tags);
                packet.extend_from_slice(&[0x08, 0x00]);
                packet.resize(64, 0x22);
                assert_eq!(io.transmit(&packet).unwrap(), TxOutcome::Submitted);
                ntcp_test_loopback();
                assert_eq!(io.receive(&mut out).unwrap(), Some(packet.len()));
                assert_eq!(&out[..packet.len()], packet.as_slice());
                assert_eq!(ntcp_test_available(), 1023);
            }

            assert_eq!(io.transmit(&[7; 129]).unwrap(), TxOutcome::Submitted);
            ntcp_test_loopback();
            let mut short = [0xa5; 128];
            assert!(io.receive(&mut short).is_err());
            assert_eq!(short, [0xa5; 128]); // Never a valid truncated packet.
            assert_eq!(ntcp_test_available(), 1023);
            ntcp_test_corrupt();
            assert!(io.receive(&mut out).is_err());
            assert_eq!(ntcp_test_available(), 1023);

            for _ in 0..7 {
                assert_eq!(io.transmit(&[8; 64]).unwrap(), TxOutcome::Submitted);
            }
            let available = ntcp_test_available();
            assert_eq!(io.transmit(&[9; 129]).unwrap(), TxOutcome::WouldBlock);
            assert_eq!(ntcp_test_available(), available); // Whole unsent chain freed.
            for _ in 0..7 {
                ntcp_test_loopback();
                assert_eq!(io.receive(&mut out).unwrap(), Some(64));
            }
            assert_eq!(ntcp_test_available(), 1023);
            for leave in [0, 1] {
                ntcp_test_hold(leave);
                assert_eq!(io.transmit(&[9; 129]).unwrap(), TxOutcome::WouldBlock);
                assert_eq!(ntcp_test_available(), leave); // Partial allocation unwound.
                ntcp_test_release();
            }
        } // Ending the adapter lifetime does not stop the borrowed port/pool.
        let mut again = Dpdk::from_borrowed(port as u16, 0, 0, pool).unwrap();
        assert_eq!(again.transmit(&[1; 64]).unwrap(), TxOutcome::Submitted);
        ntcp_test_loopback();
        assert_eq!(again.receive(&mut out).unwrap(), Some(64));
    }
}
