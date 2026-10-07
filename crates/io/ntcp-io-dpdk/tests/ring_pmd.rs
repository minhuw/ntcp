use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_io_dpdk::{Dpdk, MAX_PACKET_LEN};
use std::ffi::c_void;

unsafe extern "C" {
    fn ntcp_test_init() -> i32;
    fn ntcp_test_pool() -> *mut c_void;
    fn ntcp_test_available() -> u32;
    fn ntcp_test_loopback() -> u32;
    fn ntcp_test_corrupt();
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
            assert_eq!(io.receive(&mut out).unwrap(), None);
            assert!(io.transmit(&[]).is_err());
            assert!(io.transmit(&vec![0; MAX_PACKET_LEN + 1]).is_err());
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
