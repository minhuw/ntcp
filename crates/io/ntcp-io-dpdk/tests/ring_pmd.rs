use ntcp_io::{
    ClockDescriptor, ClockDomain, DeviceCounters, PacketIo, PacketLayer, PacketTimestamp,
    PacketTimestamps, TimestampCapabilities, TimestampPoint, TimestampSource, TimestampUnit,
    TxOutcome, TxTimestampRequest,
};
use ntcp_io_dpdk::{Dpdk, MAX_PACKET_LEN};
use std::ffi::c_void;

// What `receive_frame` put in its frame and returned, together.
struct Received {
    frame: ntcp_io::RxFrame,
    metadata: ntcp_io::ReceivedPacket,
}

trait ReceiveWhole {
    fn receive_whole(&mut self, scratch: &mut [u8]) -> std::io::Result<Option<Received>>;
}

impl<P: PacketIo + ?Sized> ReceiveWhole for P {
    fn receive_whole(&mut self, scratch: &mut [u8]) -> std::io::Result<Option<Received>> {
        let mut frame = None;
        let metadata = self.receive_frame(scratch, &mut frame)?;
        Ok(metadata.map(|metadata| Received {
            frame: frame.expect("a received packet's frame"),
            metadata,
        }))
    }
}

unsafe extern "C" {
    fn ntcp_test_mtu(port: u16) -> i32;
    fn ntcp_test_emsgsize() -> i32;
    fn ntcp_test_init() -> i32;
    fn ntcp_test_pool() -> *mut c_void;
    fn ntcp_test_available() -> u32;
    fn ntcp_test_loopback() -> u32;
    fn ntcp_test_corrupt();
    fn ntcp_test_corrupt_bounds();
    fn ntcp_test_corrupt_next();
    fn ntcp_test_shared_ref(fill: u8, length: u32);
    fn ntcp_test_release_shared_ref() -> u32;
    fn ntcp_test_other_pool(fill: u8, length: u32);
    fn ntcp_test_other_pool_available() -> u32;
    fn ntcp_test_inject(frame: *const u8, length: u32) -> i32;
    fn ntcp_test_register_timestamp();
    fn ntcp_test_timestamp(value: u64, valid: i32, corrupt: i32);
    fn ntcp_test_tx_count() -> u32;
    fn ntcp_test_rx_count() -> u32;
    fn ntcp_test_transformed(kind: u32);
    fn ntcp_test_hold(leave: u32);
    fn ntcp_test_release();
    fn ntcp_test_finish();
    fn ntcp_test_external(length: u32);
    fn ntcp_test_external_freed() -> u32;
    fn ntcp_test_element() -> u32;
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
            // A full TX ring is not a pool shortage.
            assert_eq!(io.device_counters(), DeviceCounters::default());
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
            // Each attempt the pool could not serve, the first mbuf or a
            // later one of the chain; the borrowed adapter reports no port
            // counters (its host owns the port).
            assert_eq!(
                io.device_counters(),
                DeviceCounters {
                    tx_nombuf: 2,
                    ..DeviceCounters::default()
                }
            );
        } // Ending the adapter lifetime does not stop the borrowed port/pool.
        buffered_receive_ownership(port as u16, pool);
        frames_by_reference(port as u16, pool);
        rx_views_equivalence(port as u16, pool);
        rx_views_toggles_with_leftovers(port as u16, pool);
        drop_with_leftovers_and_outstanding_frames(port as u16, pool);
        rx_views_fault_injected_mbufs(port as u16, pool);
        transmit_rewrite_and_midchain_nombuf(port as u16, pool);
        let mut again = Dpdk::from_borrowed(port as u16, 0, 0, pool).unwrap();
        assert_eq!(again.transmit(&[1; 64]).unwrap(), TxOutcome::Submitted);
        ntcp_test_loopback();
        assert_eq!(again.receive(&mut out).unwrap(), Some(64));
    }
}

// The real PMD queue distinguishes packets still owned by the host from a
// prefetched burst owned by the adapter, including on errors and destruction.
unsafe fn buffered_receive_ownership(port: u16, pool: *mut c_void) {
    unsafe {
        let mut out = [0xa5; 256];
        {
            let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
            for sequence in 0..12u8 {
                assert_eq!(io.transmit(&[sequence; 64]).unwrap(), TxOutcome::Submitted);
                ntcp_test_loopback();
            }
            assert_eq!(ntcp_test_available(), 1023 - 12);
            assert_eq!(io.receive(&mut out).unwrap(), Some(64));
            assert_eq!(&out[..64], &[0; 64]);
            assert!(
                ntcp_test_rx_count() < 11,
                "RX must prefetch a vector-compatible burst"
            );
            assert_eq!(ntcp_test_available(), 1023 - 11);
            // A new arrival must follow the already prefetched packets.
            assert_eq!(io.transmit(&[12; 64]).unwrap(), TxOutcome::Submitted);
            ntcp_test_loopback();
            for sequence in 1..=12u8 {
                assert_eq!(io.receive(&mut out).unwrap(), Some(64));
                assert_eq!(&out[..64], &[sequence; 64]);
            }
            assert_eq!(io.receive(&mut out).unwrap(), None);
            assert_eq!(ntcp_test_available(), 1023);

            let clock = ClockDescriptor {
                domain: ClockDomain::Device(17),
                unit: TimestampUnit::RawTicks { identity: 23 },
            };
            io.enable_rx_timestamps(clock).unwrap();
            for (value, valid) in [(11, 1), (22, 0), (33, 1)] {
                ntcp_test_timestamp(value, valid, 0);
            }
            for (value, valid) in [(11, true), (22, false), (33, true)] {
                let packet = io.receive_with_metadata(&mut out).unwrap().unwrap();
                assert_eq!(packet.len, 64);
                assert_eq!(&out[..64], &[0x42; 64]);
                assert_eq!(
                    packet.timestamps.hardware,
                    valid.then_some(PacketTimestamp {
                        value,
                        source: TimestampSource::Hardware,
                        point: TimestampPoint::DeviceReceive,
                        clock,
                    })
                );
            }
            assert_eq!(ntcp_test_available(), 1023);

            assert_eq!(io.transmit(&[0x11; 64]).unwrap(), TxOutcome::Submitted);
            ntcp_test_loopback();
            ntcp_test_transformed(0);
            ntcp_test_corrupt();
            for (value, length) in [(0x22, 64), (0x44, 129), (0x33, 64)] {
                assert_eq!(
                    io.transmit(&vec![value; length]).unwrap(),
                    TxOutcome::Submitted
                );
                ntcp_test_loopback();
            }
            assert_eq!(io.receive(&mut out).unwrap(), Some(64));
            assert_eq!(&out[..64], &[0x11; 64]);
            assert_eq!(ntcp_test_rx_count(), 0);
            out.fill(0xa5);
            assert_eq!(
                io.receive(&mut out).unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            );
            assert_eq!(out, [0xa5; 256]);
            assert!(io.receive(&mut out).is_err());
            assert_eq!(out, [0xa5; 256]);
            assert_eq!(io.receive(&mut out).unwrap(), Some(64));
            assert_eq!(&out[..64], &[0x22; 64]);
            let mut short = [0xa5; 128];
            assert!(io.receive(&mut short).is_err());
            assert_eq!(short, [0xa5; 128]);
            assert_eq!(io.receive(&mut out).unwrap(), Some(64));
            assert_eq!(&out[..64], &[0x33; 64]);
            assert_eq!(io.receive(&mut out).unwrap(), None);
            assert_eq!(ntcp_test_available(), 1023);
        }

        // Drop releases unread chains, including every segment, before the
        // host destroys the borrowed port and pool.
        {
            let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
            for value in 0..3u8 {
                assert_eq!(io.transmit(&[value; 129]).unwrap(), TxOutcome::Submitted);
                assert_eq!(ntcp_test_loopback(), 2);
            }
            assert_eq!(io.receive(&mut out).unwrap(), Some(129));
            assert_eq!(ntcp_test_rx_count(), 0);
            assert_eq!(ntcp_test_available(), 1023 - 4);
        }
        assert_eq!(ntcp_test_available(), 1023);

        // Destruction frees only prefetched packets, leaving the rest of the
        // borrowed queue available to the next adapter.
        let queued;
        {
            let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
            for sequence in 0..16u8 {
                assert_eq!(io.transmit(&[sequence; 64]).unwrap(), TxOutcome::Submitted);
                ntcp_test_loopback();
            }
            assert_eq!(io.receive(&mut out).unwrap(), Some(64));
            assert_eq!(&out[..64], &[0; 64]);
            queued = ntcp_test_rx_count();
            assert!(queued > 0 && queued < 15);
        }
        assert_eq!(ntcp_test_rx_count(), queued);
        assert_eq!(ntcp_test_available(), 1023 - queued);
        let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
        for sequence in (16 - queued) as u8..16 {
            assert_eq!(io.receive(&mut out).unwrap(), Some(64));
            assert_eq!(&out[..64], &[sequence; 64]);
        }
        assert_eq!(io.receive(&mut out).unwrap(), None);
        assert_eq!(ntcp_test_available(), 1023);
    }
}

// receive_frame hands the mbuf itself over: the same bytes and metadata as
// the copying receive, its truesize the pool element, held from the pool
// until the frame drops, on whatever thread, the adapter gone or not.
// Chains and extbuf-attached mbufs come as heap copies, freed at once.
unsafe fn frames_by_reference(port: u16, pool: *mut c_void) {
    unsafe {
        let mut scratch = vec![0xa5; MAX_PACKET_LEN];
        let mut out = [0; 256];
        let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
        assert_eq!(io.receive_whole(&mut scratch).unwrap().map(|_| ()), None);
        // No budget until a host sets one; the frames are mbufs either way.
        assert_eq!(
            (io.rx_frame_budget(), io.rx_frames_outstanding()),
            (None, None)
        );
        io.set_rx_frame_budget(Some(100));
        assert_eq!(io.rx_frames_outstanding(), Some(0));
        let element = ntcp_test_element() as usize;

        let packet: Vec<u8> = (0..100u8).collect();
        for _ in 0..2 {
            assert_eq!(io.transmit(&packet).unwrap(), TxOutcome::Submitted);
            ntcp_test_loopback();
        }
        let copied = io.receive_with_metadata(&mut out).unwrap().unwrap();
        let held = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(held.frame.as_slice(), &out[..copied.len]);
        assert_eq!(held.metadata, copied);
        assert!(!held.frame.is_heap());
        assert_eq!(held.frame.truesize(), element);
        assert_eq!(scratch[0], 0xa5, "a held mbuf is not copied");
        assert_eq!(ntcp_test_available(), 1023 - 1);
        assert_eq!(io.rx_frames_outstanding(), Some(1));
        drop(held);
        assert_eq!(ntcp_test_available(), 1023);
        assert_eq!(io.rx_frames_outstanding(), Some(0));

        // Timestamps read from the mbuf it hands over, as the copy reads them.
        let clock = ClockDescriptor {
            domain: ClockDomain::Device(17),
            unit: TimestampUnit::RawTicks { identity: 23 },
        };
        io.enable_rx_timestamps(clock).unwrap();
        ntcp_test_timestamp(77, 1, 0);
        let held = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(held.frame.as_slice(), &[0x42; 64]);
        assert_eq!(held.metadata.timestamps.hardware.unwrap().value, 77);
        drop(held);

        // Released on another thread, which DPDK does not know (no lcore).
        let mut frames = Vec::new();
        for value in 0..4u8 {
            assert_eq!(io.transmit(&[value; 64]).unwrap(), TxOutcome::Submitted);
            ntcp_test_loopback();
            frames.push(io.receive_whole(&mut scratch).unwrap().unwrap().frame);
        }
        assert_eq!(io.rx_frames_outstanding(), Some(4));
        assert_eq!(ntcp_test_available(), 1023 - 4);
        let last = frames.pop().unwrap();
        std::thread::spawn(move || {
            for (value, frame) in frames.into_iter().enumerate() {
                assert_eq!(frame.as_slice(), &[value as u8; 64]);
            }
        })
        .join()
        .unwrap();
        assert_eq!(io.rx_frames_outstanding(), Some(1));
        assert_eq!(ntcp_test_available(), 1023 - 1);

        // A scatter chain (129 octets in 128-octet mbufs) and an
        // extbuf-attached mbuf are copied into heap frames.
        assert_eq!(io.transmit(&[0x33; 129]).unwrap(), TxOutcome::Submitted);
        assert_eq!(ntcp_test_loopback(), 2);
        let chain = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert!(chain.frame.is_heap());
        assert_eq!(chain.frame.as_slice(), &[0x33; 129]);
        assert_eq!((chain.metadata.len, chain.frame.truesize()), (129, 129));
        ntcp_test_external(200);
        let external = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert!(external.frame.is_heap());
        assert_eq!(external.frame.as_slice(), &[0x5a; 200]);
        assert_eq!(ntcp_test_external_freed(), 1);
        assert_eq!(ntcp_test_available(), 1023 - 1);
        assert_eq!(io.rx_frames_outstanding(), Some(1));
        drop((chain, external));

        // The adapter goes first: the frame keeps its mbuf, and its
        // release frees the block.
        drop(io);
        assert_eq!(ntcp_test_available(), 1023 - 1);
        assert_eq!(last.as_slice(), &[3; 64]);
        drop(last);
        assert_eq!(ntcp_test_available(), 1023);
    }
}

fn make_pattern_packet(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_mul(31).wrapping_add(i as u8))
        .collect()
}

// Views-on (`set_rx_frame_budget(Some)`) vs views-off (`None`, both copy path
// and non-view `receive_frame`) must yield identical bytes, metadata, counts,
// and return every mbuf to the pool across full 8-packet bursts, multi-burst
// traffic (>8 packets), and short-burst leftovers.
unsafe fn rx_views_equivalence(port: u16, pool: *mut c_void) {
    #[derive(Clone, Copy)]
    enum RxMode {
        Views,
        FrameMeta,
        Copy,
    }

    type Wave<'a> = (&'a [Vec<u8>], usize);

    unsafe fn run_scenario(
        port: u16,
        pool: *mut c_void,
        mode: RxMode,
        waves: &[Wave<'_>],
    ) -> Vec<(Vec<u8>, ntcp_io::ReceivedPacket)> {
        unsafe {
            let element = ntcp_test_element() as usize;
            let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
            match mode {
                RxMode::Views => io.set_rx_frame_budget(Some(100)),
                RxMode::FrameMeta | RxMode::Copy => io.set_rx_frame_budget(None),
            }
            let mut scratch = vec![0xa5; MAX_PACKET_LEN];
            let mut out = vec![0xa5; MAX_PACKET_LEN];
            let mut results = Vec::new();
            let mut held = Vec::new();

            for &(packets, read_count) in waves {
                for packet in packets {
                    assert_eq!(ntcp_test_inject(packet.as_ptr(), packet.len() as u32), 0);
                }
                for _ in 0..read_count {
                    match mode {
                        RxMode::Views | RxMode::FrameMeta => {
                            scratch.fill(0xa5);
                            let received = io.receive_whole(&mut scratch).unwrap().unwrap();
                            let bytes = received.frame.as_slice().to_vec();
                            if bytes.len() <= 128 {
                                assert!(!received.frame.is_heap());
                                assert_eq!(received.frame.truesize(), element);
                                assert!(
                                    scratch.iter().all(|&b| b == 0xa5),
                                    "direct mbuf must not copy into scratch"
                                );
                            } else {
                                assert!(received.frame.is_heap());
                                assert_eq!(received.frame.truesize(), bytes.len());
                            }
                            results.push((bytes, received.metadata));
                            held.push(received.frame);
                        }
                        RxMode::Copy => {
                            let metadata = io.receive_with_metadata(&mut out).unwrap().unwrap();
                            results.push((out[..metadata.len].to_vec(), metadata));
                        }
                    }
                }
            }
            assert_eq!(io.receive_whole(&mut scratch).unwrap().map(|_| ()), None);
            drop(held);
            if matches!(mode, RxMode::Views) {
                assert_eq!(io.rx_frames_outstanding(), Some(0));
            }
            drop(io);
            assert_eq!(ntcp_test_available(), 1023);
            results
        }
    }

    unsafe {
        // 1. Exact 8-packet full burst of varied single-segment sizes.
        let full_burst: Vec<Vec<u8>> = [1, 14, 60, 64, 96, 126, 127, 128]
            .into_iter()
            .enumerate()
            .map(|(i, len)| make_pattern_packet(i as u8 + 1, len))
            .collect();

        // 2. >8 packets across multiple bursts (19 packets = 8 + 8 + 3),
        // mixing direct single-segment and chained multi-segment frames.
        let multi_burst: Vec<Vec<u8>> = (0..19usize)
            .map(|i| {
                let len = match i % 5 {
                    0 => 64,
                    1 => 128,
                    2 => 129,
                    3 => 256,
                    _ => 77,
                };
                make_pattern_packet((i as u8).wrapping_add(40), len)
            })
            .collect();

        // 3. Short burst (5 packets), consume 2 leaving 3 prefetched leftovers,
        // then enqueue 6 more and drain all 9 remaining.
        let short_first: Vec<Vec<u8>> = (0..5usize)
            .map(|i| make_pattern_packet(80 + i as u8, 60 + i * 16))
            .collect();
        let short_second: Vec<Vec<u8>> = (0..6usize)
            .map(|i| make_pattern_packet(90 + i as u8, if i == 2 { 140 } else { 64 + i * 8 }))
            .collect();

        let scenarios: &[&[Wave<'_>]] = &[
            &[(&full_burst, 8)],
            &[(&multi_burst, 19)],
            &[(&short_first, 2), (&short_second, 9)],
        ];

        for &waves in scenarios {
            let views_on = run_scenario(port, pool, RxMode::Views, waves);
            let views_off_frame = run_scenario(port, pool, RxMode::FrameMeta, waves);
            let views_off_copy = run_scenario(port, pool, RxMode::Copy, waves);
            assert_eq!(views_on, views_off_frame);
            assert_eq!(views_on, views_off_copy);
        }
    }
}

// Toggling RX timestamps or `set_rx_frame_budget` while unread burst leftovers
// remain in `rx_packets[rx_next..rx_count]` discards plain views and falls back
// cleanly to `receive_meta` with no corruption or mbuf leaks.
unsafe fn rx_views_toggles_with_leftovers(port: u16, pool: *mut c_void) {
    unsafe {
        let mut scratch = vec![0xa5; MAX_PACKET_LEN];
        let clock = ClockDescriptor {
            domain: ClockDomain::Device(17),
            unit: TimestampUnit::RawTicks { identity: 23 },
        };

        // Enable RX timestamps with unread burst leftovers.
        {
            let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
            io.set_rx_frame_budget(Some(100));
            for i in 0..5u64 {
                ntcp_test_timestamp(100 + i, 1, 0);
            }
            // Packet 0 prefetches all 5 packets with plain RX views enabled.
            let first = io.receive_whole(&mut scratch).unwrap().unwrap();
            assert_eq!(first.frame.as_slice(), &[0x42; 64]);
            assert_eq!(first.metadata.timestamps.hardware, None);
            assert_eq!(ntcp_test_rx_count(), 0);

            // Toggle timestamps on while 4 prefetched leftovers remain.
            io.enable_rx_timestamps(clock).unwrap();
            for expected_ts in 101..105u64 {
                let next = io.receive_whole(&mut scratch).unwrap().unwrap();
                assert_eq!(next.frame.as_slice(), &[0x42; 64]);
                assert!(!next.frame.is_heap());
                assert_eq!(
                    next.metadata.timestamps.hardware.unwrap().value,
                    expected_ts
                );
            }
            assert_eq!(io.receive_whole(&mut scratch).unwrap().map(|_| ()), None);

            // Updating budget while timestamps are enabled must NOT re-enable
            // plain views on subsequent bursts.
            io.set_rx_frame_budget(Some(120));
            ntcp_test_timestamp(200, 1, 0);
            let after = io.receive_whole(&mut scratch).unwrap().unwrap();
            assert_eq!(after.metadata.timestamps.hardware.unwrap().value, 200);
            drop((first, after));
            assert_eq!(io.rx_frames_outstanding(), Some(0));
        }
        assert_eq!(ntcp_test_available(), 1023);

        // Toggle `set_rx_frame_budget(None)` and back to `Some` with leftovers.
        {
            let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
            io.set_rx_frame_budget(Some(100));
            let packets: Vec<Vec<u8>> = (0..6u8)
                .map(|i| make_pattern_packet(10 + i, 64 + usize::from(i) * 4))
                .collect();
            for p in &packets {
                assert_eq!(ntcp_test_inject(p.as_ptr(), p.len() as u32), 0);
            }
            // Prefetch all 6 with views on; read packet 0.
            let f0 = io.receive_whole(&mut scratch).unwrap().unwrap();
            assert_eq!(f0.frame.as_slice(), packets[0].as_slice());
            assert_eq!(ntcp_test_rx_count(), 0);

            // Disable budget while 5 leftovers exist.
            io.set_rx_frame_budget(None);
            let f1 = io.receive_whole(&mut scratch).unwrap().unwrap();
            assert_eq!(f1.frame.as_slice(), packets[1].as_slice());
            assert!(!f1.frame.is_heap());
            // Copy path on a leftover also works cleanly.
            let mut copy_buf = [0u8; 256];
            let m2 = io.receive_with_metadata(&mut copy_buf).unwrap().unwrap();
            assert_eq!(&copy_buf[..m2.len], packets[2].as_slice());

            // Re-enable budget while 3 leftovers still exist: views start empty
            // (null), so leftovers fall back to `receive_meta`.
            io.set_rx_frame_budget(Some(100));
            for expected in &packets[3..6] {
                let next = io.receive_whole(&mut scratch).unwrap().unwrap();
                assert_eq!(next.frame.as_slice(), expected.as_slice());
                assert!(!next.frame.is_heap());
            }
            assert_eq!(io.receive_whole(&mut scratch).unwrap().map(|_| ()), None);

            // Next burst uses views again cleanly.
            let next_pkt = make_pattern_packet(77, 90);
            assert_eq!(
                ntcp_test_inject(next_pkt.as_ptr(), next_pkt.len() as u32),
                0
            );
            scratch.fill(0xa5);
            let fresh = io.receive_whole(&mut scratch).unwrap().unwrap();
            assert_eq!(fresh.frame.as_slice(), next_pkt.as_slice());
            assert!(!fresh.frame.is_heap());
            assert!(scratch.iter().all(|&b| b == 0xa5));
            drop((f0, f1, fresh));
            assert_eq!(io.rx_frames_outstanding(), Some(0));
        }
        assert_eq!(ntcp_test_available(), 1023);
    }
}

// Dropping `Dpdk` while unread burst leftovers exist AND while `RxFrame`s are
// still held must immediately free unread leftovers, keep held frames valid
// across threads, leave un-prefetched ring packets intact, and return the pool
// to full availability once all frames drop.
unsafe fn drop_with_leftovers_and_outstanding_frames(port: u16, pool: *mut c_void) {
    unsafe {
        let mut scratch = vec![0xa5; MAX_PACKET_LEN];
        // 12 packets: first 3 are direct (64B) and will be held; next 5 are
        // prefetched leftovers in the first 8-packet burst (mix of 1-seg 64B
        // and 2-seg 129B); last 4 stay on the rx ring beyond the burst.
        let packets: Vec<Vec<u8>> = (0..12u8)
            .map(|i| {
                let len = if i == 4 || i == 6 { 129 } else { 64 };
                make_pattern_packet(20 + i, len)
            })
            .collect();
        let mut held = Vec::new();
        {
            let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
            io.set_rx_frame_budget(Some(100));
            for p in &packets {
                assert_eq!(ntcp_test_inject(p.as_ptr(), p.len() as u32), 0);
            }
            // 10 single-seg (10 mbufs) + 2 two-seg (4 mbufs) = 14 mbufs out.
            assert_eq!(ntcp_test_available(), 1023 - 14);
            for p in &packets[..3] {
                let rec = io.receive_whole(&mut scratch).unwrap().unwrap();
                assert_eq!(rec.frame.as_slice(), p.as_slice());
                assert!(!rec.frame.is_heap());
                held.push(rec.frame);
            }
            // Burst of 8 prefetched: 3 held, 5 unread leftovers (3x1-seg + 2x2-seg = 7 mbufs),
            // 4 still queued in the rx ring (4 mbufs).
            assert_eq!(ntcp_test_rx_count(), 4);
            assert_eq!(io.rx_frames_outstanding(), Some(3));
            assert_eq!(ntcp_test_available(), 1023 - 14);
        }
        // `Dpdk` dropped: 7 leftover mbufs freed immediately; 3 held + 4 queued remain.
        assert_eq!(ntcp_test_rx_count(), 4);
        assert_eq!(ntcp_test_available(), 1023 - 7);

        // Held frames remain readable; drop 1 here and 2 on another thread.
        assert_eq!(held[0].as_slice(), packets[0].as_slice());
        let first = held.remove(0);
        drop(first);
        assert_eq!(ntcp_test_available(), 1023 - 6);

        let expected_1 = packets[1].clone();
        let expected_2 = packets[2].clone();
        std::thread::spawn(move || {
            assert_eq!(held[0].as_slice(), expected_1.as_slice());
            assert_eq!(held[1].as_slice(), expected_2.as_slice());
            drop(held);
        })
        .join()
        .unwrap();
        assert_eq!(ntcp_test_available(), 1023 - 4);

        // Drain the 4 packets that remained on the rx ring.
        let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
        io.set_rx_frame_budget(Some(100));
        for p in &packets[8..12] {
            let rec = io.receive_whole(&mut scratch).unwrap().unwrap();
            assert_eq!(rec.frame.as_slice(), p.as_slice());
        }
        assert_eq!(io.receive_whole(&mut scratch).unwrap().map(|_| ()), None);
        drop(io);
        assert_eq!(ntcp_test_available(), 1023);
    }
}

// With RX views enabled, every non-direct, chained, refcnt>1, other-pool,
// transformed, or corrupt mbuf must be rejected by `direct_frame()` /
// `receive_check()` into fallback copy or error refusal, freeing every mbuf
// exactly once while valid neighbors in the same burst still arrive cleanly.
unsafe fn rx_views_fault_injected_mbufs(port: u16, pool: *mut c_void) {
    unsafe {
        let mut scratch = vec![0xa5; MAX_PACKET_LEN];
        let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
        io.set_rx_frame_budget(Some(100));

        // Burst 1: valid direct, 2-seg chain, extbuf, refcnt==2, other-pool, valid direct.
        let direct_a = make_pattern_packet(1, 64);
        let chained = make_pattern_packet(2, 129);
        let direct_b = make_pattern_packet(3, 80);
        let ext_freed_before = ntcp_test_external_freed();

        assert_eq!(
            ntcp_test_inject(direct_a.as_ptr(), direct_a.len() as u32),
            0
        );
        assert_eq!(ntcp_test_inject(chained.as_ptr(), chained.len() as u32), 0);
        ntcp_test_external(200);
        ntcp_test_shared_ref(0x77, 64);
        ntcp_test_other_pool(0x88, 64);
        assert_eq!(ntcp_test_other_pool_available(), 62);
        assert_eq!(
            ntcp_test_inject(direct_b.as_ptr(), direct_b.len() as u32),
            0
        );

        scratch.fill(0xa5);
        let r_direct_a = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(r_direct_a.frame.as_slice(), direct_a.as_slice());
        assert!(!r_direct_a.frame.is_heap());
        assert!(scratch.iter().all(|&b| b == 0xa5));

        let r_chained = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(r_chained.frame.as_slice(), chained.as_slice());
        assert!(r_chained.frame.is_heap());

        let r_ext = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(r_ext.frame.as_slice(), &[0x5a; 200]);
        assert!(r_ext.frame.is_heap());
        assert_eq!(ntcp_test_external_freed(), ext_freed_before + 1);

        let r_shared = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(r_shared.frame.as_slice(), &[0x77; 64]);
        assert!(r_shared.frame.is_heap());
        // Adapter must have dropped its reference without raw-freeing while refcnt==2.
        assert_eq!(ntcp_test_release_shared_ref(), 1);

        let r_other = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(r_other.frame.as_slice(), &[0x88; 64]);
        assert!(r_other.frame.is_heap());
        assert_eq!(ntcp_test_other_pool_available(), 63);

        scratch.fill(0xa5);
        let r_direct_b = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(r_direct_b.frame.as_slice(), direct_b.as_slice());
        assert!(!r_direct_b.frame.is_heap());
        assert!(scratch.iter().all(|&b| b == 0xa5));

        assert_eq!(io.receive_whole(&mut scratch).unwrap().map(|_| ()), None);
        assert_eq!(io.rx_frames_outstanding(), Some(2));
        drop((r_direct_a, r_chained, r_ext, r_shared, r_other, r_direct_b));
        assert_eq!(io.rx_frames_outstanding(), Some(0));
        assert_eq!(ntcp_test_available(), 1023);

        // Burst 2: transformed (VLAN/QinQ/LRO) and corrupt single-segment
        // (`pkt_len != data_len`, `data_off + data_len > buf_len`, `nb_segs == 1 && next != NULL`),
        // bracketed by valid direct packets in the same burst.
        let before = make_pattern_packet(4, 64);
        let after = make_pattern_packet(5, 64);
        assert_eq!(ntcp_test_inject(before.as_ptr(), before.len() as u32), 0);
        for kind in 0..3 {
            ntcp_test_transformed(kind);
        }
        ntcp_test_corrupt();
        ntcp_test_corrupt_bounds();
        ntcp_test_corrupt_next();
        assert_eq!(ntcp_test_inject(after.as_ptr(), after.len() as u32), 0);

        let r_before = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(r_before.frame.as_slice(), before.as_slice());
        assert!(!r_before.frame.is_heap());
        drop(r_before);

        for _ in 0..3 {
            let mut frame = None;
            scratch.fill(0xa5);
            let err = io.receive_frame(&mut scratch, &mut frame).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
            assert!(frame.is_none());
            assert!(scratch.iter().all(|&b| b == 0xa5));
        }
        for _ in 0..3 {
            let mut frame = None;
            scratch.fill(0xa5);
            let err = io.receive_frame(&mut scratch, &mut frame).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EIO));
            assert!(frame.is_none());
            assert!(scratch.iter().all(|&b| b == 0xa5));
        }

        let r_after = io.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(r_after.frame.as_slice(), after.as_slice());
        assert!(!r_after.frame.is_heap());
        drop(r_after);

        assert_eq!(io.receive_whole(&mut scratch).unwrap().map(|_| ()), None);
        drop(io);
        assert_eq!(ntcp_test_available(), 1023);
    }
}

// Verify `ntcp_dpdk_transmit`'s `copy_segment` rewrite:
// - zero-length transmit returns EINVAL / InvalidInput with no leaks;
// - single- and multi-segment transmits below, at, and above 128-octet tailroom
//   round-trip identically with exact segment counts;
// - pool exhaustion at head or mid-chain returns WouldBlock (NOMBUF) with zero
//   mbuf leaks and increments `tx_nombuf`.
unsafe fn transmit_rewrite_and_midchain_nombuf(port: u16, pool: *mut c_void) {
    unsafe {
        let mut io = Dpdk::from_borrowed(port, 0, 0, pool).unwrap();
        let mut out = vec![0u8; MAX_PACKET_LEN];

        // Zero-length packet is refused with EINVAL.
        let err = io.transmit(&[]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        assert_eq!(ntcp_test_tx_count(), 0);
        assert_eq!(ntcp_test_available(), 1023);

        // Tailroom is 128 octets: test below, at, and above 1x, 2x, 3x tailroom.
        for length in [1usize, 64, 127, 128, 129, 255, 256, 257, 384, 385] {
            let packet = make_pattern_packet((length % 251) as u8, length);
            assert_eq!(io.transmit(&packet).unwrap(), TxOutcome::Submitted);
            assert_eq!(ntcp_test_loopback() as usize, length.div_ceil(128));
            assert_eq!(io.receive(&mut out).unwrap(), Some(length));
            assert_eq!(&out[..length], packet.as_slice());
            assert_eq!(ntcp_test_available(), 1023);
        }

        // Pool empty at head (leave=0) and mid-chain (leave=1, leave=2) for a
        // 3-segment (257-octet) packet must unwind cleanly without leaks.
        let three_seg = make_pattern_packet(0x3c, 257);
        for (attempt, leave) in [0u32, 1, 2].into_iter().enumerate() {
            ntcp_test_hold(leave);
            assert_eq!(io.transmit(&three_seg).unwrap(), TxOutcome::WouldBlock);
            assert_eq!(ntcp_test_tx_count(), 0);
            assert_eq!(ntcp_test_available(), leave);
            assert_eq!(io.device_counters().tx_nombuf, (attempt + 1) as u64);
            ntcp_test_release();
            assert_eq!(ntcp_test_available(), 1023);
        }

        // With exactly 3 mbufs left, the 3-segment transmit succeeds cleanly.
        ntcp_test_hold(3);
        assert_eq!(io.transmit(&three_seg).unwrap(), TxOutcome::Submitted);
        assert_eq!(ntcp_test_available(), 0);
        assert_eq!(ntcp_test_loopback(), 3);
        assert_eq!(io.receive(&mut out).unwrap(), Some(257));
        assert_eq!(&out[..257], three_seg.as_slice());
        assert_eq!(ntcp_test_available(), 3);
        ntcp_test_release();
        assert_eq!(ntcp_test_available(), 1023);
    }
}
