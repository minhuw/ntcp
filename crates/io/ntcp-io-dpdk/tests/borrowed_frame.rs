use ntcp_io::{BorrowedFrame, PacketIo, RxChecksum};
use ntcp_io_dpdk::Dpdk;
use std::ffi::c_void;

// SAFETY: these signatures match the private DPDK ring test fixture.
unsafe extern "C" {
    fn ntcp_test_init() -> i32;
    fn ntcp_test_pool() -> *mut c_void;
    fn ntcp_test_inject(frame: *const u8, length: u32) -> i32;
    fn ntcp_test_available() -> u32;
    fn ntcp_test_rx_count() -> u32;
    fn ntcp_test_finish();
}

fn inject(packet: &[u8]) {
    // SAFETY: inject copies `packet.len()` initialized bytes into mbufs of
    // the fixture's live pool before returning.
    assert_eq!(
        unsafe { ntcp_test_inject(packet.as_ptr(), packet.len() as u32) },
        0
    );
}

fn available() -> u32 {
    // SAFETY: reads the count of the fixture's live pool.
    unsafe { ntcp_test_available() }
}

// `consume_unannotated_frame` lends the front prefetched frame of the real
// ring PMD queue without RX checksum offload (verdict Unknown), leaves it in
// place when deferred, and frees it only once consumed. Verdicts with the
// opt-in, which the ring PMD refuses, are covered by the private fixture
// (`scheduling_tests::borrowed_checksum_verdicts`).
#[test]
fn consume_or_defer_the_front_prefetched_frame() {
    // SAFETY: this test owns EAL and both ends of the ring in its process.
    let port = unsafe { ntcp_test_init() };
    assert!(port >= 0);
    // SAFETY: the fixture port and pool stay live until `ntcp_test_finish`,
    // after the adapter and every frame it handed over have dropped.
    let mut io = unsafe { Dpdk::from_borrowed(port as u16, 0, 0, ntcp_test_pool()) }.unwrap();
    io.set_rx_frame_budget(Some(16));
    // The fixture pool's mbufs hold 128 bytes: 129 is a two-segment chain.
    let packets = [vec![3; 64], vec![5; 129], vec![7; 64], vec![11; 64]];
    for packet in &packets {
        inject(packet);
    }
    let full = available();

    // Declined: the same frame stays first, its mbuf still out.
    let mut seen = None;
    assert_eq!(
        io.consume_unannotated_frame(|bytes, checksum| {
            seen = Some((bytes.to_vec(), checksum));
            false
        }),
        BorrowedFrame::Deferred
    );
    assert_eq!(seen.take(), Some((packets[0].clone(), RxChecksum::Unknown)));
    assert_eq!(available(), full);
    assert_eq!(
        io.consume_unannotated_frame(|bytes, checksum| {
            seen = Some((bytes.to_vec(), checksum));
            true
        }),
        BorrowedFrame::Consumed
    );
    assert_eq!(seen.take(), Some((packets[0].clone(), RxChecksum::Unknown)));
    assert_eq!(available(), full + 1);
    assert_eq!(io.rx_frames_outstanding(), Some(0));

    // A chain has no plain view: deferred unseen, then copied by receive.
    assert_eq!(
        io.consume_unannotated_frame(|_, _| unreachable!("a chain is never lent")),
        BorrowedFrame::Deferred
    );
    let mut scratch = vec![0; 256];
    let mut frame = None;
    let mut meta = ntcp_io::ReceivedPacket::default();
    assert!(io.receive_frame_into(&mut scratch, &mut frame, &mut meta).unwrap());
    assert_eq!(meta.len, 129);
    assert_eq!(frame.take().unwrap().as_slice(), packets[1].as_slice());
    assert_eq!(available(), full + 3);

    // Taken normally, a direct frame is held; the next is still lent.
    assert!(io.receive_frame_into(&mut scratch, &mut frame, &mut meta).unwrap());
    let held = frame.take().unwrap();
    assert!(!held.is_heap());
    assert_eq!(held.as_slice(), packets[2].as_slice());
    assert_eq!(io.rx_frames_outstanding(), Some(1));
    assert_eq!(
        io.consume_unannotated_frame(|bytes, _| bytes == packets[3].as_slice()),
        BorrowedFrame::Consumed
    );
    assert_eq!(io.rx_frames_outstanding(), Some(1));
    assert_eq!(
        io.consume_unannotated_frame(|_, _| unreachable!("empty queue")),
        BorrowedFrame::Empty
    );
    assert!(!io.receive_frame_into(&mut scratch, &mut frame, &mut meta).unwrap());
    assert!(frame.is_none());
    drop(held);
    assert_eq!(io.rx_frames_outstanding(), Some(0));

    // Without a frame budget there are no views: deferred without a poll.
    io.set_rx_frame_budget(None);
    inject(&packets[3]);
    assert_eq!(
        io.consume_unannotated_frame(|_, _| unreachable!("no views")),
        BorrowedFrame::Deferred
    );
    // SAFETY: reads the count of the fixture's live RX ring.
    assert_eq!(unsafe { ntcp_test_rx_count() }, 1);
    let mut out = [0; 64];
    let received = io.receive_with_metadata(&mut out).unwrap().unwrap();
    assert_eq!((received.len, &out[..]), (64, packets[3].as_slice()));

    drop(io);
    assert_eq!(available(), 1023);
    // SAFETY: the only adapter and all handed-over frames have dropped.
    unsafe { ntcp_test_finish() };
}
