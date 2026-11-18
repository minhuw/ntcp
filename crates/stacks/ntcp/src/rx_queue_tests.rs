// The receive tests of the per-byte ring this queue replaced (n0bw stage
// 1), run on RxQueue with the ring's right edge: `capacity` bytes past
// the read point. Assertions on the ring's storage became ones on the
// queue's: an emptied queue holds nothing.
use super::*;
use crate::buffer::receive_differential::ReceiveQueue;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

struct Window {
    queue: RxQueue,
    capacity: usize,
}

impl Deref for Window {
    type Target = RxQueue;
    fn deref(&self) -> &RxQueue {
        &self.queue
    }
}

impl DerefMut for Window {
    fn deref_mut(&mut self) -> &mut RxQueue {
        &mut self.queue
    }
}

impl Window {
    fn new(start: Seq, capacity: usize) -> Result<Self, ()> {
        Ok(Self {
            queue: RxQueue::new(start),
            capacity,
        })
    }

    fn right_edge(&self) -> Seq {
        self.read_base.wrapping_add(self.capacity as u32)
    }

    fn insert(&mut self, sequence: Seq, payload: &[u8], fin: bool) -> ReceiveOutcome {
        self.insert_with_push(sequence, payload, fin, false)
    }

    fn insert_with_push(
        &mut self,
        sequence: Seq,
        payload: &[u8],
        fin: bool,
        push: bool,
    ) -> ReceiveOutcome {
        let limit = self.right_edge();
        let outcome = self.queue.insert(
            sequence,
            RxPayload::Borrowed(payload),
            fin,
            push,
            limit,
            |_, _| {},
        );
        self.queue.debug_check();
        outcome
    }

    fn byte_at(&self, seq: Seq) -> Option<u8> {
        ReceiveQueue::byte_at(&self.queue, seq)
    }
}

// The bytes held, in order and beyond a gap, counted one offset at a time.
fn held(recv: &Window) -> usize {
    (0..recv.capacity)
        .filter(|&offset| {
            recv.byte_at(recv.read_base.wrapping_add(offset as u32))
                .is_some()
        })
        .count()
}

// The runs a byte-by-byte scan finds are the ones block_at reports, and
// the counts and SACK emptiness agree with them.
fn assert_ranges(recv: &Window) {
    recv.debug_check();
    let mut expected = Vec::new();
    let mut offset = recv.readable();
    let present = |offset: usize| {
        recv.byte_at(recv.read_base.wrapping_add(offset as u32))
            .is_some()
    };
    while offset < recv.capacity {
        if !present(offset) {
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < recv.capacity && present(offset) {
            offset += 1;
        }
        expected.push((
            recv.read_base.wrapping_add(start as u32),
            recv.read_base.wrapping_add(offset as u32),
        ));
    }
    for &(left, right) in &expected {
        assert_eq!(recv.block_at(left), Some((left, right)));
        assert_eq!(
            recv.block_at(right.wrapping_add(u32::MAX)),
            Some((left, right))
        );
    }
    assert_eq!(recv.occupied(), held(recv));
    assert_eq!(
        recv.has_sack_blocks(),
        recv.dsack.is_some() || !expected.is_empty()
    );
    assert_eq!(recv.has_sack_blocks(), recv.sack_blocks(1)[0].is_some());
}

#[test]
fn merged_report_history_preserves_distinct_recent_blocks() {
    for start in [Seq(0), Seq(u32::MAX - 63)] {
        for limit in [3, 4] {
            let mut recv = Window::new(start, 128).unwrap();
            for offset in [10, 30, 50, 70, 90] {
                recv.insert(start.wrapping_add(offset), b"x", false);
                let first = recv.sack_blocks(limit)[0].unwrap();
                recv.commit_sack(first);
                recv.commit_report();
            }
            recv.insert(start.wrapping_add(49), &[1; 42], false);
            let bridge = recv.sack_blocks(limit);
            let history = recv.reported;
            assert_eq!(recv.sack_blocks(limit), bridge);
            assert_eq!(recv.reported, history); // Failed encoding has no commit.
            recv.commit_sack(bridge[0].unwrap());
            recv.commit_report();
            recv.insert(start.wrapping_add(110), b"x", false);
            let block =
                |left, right| Some((start.wrapping_add(left).0, start.wrapping_add(right).0));
            let report = recv.sack_blocks(limit);
            assert_eq!(
                &report[..3],
                &[block(110, 111), block(49, 91), block(30, 31)]
            );
            assert_eq!(report[3], if limit == 4 { block(10, 11) } else { None });
        }
    }
}

#[test]
fn empty_and_in_order_queues_hold_no_runs_and_keep_fin_across_wrap() {
    let capacity = 8 * 1024 * 1024;
    let start = Seq(u32::MAX - 1);
    let mut recv = Window::new(start, capacity).unwrap();
    assert_eq!((held(&recv), recv.out_of_order_end()), (0, None));
    assert_eq!(recv.sack_blocks(4), [None; 4]);
    recv.insert(start, b"abc", false);
    assert_eq!(recv.byte_at(start.wrapping_add(2)), Some(b'c'));
    assert_eq!((held(&recv), recv.out_of_order_end()), (3, None));
    assert_eq!(recv.sack_blocks(4), [None; 4]);
    assert!(recv.insert(start.wrapping_add(3), &[], true).fin);
    let mut out = [0; 3];
    assert_eq!(recv.read(&mut out), 3);
    assert_eq!(out, *b"abc");
    assert_eq!(recv.find_pending(recv.read), None);

    let mut recv = Window::new(start, 64).unwrap();
    recv.insert(start.wrapping_add(40), b"x", false);
    assert!(!recv.insert(start.wrapping_add(3), &[], true).fin);
    assert_eq!(recv.fin_sequence, None);
    assert_eq!(recv.out_of_order_end(), Some(start.wrapping_add(41)));
    assert_eq!(
        recv.block_at(start.wrapping_add(40)),
        Some((start.wrapping_add(40), start.wrapping_add(41)))
    );
}

fn receive_packet(recv: &mut Window, sequence: Seq, payload: &[u8]) -> ReceiveOutcome {
    if let Some(first) = recv.sack_blocks(4)[0] {
        recv.commit_sack(first);
    }
    recv.commit_report();
    recv.record_duplicate(sequence, payload.len());
    let behind = recv.next().distance_from(sequence);
    let skip = if behind < 1 << 31 {
        (behind as usize).min(payload.len())
    } else {
        0
    };
    recv.insert(sequence.wrapping_add(skip as u32), &payload[skip..], false)
}

#[test]
fn clear_releases_storage_without_exposing_old_payload_push_fin_or_sack() {
    let mut recv = Window::new(Seq(u32::MAX - 3), 17).unwrap();
    for complete in [false, true] {
        let start = recv.next();
        recv.insert_with_push(start, b"ab", false, true);
        recv.read(&mut [0; 1]); // Move the ring head; leave unread text.
        recv.insert_with_push(start.wrapping_add(5), b"old", true, true);
        recv.record_duplicate(start.wrapping_add(5), 3);
        if complete {
            recv.insert(start.wrapping_add(2), b"cde", false);
            assert!(recv.eof());
        }
        assert!(recv.has_data());
        recv.clear();
        assert_eq!((recv.storage(), recv.rmem(), held(&recv)), (0, 0, 0));
        assert!(!recv.has_data() && !recv.eof() && !recv.take_push());
        assert_eq!(recv.fin_sequence, None);
        assert_eq!(recv.sack_blocks(4), [None; 4]);
        recv.reset_start(Seq(100)).unwrap();
        let mut out = [0xaa; 17];
        assert_eq!(recv.read(&mut out), 0);
        assert_eq!(recv.insert(Seq(100), b"new", false).new_bytes, 3);
        assert!(!recv.take_push());
        assert_eq!(recv.read(&mut out), 3);
        assert_eq!(&out[..3], b"new");
        assert_eq!(&out[3..], &[0xaa; 14]);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Ordinary SACK selects newest contiguous retained union first, except arrivals advancing the cumulative frontier. RFC 2883 DSACK is a separate first-block extension, not asserted as ordinary RFC 2018 behavior.
//# * The first SACK block (i.e., the one immediately following the kind and
//# length fields in the option) MUST specify the contiguous block of data
//# containing the segment which triggered this ACK, unless that segment
//# advanced the Acknowledgment Number field in the header.
//= https://www.rfc-editor.org/rfc/rfc2018#section-4
//= type=test
//= reason=Four successful first-block anchors provide report history; anchors resolve through the out-of-order runs after merges and cumulative advancement. Encoding failure does not change history.
//# * The SACK option SHOULD be filled out by repeating the most recently
//# reported SACK blocks (based on first SACK blocks in previous SACK options)
//# that are not subsets of a SACK block already included in the SACK option
//# being constructed.
//= https://www.rfc-editor.org/rfc/rfc2018#section-3
//= type=test
//= reason=Gap filling advances cumulative frontier and removes consumed ordinary SACK ranges; test follows section-7 examples.
//# When missing segments are received, the data receiver acknowledges the data
//# normally by advancing the left window edge in the Acknowledgement Number
//# Field of the TCP header. The SACK option does not change the meaning of the
//# Acknowledgement Number field.
//= https://www.rfc-editor.org/rfc/rfc2018#section-3
//= type=test
//= reason=Ordinary emitted ranges represent queued contiguous non-frontier data, not holes or FIN; focused examples assert full edges and coalescing.
//# This option contains a list of some of the blocks of contiguous sequence
//# space occupied by data that has been received and queued within the window.
//= https://www.rfc-editor.org/rfc/rfc2018#section-3
//= type=test
//= reason=Receive ranges begin at first retained byte, as asserted by RFC example edges.
//# This is the first sequence number of this block.
//= https://www.rfc-editor.org/rfc/rfc2018#section-3
//= type=test
//= reason=Ranges use exclusive right edges; example tests assert last+1 and merges.
//# This is the sequence number immediately following the last sequence number
//# of this block.
//= https://www.rfc-editor.org/rfc/rfc2018#section-3
//= type=test
//= reason=Ordinary ranges coalesce adjacent retained bytes and exclude contiguous frontier. DSACK extension is not an ordinary isolated block.
//# Each block represents received bytes of data that are contiguous and
//# isolated; that is, the bytes just below the block, (Left Edge of Block - 1),
//# and just above the block, (Right Edge of Block), have not been received.
fn sack_rfc2018_examples_repeat_recent_blocks_and_merge() {
    // RFC 2018 section 7 cases 2 and 3; ordinary SACK, without DSACK.
    let mut recv = Window::new(Seq(5000), 4000).unwrap();
    for sequence in (5500..9000).step_by(500) {
        recv.insert(Seq(sequence), &[1; 500], false);
        assert_eq!(recv.next(), Seq(5000));
        assert_eq!(
            recv.sack_blocks(3),
            [Some((5500, sequence + 500)), None, None, None]
        );
        assert_ranges(&recv);
    }
    recv.insert(Seq(5000), &[2; 500], false);
    assert_eq!(recv.next(), Seq(9000));
    assert_eq!(recv.sack_blocks(4), [None; 4]);

    let mut recv = Window::new(Seq(5000), 4000).unwrap();
    recv.insert(Seq(5000), &[1; 500], false);
    let expected = [
        [Some((6000, 6500)), None, None, None],
        [Some((7000, 7500)), Some((6000, 6500)), None, None],
        [
            Some((8000, 8500)),
            Some((7000, 7500)),
            Some((6000, 6500)),
            None,
        ],
    ];
    for (sequence, blocks) in [6000, 7000, 8000].into_iter().zip(expected) {
        recv.insert(Seq(sequence), &[1; 500], false);
        assert_eq!(recv.next(), Seq(5500));
        assert_eq!(recv.sack_blocks(3), blocks);
        assert_eq!(recv.sack_blocks(1), [blocks[0], None, None, None]);
        assert_ranges(&recv);
        recv.commit_sack(blocks[0].unwrap());
        recv.commit_report();
    }
    recv.insert(Seq(6500), &[2; 500], false);
    assert_eq!(
        recv.sack_blocks(3),
        [Some((6000, 7500)), Some((8000, 8500)), None, None]
    );
    recv.insert(Seq(5500), &[2; 500], false);
    assert_eq!(recv.next(), Seq(7500));
    assert_eq!(recv.sack_blocks(3), [Some((8000, 8500)), None, None, None]);
    assert_ranges(&recv);
}

#[test]
fn sack_full_ranges_reorder_merge_read_and_wrap() {
    for start in [Seq(0), Seq(u32::MAX - 9), Seq(u32::MAX - 65540)] {
        let mut recv = Window::new(start, 70000).unwrap();
        for offset in [65536, 10, 30, 20, 40] {
            receive_packet(&mut recv, start.wrapping_add(offset), b"ab");
            assert_ranges(&recv);
        }
        let block = |left, right| Some((start.wrapping_add(left).0, start.wrapping_add(right).0));
        assert_eq!(recv.sack_blocks(0), [None; 4]);
        assert_eq!(
            recv.sack_blocks(3),
            [block(40, 42), block(20, 22), block(30, 32), None]
        );
        assert_eq!(
            recv.sack_blocks(99),
            [block(40, 42), block(20, 22), block(30, 32), block(10, 12)]
        );
        receive_packet(&mut recv, start.wrapping_add(12), &[b'x'; 18]);
        assert_eq!(
            recv.sack_blocks(4),
            [
                block(20, 22),
                block(10, 32),
                block(40, 42),
                block(65536, 65538)
            ]
        );
        recv.clear_dsack();
        assert_eq!(
            recv.sack_blocks(4),
            [block(10, 32), block(40, 42), block(65536, 65538), None]
        );
        receive_packet(&mut recv, start, &[b'y'; 10]);
        assert_eq!(recv.next(), start.wrapping_add(32));
        assert_eq!(
            recv.sack_blocks(4),
            [block(40, 42), block(65536, 65538), None, None]
        );
        assert_eq!(recv.read(&mut [0; 32]), 32);
        assert_ranges(&recv);
        receive_packet(&mut recv, start.wrapping_add(32), &[b'z'; 8]);
        assert_eq!(recv.sack_blocks(4), [block(65536, 65538), None, None, None]);
        assert_ranges(&recv);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2883#section-4
//= type=test
//= reason=Connection input clears prior D-SACK after clock validation and before all protocol drops; Endpoint rejects checksum-invalid packets before this boundary. Only SACK-negotiated, validated duplicate text records a new interval; FIN/control is not duplicate data. Packet batching tests cover ACK-only, rejected ACK/sequence, missing TS and PAWS-stale supersession across wrap, while output failure without new arrival preserves the report.
//# (1) A D-SACK block is only used to report a duplicate contiguous
//# sequence of data received by the receiver in the most recent packet.
//= https://www.rfc-editor.org/rfc/rfc2883#section-4
//= type=test
//= reason=Records raw duplicate start/exclusive end before trimming, including already-read cumulative bytes and wrap.
//# (3) The left edge of the D-SACK block specifies the first sequence
//# number of the duplicate contiguous sequence, and the right edge of
//# the D-SACK block specifies the sequence number immediately following
//# the last sequence in the duplicate contiguous sequence.
fn dsack_raw_prefix_after_read_latest_packet_and_commit() {
    for start in [Seq(100), Seq(u32::MAX - 3)] {
        let mut recv = Window::new(start, 16).unwrap();
        receive_packet(&mut recv, start, b"abcdefgh");
        assert_eq!(recv.read(&mut [0; 8]), 8);
        receive_packet(&mut recv, start, b"XXXXXXXX");
        let old = Some((start.0, start.wrapping_add(8).0));
        assert_eq!(recv.sack_blocks(4), [old, None, None, None]);
        assert_eq!(recv.sack_blocks(4), [old, None, None, None]); // Failed send does not commit.
        recv.clear_dsack();
        assert_eq!(recv.sack_blocks(4), [None; 4]);
        let mixed = receive_packet(&mut recv, start.wrapping_add(6), b"XXij");
        assert_eq!(mixed.new_bytes, 2);
        assert_eq!(
            recv.sack_blocks(4),
            [
                Some((start.wrapping_add(6).0, start.wrapping_add(8).0)),
                None,
                None,
                None
            ]
        );
        let mut out = [0; 2];
        assert_eq!(recv.read(&mut out), 2);
        assert_eq!(&out, b"ij");
        receive_packet(&mut recv, start.wrapping_add(1), b"XX");
        assert_eq!(
            recv.sack_blocks(1)[0],
            Some((start.wrapping_add(1).0, start.wrapping_add(3).0))
        );
        receive_packet(&mut recv, start.wrapping_add(10), b"k");
        assert_eq!(recv.sack_blocks(4), [None; 4]);
        recv.insert(start.wrapping_add(11), b"", true);
        recv.record_duplicate(start.wrapping_add(11), 1); // Received FIN is not data.
        assert_eq!(recv.sack_blocks(4), [None; 4]);
        recv.record_duplicate(start.wrapping_add(10), 2);
        assert_eq!(
            recv.sack_blocks(4)[0],
            Some((start.wrapping_add(10).0, start.wrapping_add(11).0))
        );
        recv.record_duplicate(start, 0);
        assert_eq!(recv.sack_blocks(4), [None; 4]);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2883#section-4
//= type=test
//= reason=Above-ACK DSACK emits full containing range second; one-slot budget declines that duplicate report and emits ordinary enclosing block instead, avoiding ambiguous DSACK. Conditional rule applies only if DSACK actually reported.
//# (4) If the D-SACK block reports a duplicate contiguous sequence from
//# a (possibly larger) block of data in the receiver's data queue above
//# the cumulative acknowledgement, then the second SACK block in that
//# SACK option should specify that (possibly larger) block of data.
//= https://www.rfc-editor.org/rfc/rfc2883#section-4
//= type=test
//= reason=Remaining available slots contain other retained ranges (at most four total/three with padded TS); ordinary RFC2018 reporting resource gaps remain separate TODOs.
//# (5) Following the SACK blocks described above for reporting duplicate
//# segments, additional SACK blocks can be used for reporting additional
//# blocks of data, as specified in RFC 2018.
//= https://www.rfc-editor.org/rfc/rfc2883#section-4.2
//= type=test
//= reason=First raw prefix/earliest retained-range overlap wins; erratum365 fixes illustrative second arrival to 2500-2999 and existing example6 test matches it.
//# When the SACK option is used for reporting partial duplicate
//# segments, the first D-SACK block reports the first duplicate sub-
//# segment.  If the data packet being acknowledged contains multiple
//# partial duplicate sub-segments, then only the first such duplicate
//# sub-segment is reported in the SACK option.
fn dsack_first_duplicate_region_and_containing_full_range() {
    let mut recv = Window::new(Seq(1000), 4000).unwrap();
    receive_packet(&mut recv, Seq(3500), &[b'a'; 500]);
    receive_packet(&mut recv, Seq(1500), &[b'b'; 500]);
    // RFC2883 example 6, erratum 365: second delayed block is 2500-2999.
    receive_packet(&mut recv, Seq(2500), &[b'c'; 500]);
    receive_packet(&mut recv, Seq(1500), &[b'x'; 1500]);
    assert_eq!(
        recv.sack_blocks(3),
        [
            Some((1500, 2000)),
            Some((1500, 3000)),
            Some((3500, 4000)),
            None
        ]
    );
    assert_ranges(&recv);
    recv.clear_dsack();
    assert_eq!(
        recv.sack_blocks(4),
        [Some((1500, 3000)), Some((3500, 4000)), None, None]
    );
    receive_packet(&mut recv, Seq(1800), &[b'x'; 100]);
    assert_eq!(
        recv.sack_blocks(4),
        [
            Some((1800, 1900)),
            Some((1500, 3000)),
            Some((3500, 4000)),
            None
        ]
    );
    receive_packet(&mut recv, Seq(1000), &[b'y'; 600]);
    assert_eq!(
        recv.sack_blocks(4),
        [Some((1500, 1600)), Some((3500, 4000)), None, None]
    );
    assert_ranges(&recv);
    // An old prefix wins over a later, separate OOO duplicate region.
    receive_packet(&mut recv, Seq(2800), &[b'z'; 800]);
    assert_eq!(recv.sack_blocks(4)[0], Some((2800, 3000)));
}

#[test]
fn one_block_budget_preserves_full_range_and_below_ack_dsack() {
    for start in [Seq(1000), Seq(u32::MAX - 12)] {
        let mut recv = Window::new(start, 64).unwrap();
        receive_packet(&mut recv, start.wrapping_add(10), &[b'x'; 10]);
        receive_packet(&mut recv, start.wrapping_add(12), &[b'x'; 3]);
        let containing = Some((start.wrapping_add(10).0, start.wrapping_add(20).0));
        let duplicate = Some((start.wrapping_add(12).0, start.wrapping_add(15).0));
        assert_eq!(recv.sack_blocks(0), [None; 4]);
        assert_eq!(recv.sack_blocks(1), [containing, None, None, None]);
        // Planning a smaller option did not consume the pending duplicate.
        assert_eq!(recv.sack_blocks(2), [duplicate, containing, None, None]);
        receive_packet(&mut recv, start, &[b'y'; 10]);
        recv.record_duplicate(start.wrapping_add(12), 3);
        assert_eq!(recv.sack_blocks(1), [duplicate, None, None, None]);
        recv.clear_dsack();
        assert_eq!(recv.sack_blocks(1), [None; 4]);
    }
}

#[test]
fn exhausted_output_bounds_report_work_without_losing_readable_bytes() {
    let mut recv = Window::new(Seq(u32::MAX - 7), 17).unwrap();
    for _ in 0..8 {
        let start = recv.next();
        for offset in (1..17).step_by(2) {
            assert_eq!(
                recv.insert(start.wrapping_add(offset), b"a", false)
                    .new_bytes,
                1
            );
        }
        recv.insert(start, &[b'b'; 17], false);
        let mut out = [0; 17];
        assert_eq!(recv.read(&mut out), 17);
        assert!(
            out.iter()
                .enumerate()
                .all(|(i, &byte)| byte == if i % 2 == 0 { b'b' } else { b'a' })
        );
        assert_eq!(recv.reported, [None; 4]); // Arrival is not report history.
        assert!(recv.report_debt <= 17);
        assert_eq!(recv.sack_blocks(4), [None; 4]); // Read data is never fabricated as queued SACK.
    }
    assert_eq!(recv.report_debt, 17);
    for _ in 0..17 {
        recv.commit_report();
    }
    assert!(!recv.has_pending_report());
    assert_eq!(recv.storage_less_spare(), 0);
}

// In-order arrivals beyond no retained byte take the copying path, the
// rest the per-byte one. Mixed at random across ring wraps, with partial
// reads, they count every new byte once and deliver the stream exactly.
#[test]
fn copying_and_per_byte_insertion_deliver_the_same_stream() {
    for capacity in [61, 64, 256] {
        let start = Seq(u32::MAX - 40);
        let mut recv = Window::new(start, capacity).unwrap();
        let stream: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
        let mut received = alloc::vec![false; stream.len()];
        let mut random = 7u32;
        let mut draw = |bound: u32| {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            ((random >> 8) % bound) as usize
        };
        let mut delivered = Vec::new();
        let mut out = alloc::vec![0; capacity];
        while delivered.len() < stream.len() {
            let base = delivered.len();
            let frontier = base + recv.readable();
            let (from, len) = if draw(3) == 0 {
                (frontier + 1 + draw(12), 1 + draw(8))
            } else {
                (frontier, 1 + draw(24))
            };
            let end = (from + len).min(base + capacity).min(stream.len());
            if from < end {
                let fresh = (from..end).filter(|&i| !received[i]).count();
                let outcome = recv.insert_with_push(
                    start.wrapping_add(from as u32),
                    &stream[from..end],
                    false,
                    draw(2) == 0,
                );
                assert_eq!(outcome.new_bytes, fresh, "{from}..{end}");
                received[from..end].fill(true);
            }
            let want = draw(capacity as u32 + 1);
            let count = recv.read(&mut out[..want]);
            delivered.extend_from_slice(&out[..count]);
        }
        assert_eq!(delivered, stream);
        assert_eq!(recv.readable(), 0);
    }
}

#[test]
fn alternating_window_retains_every_byte_across_wrap_and_bridges() {
    for capacity in [255, 256, 8192] {
        let start = Seq(u32::MAX - 64);
        let mut recv = Window::new(start, capacity).unwrap();
        for offset in (1..capacity).step_by(2) {
            let outcome =
                recv.insert_with_push(start.wrapping_add(offset as u32), b"a", false, true);
            assert_eq!(outcome.new_bytes, 1);
            assert!(!outcome.sack_overflow);
            assert_eq!(
                recv.sack_blocks(4)[0],
                Some((
                    start.wrapping_add(offset as u32).0,
                    start.wrapping_add(offset as u32 + 1).0
                ))
            );
        }
        assert_ranges(&recv);
        for offset in (0..capacity).step_by(2) {
            assert_eq!(
                recv.insert(start.wrapping_add(offset as u32), b"b", false)
                    .new_bytes,
                1
            );
        }
        assert_eq!(recv.readable(), capacity);
        assert!(recv.take_push());
        assert_eq!(recv.sack_blocks(4), [None; 4]);
        let mut out = alloc::vec![0; capacity];
        assert_eq!(recv.read(&mut out), capacity);
        assert!(
            out.iter()
                .enumerate()
                .all(|(i, b)| *b == if i % 2 == 0 { b'b' } else { b'a' })
        );
        assert!(!recv.has_data());
        // Reuse at a non-word-aligned ring head.
        let next = recv.next();
        recv.insert(next, b"abc", false);
        recv.read(&mut out[..3]);
        let next = recv.next();
        recv.insert(next.wrapping_add(33), b"xyz", true);
        recv.insert(next, &[b'q'; 33], false);
        assert!(recv.eof());
        assert_eq!(recv.read(&mut out), 36);
    }
}

#[test]
fn bounded_recency_survives_many_arrivals_and_metadata_matches_ring() {
    let mut recv = Window::new(Seq(u32::MAX - 10), 256).unwrap();
    let mut random = 1u32;
    for _ in 0..4000 {
        random = random.wrapping_mul(1664525).wrapping_add(1013904223);
        let offset = random % 260;
        let sequence = recv.next().wrapping_add(offset);
        receive_packet(&mut recv, sequence, &[b'x'; 3]);
        assert_ranges(&recv);
        if random & 7 == 0 {
            let next = recv.next();
            receive_packet(&mut recv, next, b"abc");
            recv.read(&mut [0; 16]);
            assert_ranges(&recv);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# If a segment's contents straddle the boundary between old and new, only the new
//# parts are processed.
fn wraps_trims_overlaps_and_reuses_read_credit() {
    let start = Seq(u32::MAX - 2);
    let mut recv = Window::new(start, 6).unwrap();
    let result = recv.insert(start.wrapping_add(2), b"cdefgh", false);
    assert_eq!(result.new_bytes, 4);
    assert!(result.out_of_order);
    assert!(!result.advanced);
    // Out-of-order bytes are retained but unreadable until the gap is filled.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# Segments with higher beginning sequence numbers SHOULD be held for later
    //# processing (SHLD-31).
    assert_eq!(recv.readable(), 0);
    assert_eq!(held(&recv), 4);
    let result = recv.insert(start.wrapping_add(u32::MAX), b"!abXYZ", false);
    assert_eq!(result.new_bytes, 2);
    assert!(result.advanced);
    assert_eq!(recv.next(), Seq(3));
    assert_eq!(recv.right_edge(), Seq(3));
    assert_eq!(recv.insert(start, b"XXXXXX", false).new_bytes, 0);
    assert_eq!(recv.insert(recv.right_edge(), b"g", false).new_bytes, 0);
    let mut out = [0; 8];
    assert_eq!(recv.read(&mut out[..2]), 2);
    assert_eq!(&out[..2], b"ab");
    assert_eq!(recv.next(), Seq(3));
    assert_eq!(recv.right_edge(), Seq(5));
    assert_eq!(recv.insert(Seq(3), b"ghi", false).new_bytes, 2);
    assert_eq!(recv.read(&mut out), 6);
    assert_eq!(&out[..6], b"cdefgh");
    assert_eq!(recv.read(&mut out), 0);
    assert_eq!(recv.next(), Seq(5));
    assert_eq!(held(&recv), 0);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
//= type=test
//# while the FIN is considered to occur after the last actual data octet in a segment
//# in which it occurs.
fn pending_fin_waits_for_gap_and_only_consumes_once() {
    let mut recv = Window::new(Seq(u32::MAX - 1), 8).unwrap();
    let pending = recv.insert(Seq(0), b"cd", true);
    assert_eq!(pending.new_bytes, 2);
    assert!(pending.out_of_order);
    assert!(!pending.fin);
    assert!(!pending.advanced);
    assert_eq!(recv.fin_sequence, Some(Seq(2)));
    assert!(!recv.insert(Seq(2), b"", true).fin);
    assert_eq!(recv.insert(Seq(2), b"ignored", false).new_bytes, 0);
    let completed = recv.insert(Seq(u32::MAX - 1), b"abXXtail", false);
    assert_eq!(completed.new_bytes, 2);
    assert!(completed.advanced && completed.fin);
    assert!(!completed.out_of_order);
    assert_eq!(recv.next(), Seq(3));
    assert!(recv.eof());
    let duplicate = recv.insert(Seq(2), b"", true);
    assert!(duplicate.out_of_order);
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //# one and only one copy of the control will be acted upon
    assert!(!duplicate.fin && !duplicate.advanced);
    assert_eq!(recv.insert(Seq(3), b"x", true).new_bytes, 0);
    let mut out = [0; 8];
    assert_eq!(recv.read(&mut out[..1]), 1);
    assert_eq!(out[0], b'a');
    assert_eq!(recv.next(), Seq(3));
    assert_eq!(recv.read(&mut out), 3);
    assert_eq!(&out[..3], b"bcd");
    assert_eq!(recv.next(), Seq(3));
    assert!(recv.eof());
    assert_eq!(recv.reset_start(Seq(100)), Err(()));
}

#[test]
fn in_order_text_with_fin_ends_the_stream_across_the_wrap() {
    let mut recv = Window::new(Seq(u32::MAX - 1), 8).unwrap();
    recv.insert(Seq(u32::MAX - 1), b"abcde", false);
    let mut out = [0; 8];
    assert_eq!(recv.read(&mut out[..5]), 5);
    let result = recv.insert_with_push(Seq(3), b"fghijk", true, true);
    assert_eq!(result.new_bytes, 6);
    assert!(result.fin && result.advanced && !result.out_of_order);
    assert!(recv.eof() && recv.take_push());
    assert_eq!(recv.next(), Seq(10));
    assert_eq!(recv.fin_sequence, Some(Seq(9)));
    assert!(!recv.insert(Seq(9), b"", true).fin);
    assert_eq!(recv.read(&mut out), 6);
    assert_eq!(&out[..6], b"fghijk");
    assert_eq!(recv.storage_less_spare(), 0);
}

#[test]
fn rejects_fin_conflicts_without_destroying_accepted_bytes() {
    let mut recv = Window::new(Seq(10), 8).unwrap();
    recv.insert(Seq(14), b"e", false);
    for position in [9, 12, 14, 18] {
        assert!(!recv.insert(Seq(position), b"", true).fin);
        assert_eq!(recv.fin_sequence, None);
    }
    recv.insert(Seq(15), b"", true);
    assert_eq!(recv.fin_sequence, Some(Seq(15)));
    for position in [12, 16] {
        recv.insert(Seq(position), b"", true);
        assert_eq!(recv.fin_sequence, Some(Seq(15)));
    }
    let result = recv.insert(Seq(10), b"abcde", false);
    assert!(result.fin);
    assert_eq!(recv.next(), Seq(16));
    let mut out = [0; 6];
    assert_eq!(recv.read(&mut out), 5);
    assert_eq!(&out[..5], b"abcde");

    let mut recv = Window::new(Seq(0), 4).unwrap();
    recv.insert(Seq(0), b"abcd", true); // FIN at right edge is excluded.
    assert_eq!(recv.fin_sequence, None);
    assert!(!recv.insert(Seq(2), b"", true).fin);
    assert_eq!(recv.read(&mut out[..1]), 1);
    let result = recv.insert(Seq(4), b"", true);
    assert!(result.fin && result.advanced);
    assert_eq!(recv.readable(), 3);
}

#[test]
fn reading_preserves_out_of_order_data_and_pending_fin() {
    let mut recv = Window::new(Seq(10), 6).unwrap();
    recv.insert(Seq(14), b"e", true);
    recv.insert(Seq(10), b"ab", false);
    let mut out = [0; 6];
    assert_eq!(recv.read(&mut out), 2);
    assert_eq!(&out[..2], b"ab");
    assert_eq!(recv.next(), Seq(12));
    assert_eq!(recv.right_edge(), Seq(18));
    assert_eq!(recv.insert(Seq(15), b"xyz", false).new_bytes, 0);
    let completed = recv.insert(Seq(12), b"cd", false);
    assert!(completed.fin && completed.advanced);
    assert_eq!(recv.read(&mut out), 3);
    assert_eq!(&out[..3], b"cde");
    assert_eq!(recv.next(), Seq(16));
}

#[test]
fn adversarial_gaps_are_held_and_released_at_read() {
    let mut recv = Window::new(Seq(0), 64).unwrap();
    for offset in (1..64).step_by(2) {
        assert_eq!(
            recv.insert(Seq(offset), &[offset as u8], false).new_bytes,
            1
        );
    }
    assert_eq!(recv.readable(), 0);
    assert_eq!(held(&recv), 32);
    for offset in (0..64).step_by(2) {
        assert_eq!(
            recv.insert(Seq(offset), &[offset as u8], false).new_bytes,
            1
        );
    }
    assert_eq!(recv.readable(), 64);
    assert_eq!(held(&recv), 64);
    let mut out = [0; 64];
    assert_eq!(recv.read(&mut out), 64);
    for (offset, &byte) in out.iter().enumerate() {
        assert_eq!(byte, offset as u8);
    }
    assert_eq!((recv.storage_less_spare(), recv.rmem()), (0, 0));
}

#[test]
fn empty_queue_holds_nothing_and_has_data_follows_held_bytes() {
    let mut recv = Window::new(Seq(u32::MAX - 8), 8192).unwrap();
    assert_eq!(recv.storage(), 0);
    assert!(!recv.has_data());
    assert_eq!(recv.reset_start(Seq(10)), Ok(()));
    recv.insert(Seq(12), b"cd", false);
    assert!(recv.has_data());
    assert_eq!(recv.reset_start(Seq(20)), Err(()));
    recv.insert(Seq(10), b"ab", false);
    assert!(recv.has_data());
    assert_eq!(recv.read(&mut [0; 4]), 4);
    assert!(!recv.has_data());
    assert_eq!(recv.storage_less_spare(), 0);
    assert_eq!(recv.reset_start(Seq(20)), Ok(()));
}

#[test]
fn exact_capacity_wrap_overlap_push_and_fin() {
    for capacity in (1..=9).chain([15, 17, 63, 65, 70, 127, 129]) {
        let mut recv = Window::new(Seq(u32::MAX - 3), capacity).unwrap();
        let payload: Vec<_> = (0..capacity).map(|i| i as u8).collect();
        let mut out = alloc::vec![0; capacity];
        for _ in 0..3 {
            let start = recv.next();
            assert_eq!(recv.right_edge(), start.wrapping_add(capacity as u32));
            let last = start.wrapping_add(capacity as u32 - 1);
            recv.insert_with_push(last, &payload[capacity - 1..], false, true);
            // Duplicate PSH changes only the mark, not the stored byte.
            assert_eq!(recv.insert_with_push(last, b"!", false, true).new_bytes, 0);
            recv.insert(start, &payload, false);
            assert!(recv.take_push());
            assert!(!recv.take_push());
            assert_eq!(recv.insert(recv.right_edge(), b"!", false).new_bytes, 0);
            assert_ranges(&recv);
            // Moving the head by one crosses bit-byte and ring boundaries
            // over successive cycles; cleared slots must be fully rewritten.
            assert_eq!(recv.read(&mut out[..1]), 1);
            assert_eq!(out[0], payload[0]);
            let next = recv.next();
            assert_eq!(recv.insert(next, b"z", false).new_bytes, 1);
            assert!(!recv.take_push());
            assert_eq!(recv.read(&mut out), capacity);
            assert_eq!(&out[..capacity - 1], &payload[1..]);
            assert_eq!(out[capacity - 1], b'z');
            assert_eq!(recv.storage_less_spare(), 0);
            assert!(!recv.has_data());
        }
        let start = recv.next();
        let fin = start.wrapping_add(capacity as u32 - 1);
        recv.insert(fin, b"", true);
        recv.insert_with_push(start, &payload[..capacity - 1], false, true);
        assert!(recv.eof());
        assert_eq!(recv.next(), fin.wrapping_add(1));
        assert_eq!(recv.read(&mut out), capacity - 1);
        assert_eq!(&out[..capacity - 1], &payload[..capacity - 1]);
        assert_eq!(recv.storage_less_spare(), 0);
    }
}

#[test]
fn peek_preserves_credit_frontiers_metadata_and_wraparound() {
    let mut recv = Window::new(Seq(100), 8).unwrap();
    recv.insert(Seq(100), b"abcdef", false);
    assert_eq!(recv.read(&mut [0; 5]), 5);
    recv.insert(Seq(106), b"ghij", false);
    recv.insert(Seq(112), b"z", false); // Out-of-order byte is not readable.
    let before = (
        ReceiveQueue::snapshot(&recv.queue),
        recv.storage(),
        recv.rmem(),
    );
    let mut out = [0; 16];
    for _ in 0..2 {
        assert_eq!(recv.peek(&mut out), 5);
        assert_eq!(&out[..5], b"fghij");
        assert_eq!(
            (
                ReceiveQueue::snapshot(&recv.queue),
                recv.storage(),
                recv.rmem()
            ),
            before
        );
    }
    assert_eq!(recv.read(&mut out), 5);
    assert_eq!(&out[..5], b"fghij");
    assert_eq!(recv.peek(&mut out), 0);
}

#[test]
fn empty_reset_and_outcome_flags() {
    let mut recv = Window::new(Seq(0), 2).unwrap();
    assert_eq!(recv.reset_start(Seq(10)), Ok(()));
    let result = recv.insert(Seq(42), b"", false);
    assert_eq!(result.new_bytes, 0);
    assert!(!result.advanced && !result.fin && !result.out_of_order);
    assert_eq!(recv.next(), Seq(10));
    let rejected = recv.insert(Seq(42), b"x", false);
    assert!(rejected.out_of_order);
    assert_eq!(rejected.new_bytes, 0);
    recv.insert(Seq(11), b"b", false);
    assert_eq!(recv.reset_start(Seq(20)), Err(()));
    recv.insert(Seq(10), b"a", false);
    assert_eq!(recv.reset_start(Seq(20)), Err(()));
    assert_eq!(recv.read(&mut []), 0);
    assert_eq!(recv.read(&mut [0; 2]), 2);
    assert_eq!(recv.reset_start(Seq(20)), Ok(()));
    assert_eq!(recv.next(), Seq(20));
    recv.insert(Seq(21), b"", true);
    assert_eq!(recv.reset_start(Seq(30)), Err(()));

    let mut recv = Window::new(Seq(7), 1).unwrap();
    let result = recv.insert(Seq(7), b"", true);
    assert!(result.fin && result.advanced);
    assert!(!result.out_of_order);
    assert_eq!(recv.next(), Seq(8));
    assert_eq!(recv.read(&mut [0]), 0);
}

#[test]
fn push_marks_remain_bounded_across_gaps_overlaps_and_slot_reuse() {
    let mut recv = Window::new(Seq(u32::MAX - 1), 64).unwrap();
    for cycle in 0..3 {
        let start = recv.next();
        for offset in (1..64).step_by(2) {
            recv.insert_with_push(start.wrapping_add(offset), b"x", false, true);
            assert!(!recv.take_push());
        }
        for offset in (0..64).step_by(2) {
            recv.insert_with_push(start.wrapping_add(offset), b"y", false, false);
            assert!(recv.take_push());
        }
        assert!(!recv.take_push());
        assert_eq!(recv.read(&mut [0; 64]), 64);
        assert_eq!(recv.storage_less_spare(), 0, "cycle {cycle}");
    }
    let start = recv.next();
    recv.insert_with_push(start.wrapping_add(3), b"d", false, false);
    recv.insert_with_push(start.wrapping_add(2), b"cd", false, true);
    assert!(!recv.take_push()); // New c carries a mark ending on already queued d.
    recv.insert_with_push(start, b"ab", false, false);
    assert!(recv.take_push());
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.3
//= type=test
//# A TCP receiver MAY pass a received PSH bit to the application layer via
//# the PUSH flag in the interface (MAY-17), but it is not required
fn duplicate_out_of_order_text_can_introduce_push() {
    for start in [Seq(100), Seq(u32::MAX - 3)] {
        let mut recv = Window::new(start, 8).unwrap();
        recv.insert_with_push(start.wrapping_add(4), b"efgh", false, false);
        let duplicate = recv.insert_with_push(start.wrapping_add(4), b"efgh", false, true);
        assert_eq!(duplicate.new_bytes, 0);
        assert!(!recv.take_push());
        recv.insert_with_push(start, b"abcd", false, false);
        assert!(recv.take_push());
        assert!(!recv.take_push());
        recv.insert_with_push(start.wrapping_add(4), b"efgh", false, true);
        assert!(!recv.take_push()); // Already contiguous, even before read.
        let mut out = [0; 8];
        assert_eq!(recv.read(&mut out), 8);
        assert_eq!(&out, b"abcdefgh");
        recv.insert_with_push(start.wrapping_add(4), b"efgh", false, true);
        recv.insert_with_push(recv.next(), b"", false, true);
        assert!(!recv.take_push());
        assert_eq!(recv.storage_less_spare(), 0);
    }
}

#[test]
fn duplicate_push_ignores_trimmed_endpoints_and_preserves_fin_conflicts() {
    let mut recv = Window::new(Seq(100), 8).unwrap();
    recv.insert(Seq(104), b"efgh", false);
    recv.insert_with_push(Seq(104), b"efghi", false, true);
    recv.insert_with_push(Seq(106), b"", true, true); // FIN conflicts with gh.
    assert_eq!(recv.fin_sequence, None);
    recv.insert(Seq(100), b"abcd", false);
    assert!(!recv.take_push());
    assert_eq!(recv.read(&mut [0; 8]), 8);

    let mut recv = Window::new(Seq(100), 8).unwrap();
    recv.insert(Seq(104), b"ef", true); // Pending FIN at 106.
    recv.insert_with_push(Seq(104), b"efgh", false, true);
    assert_eq!(recv.fin_sequence, Some(Seq(106)));
    recv.insert(Seq(100), b"abcd", false);
    assert!(!recv.take_push()); // Endpoint beyond FIN was trimmed.
    assert!(recv.eof());
    assert_eq!(recv.read(&mut [0; 8]), 6);
}
