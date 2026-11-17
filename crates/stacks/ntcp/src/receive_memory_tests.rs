//! The receive memory rules (n0bw stage 1 C6), in Linux's order:
//! tcp_try_rmem_schedule -> tcp_prune_queue (tcp_clamp_window, collapse of
//! the out-of-order runs and the in-order frames, tcp_prune_ofo_queue) ->
//! the drop (PROTO_MEM), with the in-order exception
//! (sk_forced_mem_schedule) and the zero-window ACK (ICSK_ACK_NOMEM).
extern crate std;

use super::*;
use crate::{MemoryCounters, rx_queue::RX_ENTRY_TRUESIZE};
use ntcp_buffer::RxFrame;
use std::vec::Vec;

fn config(receive: usize, sack: bool) -> EndpointConfig {
    let mut config = EndpointConfig {
        max_connections: 4,
        max_listeners: 1,
        ..EndpointConfig::default()
    };
    config.connection.nagle = false;
    config.connection.sack = sack;
    config.connection.timestamps = false;
    config.connection.delayed_ack_us = 0;
    config.connection.receive_capacity = receive;
    config
}

type Packets = Vec<(IpMetadata, Vec<u8>)>;

fn flight(endpoint: &mut Endpoint, now: u64) -> Packets {
    let mut out = Vec::new();
    loop {
        let mut bytes = [0; 2048];
        let output = endpoint.poll_transmit(now, &mut bytes, 16).unwrap();
        if let Some(packet) = output.packet {
            out.push((packet.ip, bytes[..packet.len].to_vec()));
        }
        if !output.more_work {
            return out;
        }
    }
}

// An established pair, `b` receiving with a fixed `receive` buffer.
fn pair(receive: usize, sack: bool) -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let local: core::net::SocketAddr = "192.0.2.1:40000".parse().unwrap();
    let remote: core::net::SocketAddr = "192.0.2.2:8080".parse().unwrap();
    let mut a = Endpoint::new(config(1 << 20, sack), [1; 32], 0, |_| true).unwrap();
    let mut b = Endpoint::new(config(receive, sack), [2; 32], 0, |_| true).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    for _ in 0..4 {
        for (ip, bytes) in flight(&mut a, 0) {
            b.input(0, ip, &bytes).unwrap();
        }
        for (ip, bytes) in flight(&mut b, 0) {
            a.input(0, ip, &bytes).unwrap();
        }
    }
    let server = b.accept(listener).unwrap();
    (a, b, client, server)
}

// One data segment per write of `size` bytes.
fn segments(a: &mut Endpoint, client: ConnectionId, count: usize, size: usize) -> Packets {
    let mut out = Vec::new();
    for k in 0..count {
        a.write(client, &std::vec![k as u8; size]).unwrap();
        let sent = flight(a, 0);
        assert_eq!(sent.len(), 1);
        out.extend(sent);
    }
    out
}

fn rmem(b: &Endpoint, server: ConnectionId) -> usize {
    b.slot(server).unwrap().connection.receive_queue().rmem()
}

fn window(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[14], bytes[15]])
}

// The receive memory counters only.
fn counters(b: &Endpoint) -> MemoryCounters {
    let all = b.memory_counters();
    MemoryCounters {
        prune_called: all.prune_called,
        rcv_pruned: all.rcv_pruned,
        ofo_pruned: all.ofo_pruned,
        rcv_collapsed: all.rcv_collapsed,
        rcv_queue_drops: all.rcv_queue_drops,
        ofo_drops: all.ofo_drops,
        ..MemoryCounters::default()
    }
}

// 18-byte requests held in 2304 B frames (a DPDK element) are bloated:
// win_from_space(2304 + RX_ENTRY_TRUESIZE) is far above 18. Past the limit
// (twice the 8192 B window: no full-size segment has measured the ratio)
// the in-order frames are copied into one heap frame (tcp_collapse,
// TCPRcvCollapsed), which brings the queue within it, and nothing is
// dropped.
#[test]
fn collapse_copies_bloated_frames_within_the_limit() {
    let (mut a, mut b, client, server) = pair(8192, true);
    for (ip, bytes) in segments(&mut a, client, 8, 18) {
        let mut frame = Vec::with_capacity(2304);
        frame.extend_from_slice(&bytes);
        b.input_frame(
            0,
            ip,
            0,
            Ipv4Options::default(),
            RxFrame::from_vec(frame),
            crate::RxPacketMetadata::default(),
        )
        .unwrap();
        assert!(rmem(&b, server) <= 2 * 8192 + 2304 + RX_ENTRY_TRUESIZE);
    }
    // Seven frames fit (6 * 2496 <= 2 * 8192 < 7 * 2496); the eighth found the
    // queue past its limit and collapsed the seven into one 126 B frame.
    assert_eq!(
        counters(&b),
        MemoryCounters {
            prune_called: 1,
            rcv_collapsed: 7,
            ..MemoryCounters::default()
        }
    );
    assert_eq!(rmem(&b, server), 126 + 2304 + 2 * RX_ENTRY_TRUESIZE);
    let mut out = [0; 256];
    assert_eq!(b.read(server, &mut out), Ok(144));
    assert!((0..8).all(|k| out[18 * k..18 * (k + 1)].iter().all(|&x| x == k as u8)));
    assert_eq!(rmem(&b, server), 0);
    assert_eq!(b.drop_counts().total(), 0);
}

// One-byte out-of-order segments into a 2048 B window: 22 fit its 4096 B
// limit (twice the window before the ratio is measured; 21 * 193 <= 4096),
// the rest find it passed, cannot be collapsed (runs of one tiny
// frame) and would land last, so nothing is pruned for them and they are
// dropped (RcvPruned, TCPOFODrop, PROTO_MEM). The in-order byte that
// follows prunes from the top (tcp_prune_ofo_queue, 4096 / 8 = 512 B of
// truesize: three frames) and resets the SACK state, then is taken.
#[test]
//= https://www.rfc-editor.org/rfc/rfc2018#section-8
//= type=test
//= reason=Out-of-order frames reported in SACK blocks are dropped from the top past the limit (TCP_OFO_QUEUE_PRUNE, OfoPruned).
//# The data receiver MAY elect not to keep data which it has reported in a SACK
//# option.
//= https://www.rfc-editor.org/rfc/rfc2018#section-8
//= type=test
//= reason=The ACK after the prune reports no block above the highest frame still held.
//# * Except for the newest segment, all SACK blocks MUST NOT report any old
//# data which is no longer actually held by the receiver.
fn prune_drops_out_of_order_frames_from_the_top_and_resets_sack() {
    let (mut a, mut b, client, server) = pair(2048, true);
    let sent = segments(&mut a, client, 61, 1);
    for (ip, bytes) in sent.iter().skip(1).step_by(2) {
        b.input(0, *ip, bytes).unwrap();
        flight(&mut b, 0);
    }
    let dropped = 30 - 22;
    assert_eq!(
        counters(&b),
        MemoryCounters {
            prune_called: dropped,
            rcv_pruned: dropped,
            ofo_drops: dropped,
            ..MemoryCounters::default()
        }
    );
    assert_eq!(b.drop_counts()[DropReason::ProtoMem], dropped);
    assert_eq!(rmem(&b, server), 22 * (1 + RX_ENTRY_TRUESIZE));
    let (ip, bytes) = &sent[0];
    b.input(0, *ip, bytes).unwrap();
    assert_eq!(
        counters(&b),
        MemoryCounters {
            prune_called: dropped + 1,
            rcv_pruned: dropped,
            ofo_drops: dropped,
            ofo_pruned: 1,
            ..MemoryCounters::default()
        }
    );
    assert_eq!(b.drop_counts()[DropReason::TcpOfoQueuePrune], 3);
    // Bytes 0 and 1 are in order now; 19 out-of-order frames remain, the
    // highest at byte 37.
    assert_eq!(b.readable_bytes(server), Ok(2));
    let ack = flight(&mut b, 0);
    let segment = wire::parse(ack[0].0, &ack[0].1).unwrap();
    let highest = segment.header.acknowledgment.wrapping_add(36);
    for block in segment.options.sack_blocks.iter().flatten() {
        assert!(
            Seq(block.1).distance_from(Seq(segment.header.acknowledgment)) <= 36,
            "{block:?} above {highest}"
        );
    }
}

// An out-of-order segment below the highest held frame prunes from the top
// to make room and is taken; it is then the newest segment, and the ACK's
// first SACK block reports it (RFC 2018 sections 4 and 8), merged with its
// held neighbours: bytes 1 to 3.
#[test]
fn an_out_of_order_segment_taken_after_a_prune_is_the_first_sack_block() {
    let (mut a, mut b, client, server) = pair(2048, true);
    let sent = segments(&mut a, client, 45, 1);
    for (ip, bytes) in sent.iter().skip(1).step_by(2) {
        b.input(0, *ip, bytes).unwrap();
        flight(&mut b, 0);
    }
    assert_eq!(rmem(&b, server), 22 * (1 + RX_ENTRY_TRUESIZE));
    let (ip, bytes) = &sent[2];
    b.input(0, *ip, bytes).unwrap();
    assert_eq!(b.drop_counts()[DropReason::TcpOfoQueuePrune], 3);
    assert_eq!(b.drop_counts()[DropReason::ProtoMem], 0);
    assert_eq!(rmem(&b, server), 20 * (1 + RX_ENTRY_TRUESIZE));
    let ack = flight(&mut b, 0);
    let segment = wire::parse(ack[0].0, &ack[0].1).unwrap();
    let next = segment.header.acknowledgment;
    assert_eq!(
        segment.options.sack_blocks[0],
        Some((next.wrapping_add(1), next.wrapping_add(4)))
    );
}

// With the budget at its cap the queue has no room (sk_rmem_schedule
// fails): an in-order segment into an empty queue is still taken
// (sk_forced_mem_schedule), one into a queue holding unread data is dropped
// (TCPRcvQDrop, PROTO_MEM); each is answered at once by a segment offering
// a zero window, which moves no edge, and the next ACK offers the window
// again. A read returns the memory and the retransmission is taken.
#[test]
fn an_in_order_segment_is_forced_into_an_empty_queue_and_dropped_into_a_held_one() {
    let (mut a, mut b, client, server) = pair(65536, false);
    b.config.max_buffer_bytes = b.buffer_bytes();
    let sent = segments(&mut a, client, 2, 100);
    let edge = b.slot(server).unwrap().connection.receive_model_view();
    b.input(0, sent[0].0, &sent[0].1).unwrap();
    assert_eq!(b.readable_bytes(server), Ok(100));
    let nomem = flight(&mut b, 0);
    assert_eq!(nomem.len(), 1);
    assert_eq!(window(&nomem[0].1), 0);
    let view = b.slot(server).unwrap().connection.receive_model_view();
    assert_eq!(
        view.next.wrapping_add(view.window),
        edge.next.wrapping_add(edge.window),
        "the zero window moved no edge"
    );
    b.input(0, sent[1].0, &sent[1].1).unwrap();
    assert_eq!(b.readable_bytes(server), Ok(100));
    let nomem = flight(&mut b, 0);
    assert_eq!(window(&nomem[0].1), 0);
    assert_eq!(
        counters(&b),
        MemoryCounters {
            prune_called: 2,
            rcv_queue_drops: 1,
            ..MemoryCounters::default()
        }
    );
    assert_eq!(b.drop_counts()[DropReason::ProtoMem], 1);
    let mut out = [0; 200];
    assert_eq!(b.read(server, &mut out), Ok(100));
    let update = flight(&mut b, 0);
    assert!(update.iter().all(|(_, bytes)| window(bytes) != 0));
    b.input(0, sent[1].0, &sent[1].1).unwrap();
    assert_eq!(b.read(server, &mut out), Ok(100));
}

// A fresh 64 KiB window filled with 100 B segments while the application
// reads nothing: each held frame takes 100 + RX_ENTRY_TRUESIZE of receive
// memory, 191 KB for the whole window, so the window closes long before
// the peer has sent what it was promised, and the promise is kept. The
// limit starts at twice the window, as Linux's sk_rcvbuf starts at twice
// its window (TCP_DEFAULT_SCALING_RATIO): collapse brings the frames into
// 4 KiB copies within it and the whole promise is taken, with no drop and
// no zero-window ACK. A limit of the window alone could not hold even the
// collapsed copies (16 * (4096 + RX_ENTRY_TRUESIZE) > 65536).
#[test]
fn small_segments_filling_a_fresh_window_are_all_taken() {
    let (mut a, mut b, client, server) = pair(65535, false);
    let limit = b.slot(server).unwrap().connection.receive_limit();
    assert_eq!(limit, 2 * 65535);
    let promised = b
        .slot(server)
        .unwrap()
        .connection
        .receive_model_view()
        .window;
    let (mut written, mut sent) = (0, 0);
    loop {
        let size = 100.min(promised as usize - written);
        if size != 0 && a.write(client, &[(written / 100) as u8; 100][..size]) == Ok(size) {
            written += size;
        }
        let out = flight(&mut a, 0);
        if out.is_empty() {
            break;
        }
        for (ip, bytes) in out {
            let segment = wire::parse(ip, &bytes).unwrap();
            sent += segment.payload.len();
            b.input(0, ip, &bytes).unwrap();
        }
        let acks = flight(&mut b, 0);
        let view = b.slot(server).unwrap().connection.receive_model_view();
        for (ip, bytes) in acks {
            assert!(
                window(&bytes) != 0 || view.window == 0,
                "a zero window with {} bytes still promised",
                view.window
            );
            a.input(0, ip, &bytes).unwrap();
        }
    }
    assert_eq!(sent, promised as usize);
    assert_eq!(b.readable_bytes(server), Ok(sent));
    let counters = counters(&b);
    assert!(counters.rcv_collapsed > 0, "{counters:?}");
    assert_eq!(
        (
            counters.rcv_queue_drops,
            counters.ofo_drops,
            counters.rcv_pruned
        ),
        (0, 0, 0)
    );
    assert_eq!(b.drop_counts().total(), 0);
    assert!(rmem(&b, server) <= limit);
    let mut out = std::vec![0; sent + 1];
    assert_eq!(b.read(server, &mut out), Ok(sent));
    assert!(
        out[..sent]
            .chunks(100)
            .enumerate()
            .all(|(n, chunk)| chunk.iter().all(|&x| x == n as u8))
    );
}

// The limit is twice the window until an in-order segment of at least the
// receive MSS estimate sets the scaling ratio; then it follows that ratio
// (payload to frame truesize + RX_ENTRY_TRUESIZE), as the window does,
// which offered its ratio 1:1 until then. A small segment measures nothing.
#[test]
fn the_limit_follows_the_measured_ratio_after_a_full_size_segment() {
    let (mut a, mut b, client, server) = pair(65536, false);
    let limit = |b: &Endpoint| b.slot(server).unwrap().connection.receive_limit();
    assert_eq!(limit(&b), 2 * 65536);
    for (ip, bytes) in segments(&mut a, client, 1, 100) {
        b.input(0, ip, &bytes).unwrap();
    }
    assert_eq!(limit(&b), 2 * 65536);
    let mut frame = Vec::with_capacity(2304);
    let sent = segments(&mut a, client, 1, 1460);
    let segment = wire::parse(sent[0].0, &sent[0].1).unwrap();
    assert_eq!(segment.payload.len(), 1460);
    frame.extend_from_slice(&sent[0].1);
    b.input_frame(
        0,
        sent[0].0,
        0,
        Ipv4Options::default(),
        RxFrame::from_vec(frame),
        crate::RxPacketMetadata::default(),
    )
    .unwrap();
    assert_eq!(limit(&b), 65536 * (2304 + RX_ENTRY_TRUESIZE) / 1460);
}
