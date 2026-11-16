//! Endpoint::input_frame against the copying input: the same traces, the
//! frame itself held in place of a copy, and no frame released while the
//! input that brought it still borrows its bytes.
extern crate std;

use super::*;
use crate::rx_queue::{ReceiveOutcome, RxPayload, RxQueue};
use ntcp_buffer::RxFrameVtable;
use std::{
    boxed::Box,
    cell::{Cell, RefCell},
    vec::Vec,
};

std::thread_local! {
    // Frames built here and not yet released.
    static LIVE: Cell<isize> = const { Cell::new(0) };
    // Released frames' memory, poisoned and kept allocated: an input that
    // read a frame after its release would read the poison (and its trace
    // would differ from the copying input's) rather than freed memory.
    static RELEASED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

static COUNTED: RxFrameVtable = RxFrameVtable { release };

// SAFETY (caller): context is a Box<Vec<u8>> given up by `frame`.
unsafe fn release(context: *mut (), _token: usize) {
    let mut bytes = unsafe { Box::from_raw(context.cast::<Vec<u8>>()) };
    bytes.fill(0xa5);
    RELEASED.with_borrow_mut(|released| released.push(*bytes));
    LIVE.set(LIVE.get() - 1);
}

// A heap frame of `bytes` with `spare` bytes of unused capacity, counted in
// LIVE until released.
fn frame(bytes: &[u8], spare: usize) -> RxFrame {
    let mut vec = Vec::with_capacity(bytes.len() + spare);
    vec.extend_from_slice(bytes);
    let (data, len, truesize) = (vec.as_ptr(), vec.len(), vec.capacity());
    LIVE.set(LIVE.get() + 1);
    let context = Box::into_raw(Box::new(vec));
    // SAFETY: the Vec's bytes are initialized and stay where they are until
    // `release` drops the box holding it, once.
    unsafe {
        RxFrame::from_raw_parts(
            core::ptr::NonNull::new(data.cast_mut()).unwrap(),
            len as u32,
            truesize as u32,
            &COUNTED,
            context.cast(),
            0,
        )
    }
}

// A heap frame of `bytes` with `spare` bytes of unused capacity, freed when
// released.
fn heap(bytes: &[u8], spare: usize) -> RxFrame {
    let mut vec = Vec::with_capacity(bytes.len() + spare);
    vec.extend_from_slice(bytes);
    RxFrame::from_vec(vec)
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Copy,
    // Frames with this much spare capacity (a DPDK element's 2304 B).
    Frame(usize),
    // Heap frames (`heap`) with this much spare capacity, whose release
    // frees their memory: under Miri, an input that read its frame after
    // its release is a use after free.
    Heap(usize),
}

fn input(
    endpoint: &mut Endpoint,
    mode: Mode,
    now: u64,
    ip: IpMetadata,
    bytes: &[u8],
) -> Result<InputDisposition, EndpointError> {
    match mode {
        Mode::Copy => endpoint.input(now, ip, bytes),
        Mode::Frame(spare) => endpoint.input_frame(
            now,
            ip,
            0,
            Ipv4Options::default(),
            frame(bytes, spare),
            crate::RxPacketMetadata::default(),
        ),
        Mode::Heap(spare) => endpoint.input_frame(
            now,
            ip,
            0,
            Ipv4Options::default(),
            heap(bytes, spare),
            crate::RxPacketMetadata::default(),
        ),
    }
}

fn addresses() -> (core::net::SocketAddr, core::net::SocketAddr) {
    (
        "192.0.2.1:40000".parse().unwrap(),
        "192.0.2.2:8080".parse().unwrap(),
    )
}

fn endpoints() -> (Endpoint, Endpoint, ListenerId, ConnectionId) {
    let config = EndpointConfig {
        max_connections: 8,
        max_listeners: 2,
        connection: ConnectionConfig {
            mss: 64,
            send_capacity: 1024,
            receive_capacity: 1024,
            nagle: false,
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    };
    let (local, remote) = addresses();
    let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
    let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    (a, b, listener, client)
}

fn packets(endpoint: &mut Endpoint, now: u64) -> Vec<(IpMetadata, Vec<u8>)> {
    let mut result = Vec::new();
    for _ in 0..256 {
        let mut bytes = [0; 2048];
        let output = endpoint.poll_transmit(now, &mut bytes, 16).unwrap();
        if let Some(packet) = output.packet {
            result.push((packet.ip, bytes[..packet.len].to_vec()));
        }
        if !output.more_work {
            return result;
        }
    }
    panic!("endpoint failed to quiesce");
}

fn pump(a: &mut Endpoint, b: &mut Endpoint, mode: Mode, now: u64) {
    for _ in 0..128 {
        let ab = packets(a, now);
        let ba = packets(b, now);
        if ab.is_empty() && ba.is_empty() {
            return;
        }
        for (ip, bytes) in ab {
            input(b, mode, now, ip, &bytes).unwrap();
        }
        for (ip, bytes) in ba {
            input(a, mode, now, ip, &bytes).unwrap();
        }
    }
    panic!("unexpected infinite packet exchange");
}

#[derive(Debug, PartialEq)]
enum Step {
    Packet(bool, u64, Vec<u8>),
    Input(Result<InputDisposition, EndpointError>),
    Read(bool, Vec<u8>),
    State(Result<State, EndpointError>, Result<State, EndpointError>),
    Done(bool),
}

// A duplex transfer through a network that loses, delays, duplicates,
// reorders and corrupts segments, both sides writing, reading at random and
// closing: every packet sent, input disposition and byte read, in order.
fn faulty_duplex(trial: u64, mode: Mode) -> Vec<Step> {
    fn random(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *seed >> 17
    }
    let mut trace = Vec::new();
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, mode, 0);
    let server = b.accept(listener).unwrap();
    a.set_user_timeout(client, 1_000_000_000).unwrap();
    b.set_user_timeout(server, 1_000_000_000).unwrap();
    let a_data: Vec<u8> = (0..4096).map(|i| ((i * 7 + trial) % 251) as u8).collect();
    let b_data: Vec<u8> = (0..3072).map(|i| ((i * 13 + trial) % 253) as u8).collect();
    let (mut a_sent, mut b_sent, mut a_read, mut b_read) = (0, 0, 0, 0);
    let (mut a_closed, mut b_closed) = (false, false);
    let mut seed = trial;
    let mut network: Vec<(u64, bool, IpMetadata, Vec<u8>)> = Vec::new();
    // Eventual delivery: losses can drive the backoff to 60 s.
    for step in 1..=100_000 {
        let now = step * 10_000;
        a.on_timeout(now, 32).unwrap();
        b.on_timeout(now, 32).unwrap();
        for (endpoint, id, source, sent, closed) in [
            (&mut a, client, &a_data, &mut a_sent, &mut a_closed),
            (&mut b, server, &b_data, &mut b_sent, &mut b_closed),
        ] {
            if *sent < source.len() {
                let end = source
                    .len()
                    .min(*sent + 1 + (random(&mut seed) % 197) as usize);
                match endpoint.write(id, &source[*sent..end]) {
                    Ok(n) => *sent += n,
                    Err(EndpointError::Connection(Error::WouldBlock)) => {}
                    other => panic!("write failed: {other:?}"),
                }
            }
            if *sent == source.len() && !*closed {
                endpoint.shutdown(id).unwrap();
                *closed = true;
            }
        }
        for (endpoint, to_b) in [(&mut a, true), (&mut b, false)] {
            for (ip, mut bytes) in packets(endpoint, now) {
                trace.push(Step::Packet(to_b, now, bytes.clone()));
                let choice = random(&mut seed);
                if choice.is_multiple_of(8) || network.len() >= 128 {
                    continue;
                }
                if choice.is_multiple_of(17) {
                    let end = bytes.len() - 1;
                    bytes[end] ^= 0x80;
                }
                let at = now + (random(&mut seed) % 7) * 10_000;
                if choice.is_multiple_of(9) {
                    network.push((at + 20_000, to_b, ip, bytes.clone()));
                }
                network.push((at, to_b, ip, bytes));
            }
        }
        let mut index = 0;
        while index < network.len() {
            if network[index].0 <= now {
                let (_, to_b, ip, bytes) = network.swap_remove(index);
                let target = if to_b { &mut b } else { &mut a };
                trace.push(Step::Input(input(target, mode, now, ip, &bytes)));
            } else {
                index += 1;
            }
        }
        for (endpoint, id, read, a_side) in [
            (&mut a, client, &mut a_read, true),
            (&mut b, server, &mut b_read, false),
        ] {
            if random(&mut seed).is_multiple_of(4) {
                continue;
            }
            let mut out = [0; 113];
            while let Ok(n) = endpoint.read(id, &mut out) {
                trace.push(Step::Read(a_side, out[..n].to_vec()));
                *read += n;
                if n == 0 {
                    break;
                }
            }
        }
        trace.push(Step::State(a.state(client), b.state(server)));
        if a_read == b_data.len()
            && b_read == a_data.len()
            && a.acknowledged(client).unwrap() == a_data.len() as u64
            && b.acknowledged(server).unwrap() == b_data.len() as u64
        {
            break;
        }
    }
    trace.push(Step::Done(a_read == b_data.len() && b_read == a_data.len()));
    trace
}

// The frame and the copying input paths give the same traces (the window
// rule counts bytes, not truesize), and every frame is released by the
// time its endpoint is dropped.
#[test]
fn frame_and_copy_inputs_give_identical_traces() {
    for trial in 1..=4 {
        let copy = faulty_duplex(trial, Mode::Copy);
        assert_eq!(copy.last(), Some(&Step::Done(true)));
        for spare in [0, 2304 - 64 - 52] {
            let framed = faulty_duplex(trial, Mode::Frame(spare));
            assert_eq!(LIVE.get(), 0, "trial {trial}: frames leaked");
            for (at, (x, y)) in copy.iter().zip(&framed).enumerate() {
                assert_eq!(x, y, "trial {trial} spare {spare}: step {at}");
            }
            assert_eq!(framed.len(), copy.len(), "trial {trial} spare {spare}");
        }
    }
}

fn established(mode: Mode) -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, mode, 0);
    let server = b.accept(listener).unwrap();
    (a, b, client, server)
}

fn held(b: &Endpoint, server: ConnectionId) -> usize {
    b.slot(server).unwrap().connection.receive_queue().storage()
}

// The payload a connection accepts is the frame itself, trimmed: held at
// its truesize until read to its end; a duplicate is dropped once its
// input returns.
#[test]
fn accepted_payload_is_the_frame_held_until_read() {
    let mode = Mode::Frame(2000);
    let (mut a, mut b, client, server) = established(mode);
    assert_eq!(LIVE.get(), 0);
    a.write(client, &[5; 100]).unwrap();
    let data = packets(&mut a, 0);
    assert_eq!(data.len(), 2);
    let truesize = |packet: &(IpMetadata, Vec<u8>)| packet.1.len() + 2000;
    // Out of order first, then the gap.
    input(&mut b, mode, 0, data[1].0, &data[1].1).unwrap();
    assert_eq!(LIVE.get(), 1);
    let ofo = held(&b, server);
    assert!(ofo >= truesize(&data[1]), "{ofo}");
    // A duplicate takes nothing.
    input(&mut b, mode, 0, data[1].0, &data[1].1).unwrap();
    assert_eq!((LIVE.get(), held(&b, server)), (1, ofo));
    input(&mut b, mode, 0, data[0].0, &data[0].1).unwrap();
    assert_eq!(LIVE.get(), 2);
    // The two frames, and the in-order deque's few slots.
    let frames = truesize(&data[0]) + truesize(&data[1]);
    let both = held(&b, server);
    assert!(
        both >= frames + 2 * size_of::<RxFrame>() && both <= frames + 16 * size_of::<RxFrame>(),
        "{both} {frames}"
    );
    let mut out = [0; 100];
    assert_eq!(b.read(server, &mut out[..63]).unwrap(), 63);
    assert_eq!(LIVE.get(), 2, "a partly read frame stays held");
    assert_eq!(b.read(server, &mut out[63..]).unwrap(), 37);
    assert_eq!(out, [5; 100]);
    assert_eq!((LIVE.get(), held(&b, server)), (0, 0));

    drop((a, b));
    assert_eq!(LIVE.get(), 0);
}

// A frame taken and then let go in the same input (new text after the
// reader closed aborts the connection and clears its queue) outlives that
// input, which still reads its header for the reset: the reset is the
// copying input's.
#[test]
fn a_frame_cleared_by_its_own_input_outlives_it() {
    let mut resets = Vec::new();
    for mode in [Mode::Copy, Mode::Frame(512), Mode::Heap(512)] {
        let (mut a, mut b, client, server) = established(mode);
        b.close(server).unwrap();
        pump(&mut a, &mut b, mode, 0);
        a.write(client, b"late").unwrap();
        let data = packets(&mut a, 0);
        assert_eq!(data.len(), 1);
        input(&mut b, mode, 0, data[0].0, &data[0].1).unwrap();
        assert_eq!(LIVE.get(), 0);
        assert_eq!(
            b.close_reason(server).unwrap(),
            Some(crate::CloseReason::Aborted)
        );
        assert_eq!(b.drop_counts()[DropReason::TcpAbortOnData], 1);
        resets.push(packets(&mut b, 0));
    }
    assert_eq!(resets[0].len(), 1);
    assert_eq!(resets[0], resets[1]);
    assert_eq!(resets[0], resets[2]);
}

// The paths on which the lent frame goes back to the Endpoint, with heap
// frames, whose release frees their memory: under Miri, a read of a lent
// frame after its release is a use after free.

// White box, for a defensive path: Endpoint::reclaim of the connection a
// frame is lent to, inside the input, takes the lent frame back
// (end_lend(true)). Here refresh reclaims a failed child (an unaccepted
// SYN-RECEIVED connection the peer's reset closes) whose output is drained.
// Through the public API no input reaches a reclaim (closed_output_drained
// is set only on a CLOSED connection, which refresh unmaps, and TIME-WAIT
// entry always leaves an ACK to send), so the child's flag is set directly
// before the reset arrives.
#[test]
fn a_frame_lent_to_a_connection_reclaimed_by_its_input_outlives_it() {
    for mode in [Mode::Copy, Mode::Heap(64)] {
        let (mut a, mut b, _listener, client) = endpoints();
        let syn = packets(&mut a, 0);
        input(&mut b, mode, 0, syn[0].0, &syn[0].1).unwrap();
        let synack = packets(&mut b, 0);
        input(&mut a, mode, 0, synack[0].0, &synack[0].1).unwrap();
        a.abort(client).unwrap();
        let reset = packets(&mut a, 0)
            .into_iter()
            .find(|(_, bytes)| bytes[13] & 0x04 != 0)
            .unwrap();
        let child = b.slots.iter().position(Option::is_some).unwrap();
        let slot = b.slots[child].as_mut().unwrap();
        assert_eq!(slot.connection.state(), State::SynReceived);
        slot.closed_output_drained = true;
        let reclaimed = b.reclaimed();
        input(&mut b, mode, 0, reset.0, &reset.1).unwrap();
        assert_eq!(b.reclaimed(), reclaimed + 1, "{mode:?}");
        assert!(b.slots[child].is_none());
        assert!(b.ingress.is_none() && b.lent.is_none());
    }
}

// A segment whose bytes the slice borrows from `frame`, as input_frame
// makes it: the queue builds its held frame from the lent one.
fn lent(queue: &mut RxQueue, frame: RxFrame) -> &'static [u8] {
    // SAFETY (test): every caller keeps the frame alive, lent or given
    // back, until its last use of the slice.
    let bytes = unsafe { core::slice::from_raw_parts(frame.as_ptr(), frame.len()) };
    queue.lend(frame);
    bytes
}

// `queue.insert` of `payload` at `seq`, within a 4096 B window.
fn insert(queue: &mut RxQueue, seq: u32, payload: RxPayload<'_>) -> ReceiveOutcome {
    queue.insert(Seq(seq), payload, false, false, Seq(4096), |_, _| {})
}

// The lent frame taken for in-order data whose deque slot is then refused
// goes back to the lend, as does the one taken for data that fills the gap
// before held out-of-order data when the slots its promotion needs are
// refused: both outlive the insertion, and the queue is as it was.
#[test]
fn a_lent_frame_refused_a_deque_slot_goes_back_to_the_lend() {
    let mut queue = RxQueue::new(Seq(0));
    let bytes = lent(&mut queue, heap(&[1; 40], 100));
    let outcome = crate::allocation_tests::fail_after(0, || {
        insert(&mut queue, 0, RxPayload::Borrowed(&bytes[20..]))
    });
    assert!(outcome.refused);
    assert_eq!(queue.readable(), 0);
    assert_eq!(bytes, &[1; 40]);
    let frame = queue.end_lend().expect("given back");
    assert_eq!((frame.len(), frame.truesize()), (20, 140));
    drop(frame);

    // Out of order, then the gap: the promotion needs two deque slots.
    let outcome = insert(&mut queue, 20, RxPayload::Borrowed(&[3; 20]));
    assert_eq!(outcome.new_bytes, 20);
    let bytes = lent(&mut queue, heap(&[2; 40], 100));
    let outcome = crate::allocation_tests::fail_after(0, || {
        insert(&mut queue, 0, RxPayload::Borrowed(&bytes[20..]))
    });
    assert!(outcome.refused);
    assert_eq!(queue.readable(), 0);
    assert_eq!(bytes, &[2; 40]);
    let frame = queue.end_lend().expect("given back");
    assert_eq!(frame.len(), 20);
    drop(frame);
    // And without the refusal both are held: the lent frame is the queue's.
    let bytes = lent(&mut queue, heap(&[2; 40], 100));
    let outcome = insert(&mut queue, 0, RxPayload::Borrowed(&bytes[20..]));
    assert_eq!(outcome.new_bytes, 20);
    assert!(queue.end_lend().is_none());
    let mut out = [0; 64];
    assert_eq!(queue.read(&mut out), 40);
    assert_eq!(&out[..40], [[2; 20], [3; 20]].concat());
}

// Endpoint::reclaim of the connection a frame is lent to clears its queue
// first (Connection::end_lend(true)): a frame it took, held in order, out
// of order or as deferred SYN data, goes back to the lend and outlives the
// clear, while the queue's other frames are dropped.
#[test]
fn a_taken_frame_cleared_before_the_lend_ends_goes_back() {
    for case in 0..3 {
        let mut queue = RxQueue::new(Seq(0));
        if case != 2 {
            insert(&mut queue, 100, RxPayload::Owned(heap(&[9; 10], 0)));
        }
        let bytes = lent(&mut queue, heap(&[case as u8; 60], 2000));
        match case {
            0 => {
                let outcome = insert(&mut queue, 0, RxPayload::Borrowed(&bytes[20..]));
                assert_eq!(outcome.new_bytes, 40);
            }
            1 => {
                let outcome = insert(&mut queue, 50, RxPayload::Borrowed(&bytes[20..]));
                assert_eq!(outcome.new_bytes, 40);
            }
            _ => {
                let frame = queue.frame_of(&bytes[20..]).unwrap();
                queue.defer_syn(frame, false, false).unwrap();
            }
        }
        queue.clear();
        assert_eq!((queue.rmem(), queue.readable()), (0, 0));
        assert_eq!(bytes, &[case as u8; 60][..]);
        let frame = queue.end_lend().expect("given back");
        assert_eq!(
            (frame.len(), frame.truesize(), frame[0]),
            (40, 2060, case as u8)
        );
        assert_eq!(bytes, &[case as u8; 60][..]);
        drop(frame);
    }
}

// A SYN-ACK carrying data to an active opener (no Fast Open): learn_syn
// takes the lent frame for the SYN data (frame_of) and defers it
// (defer_syn), whose deque slot can be refused; the refused frame must go
// back to the lend and outlive the input. Each allocation of that input is
// refused in turn (`fail`); some refusal must reach defer_syn (ProtoMem:
// frame_of allocates nothing for a lent frame).
#[test]
fn syn_ack_data_refused_a_deque_slot_outlives_its_input() {
    let mut refusals = 0;
    for fail in 0..24 {
        let (mut a, mut b, _listener, _client) = endpoints();
        let syn = packets(&mut a, 0);
        assert_eq!(syn.len(), 1);
        b.input(0, syn[0].0, &syn[0].1).unwrap();
        let synack = packets(&mut b, 0);
        assert_eq!(synack.len(), 1);
        let (ip, mut bytes) = synack[0].clone();
        bytes.extend_from_slice(b"syn-ack data");
        bytes[16..18].fill(0);
        let sum = crate::wire::checksum(ip, &bytes).unwrap();
        bytes[16..18].copy_from_slice(&sum.to_be_bytes());
        let frame = heap(&bytes, 64);
        let _ = crate::allocation_tests::fail_after(fail, || {
            a.input_frame(
                0,
                ip,
                0,
                Ipv4Options::default(),
                frame,
                crate::RxPacketMetadata::default(),
            )
        });
        if a.drop_counts()[DropReason::ProtoMem] != 0 {
            refusals += 1;
        }
    }
    assert!(refusals != 0, "no allocation refusal reached defer_syn");
}
