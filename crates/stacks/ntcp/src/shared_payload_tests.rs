use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn connected() -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 100);
    let server = b.accept(listener).unwrap();
    a.enable_output_reservations().unwrap();
    a.enable_shared_output(8).unwrap();
    (a, b, client, server)
}

fn loan(
    a: &mut Endpoint,
    id: ConnectionId,
    now: u64,
) -> (Transmit, TransmitAttempt, Vec<u8>, Vec<Payload>) {
    let mut header = vec![0xa5; 2048];
    let mut payload = Vec::with_capacity(8);
    let (out, token) = a
        .poll_reserved_transmit_shared_for(now, id, &mut header, &mut payload, 32)
        .unwrap();
    let packet = out.packet.unwrap();
    let n = packet.len - payload.iter().map(Payload::len).sum::<usize>();
    assert!(header[n..].iter().all(|&v| v == 0xa5));
    header.truncate(n);
    (packet, token.unwrap(), header, payload)
}
fn wire_bytes(header: &[u8], payload: &[Payload]) -> Vec<u8> {
    let mut bytes = header.to_vec();
    for p in payload {
        bytes.extend_from_slice(p.as_slice());
    }
    bytes
}

#[test]
fn shared_payload_ack_and_backend_release_are_independent() {
    let (mut a, mut b, client, server) = connected();
    let data: Vec<u8> = (0..130).map(|n| n as u8).collect();
    let pointer = data.as_ptr();
    let base = Payload::from_vec(data);
    let done = Arc::new(AtomicUsize::new(0));
    let state = done.clone();
    assert_eq!(
        a.write_shared(
            client,
            base.clone().with_release(move || {
                state.fetch_add(1, Ordering::SeqCst);
            }),
            false,
            false,
            None
        ),
        Ok(130)
    );
    let mut held = Vec::new();
    let mut total = 0;
    for now in 101..104 {
        let (packet, token, header, payload) = loan(&mut a, client, now);
        assert_eq!(payload[0].as_slice().as_ptr(), pointer.wrapping_add(total));
        let bytes = wire_bytes(&header, &payload);
        wire::parse(packet.ip, &bytes).unwrap();
        total += payload.iter().map(Payload::len).sum::<usize>();
        a.accept_transmit(now, token).unwrap();
        b.input(now, packet.ip, &bytes).unwrap();
        held.extend(payload);
    }
    assert_eq!(total, 130);
    b.on_timeout(210_104, 32).unwrap();
    deliver(&mut a, 210_104, packets(&mut b, 210_104));
    assert_eq!(a.acknowledged(client), Ok(130));
    assert_eq!(done.load(Ordering::SeqCst), 0);
    assert_eq!(b.read(server, &mut [0; 130]), Ok(130));
    drop(held);
    assert_eq!(done.load(Ordering::SeqCst), 1);
    assert_eq!(base.as_slice().as_ptr(), pointer);
}

#[test]
fn shared_payload_rto_reuses_original_storage_and_abort_waits_for_backend() {
    let (mut a, _, client, _) = connected();
    let done = Arc::new(AtomicUsize::new(0));
    let state = done.clone();
    let base = Payload::from_vec(vec![7; 64]);
    let pointer = base.as_slice().as_ptr();
    a.write_shared(
        client,
        base.with_release(move || {
            state.fetch_add(1, Ordering::SeqCst);
        }),
        false,
        false,
        None,
    )
    .unwrap();
    let (first, token, header, old_backend) = loan(&mut a, client, 101);
    a.accept_transmit(101, token).unwrap();
    let sequence = wire::parse(first.ip, &wire_bytes(&header, &old_backend))
        .unwrap()
        .header
        .sequence;
    let expiry = a.next_deadline().unwrap();
    a.on_timeout(expiry, 32).unwrap();
    let (retry, token, header, new_backend) = loan(&mut a, client, expiry);
    assert_eq!(new_backend[0].as_slice().as_ptr(), pointer);
    let bytes = wire_bytes(&header, &new_backend);
    assert_eq!(
        wire::parse(retry.ip, &bytes).unwrap().header.sequence,
        sequence
    );
    a.accept_transmit(expiry, token).unwrap();
    a.abort(client).unwrap();
    drop(old_backend);
    assert_eq!(done.load(Ordering::SeqCst), 0);
    drop(new_backend);
    assert_eq!(done.load(Ordering::SeqCst), 1);
}

#[test]
fn shared_ranges_can_be_copied_by_legacy_output_without_corruption() {
    let (mut a, mut b, client, server) = connected();
    a.write_shared(client, Payload::from_vec(vec![3; 11]), true, false, None)
        .unwrap();
    a.write(client, &[5; 13]).unwrap();
    a.write_shared(client, Payload::from_vec(vec![7; 17]), false, false, None)
        .unwrap();
    pump(&mut a, &mut b, 200);
    b.on_timeout(210_200, 32).unwrap();
    pump(&mut a, &mut b, 210_200);
    let mut result = [0; 41];
    assert_eq!(b.read(server, &mut result), Ok(41));
    assert_eq!(&result[..11], &[3; 11]);
    assert_eq!(&result[11..24], &[5; 13]);
    assert_eq!(&result[24..], &[7; 17]);
}

#[test]
fn shared_metadata_partial_ack_resize_and_fragment_limits_preserve_bytes() {
    use crate::buffer::SendBuffer;
    let mut buffer = SendBuffer::new(128).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let state = count.clone();
    let base = Payload::from_vec(vec![2; 13]);
    let leased = base.clone().with_release(move || {
        state.fetch_add(1, Ordering::SeqCst);
    });
    buffer.prepare_shared(&leased, 4096).unwrap();
    buffer.write_shared(leased);
    buffer.write(&[3; 7]);
    let next = Payload::from_vec(vec![4; 11]);
    buffer.prepare_shared(&next, 4096).unwrap();
    buffer.write_shared(next);
    buffer.mark_end_of_record();
    buffer.acknowledge(5).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 0);
    buffer.grow(256).unwrap();
    buffer.set_limit(256);
    let mut out = [0; 26];
    assert_eq!(buffer.copy(0, &mut out), 26);
    assert_eq!(&out[..8], &[2; 8]);
    assert_eq!(&out[8..15], &[3; 7]);
    assert_eq!(&out[15..], &[4; 11]);
    buffer.set_shared_output(Some(1));
    assert_eq!(buffer.copy(0, &mut out), 8);
    assert_eq!(buffer.copy(8, &mut out), 7);
    assert_eq!(buffer.copy(15, &mut out), 11);
    buffer.acknowledge(8).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    buffer.truncate(10);
    buffer.set_shared_output(None);
    assert_eq!(buffer.copy(0, &mut out), 10);
    assert_eq!(&out[..10], &[3, 3, 3, 3, 3, 3, 3, 4, 4, 4]);
}

#[test]
fn adjacent_shared_writes_coalesce_into_one_span() {
    let (mut a, mut b, client, server) = connected();
    let data: Vec<u8> = (0..64).collect();
    let pointer = data.as_ptr();
    let done = Arc::new(AtomicUsize::new(0));
    let state = done.clone();
    let lease = Payload::from_vec(data).with_release(move || {
        state.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(
        a.write_shared(client, lease.slice(0..1).unwrap(), true, false, None),
        Ok(1)
    );
    let charge = a.buffer_bytes();
    for n in 1..64 {
        assert_eq!(
            a.write_shared(client, lease.slice(n..n + 1).unwrap(), true, false, None),
            Ok(1)
        );
    }
    // 64 one-byte writes hold one span and one segment: neither the span
    // storage nor the ledgers grew.
    assert_eq!(a.buffer_bytes(), charge);
    drop(lease);
    // One reference carries the whole segment (MSS 64), where 64 spans
    // would have stopped it at the 8 references a packet may carry.
    let (packet, token, header, payload) = loan(&mut a, client, 101);
    assert_eq!(payload.len(), 1);
    assert_eq!(payload[0].as_slice().as_ptr(), pointer);
    assert_eq!(payload[0].len(), 64);
    let bytes = wire_bytes(&header, &payload);
    a.accept_transmit(101, token).unwrap();
    b.input(101, packet.ip, &bytes).unwrap();
    drop(payload);
    b.on_timeout(210_101, 32).unwrap();
    deliver(&mut a, 210_101, packets(&mut b, 210_101));
    assert_eq!(a.acknowledged(client), Ok(64));
    assert_eq!(done.load(Ordering::SeqCst), 1);
    let mut result = [0; 64];
    assert_eq!(b.read(server, &mut result), Ok(64));
    assert!(result.iter().copied().eq(0..64));
}

#[test]
fn shared_writes_join_only_contiguous_ranges_of_one_lease() {
    use crate::buffer::SendBuffer;
    let mut buffer = SendBuffer::new(128).unwrap();
    let base = Payload::from_vec((0..32).collect());
    let lease = base.clone().with_release(|| {});
    let write = |buffer: &mut SendBuffer, payload: Payload| {
        buffer.prepare_shared(&payload, 4096).unwrap();
        assert_eq!(buffer.write_shared(payload.clone()), payload.len());
    };
    write(&mut buffer, lease.slice(0..4).unwrap());
    write(&mut buffer, lease.slice(4..8).unwrap());
    assert_eq!(buffer.shared_spans(), 1);
    // Same storage, another lease (or none).
    write(&mut buffer, base.slice(8..12).unwrap());
    assert_eq!(buffer.shared_spans(), 2);
    // A gap in the storage.
    write(&mut buffer, base.slice(13..16).unwrap());
    assert_eq!(buffer.shared_spans(), 3);
    write(&mut buffer, base.slice(16..20).unwrap());
    assert_eq!(buffer.shared_spans(), 3);
    // Copied bytes between: the next range is contiguous in storage only.
    buffer.write(&[0xff; 2]);
    write(&mut buffer, base.slice(20..24).unwrap());
    assert_eq!(buffer.shared_spans(), 4);
    // A span cut by truncate continues from its new end.
    buffer.truncate(buffer.len() - 2);
    write(&mut buffer, base.slice(22..26).unwrap());
    assert_eq!(buffer.shared_spans(), 4);
    let mut out = [0; 27];
    assert_eq!(buffer.copy(0, &mut out), 27);
    let expected: Vec<u8> = (0..12)
        .chain(13..20)
        .chain([0xff, 0xff])
        .chain(20..26)
        .collect();
    assert_eq!(&out[..], &expected[..]);
    // Partial ACKs slice the joined front span.
    buffer.acknowledge(6).unwrap();
    buffer.set_shared_output(Some(1));
    assert_eq!(buffer.copy(0, &mut out), 2);
}

#[test]
fn separate_shared_spans_stop_at_iov_max() {
    let mut cfg = config();
    cfg.connection.send_capacity = 4096;
    cfg.connection.receive_capacity = 4096;
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 100);
    let server = b.accept(listener).unwrap();
    // A packet's reference limit does not bound the spans a connection holds.
    a.enable_output_reservations().unwrap();
    a.enable_shared_output(8).unwrap();
    let max = Endpoint::MAX_SHARED_SEGMENTS;
    let base = Payload::from_vec((0..2 * max + 4).map(|n| n as u8).collect());
    let one = |n: usize| base.slice(n..n + 1).unwrap();
    // Writes that do not continue one another each take a span.
    for n in 0..max {
        assert_eq!(a.write_shared(client, one(2 * n), true, false, None), Ok(1));
    }
    let charge = a.buffer_bytes();
    let refused = Err(EndpointError::Connection(Error::InvalidArgument));
    assert_eq!(
        a.write_shared(client, one(2 * max), true, false, None),
        refused
    );
    assert_eq!(
        a.write_shared(client, Payload::from_vec(vec![1]), true, false, None),
        refused
    );
    assert_eq!(a.buffer_bytes(), charge);
    // One continuing the last span joins it; copied bytes take no span.
    assert_eq!(
        a.write_shared(client, one(2 * max - 1), true, false, None),
        Ok(1)
    );
    assert_eq!(a.write(client, &[0xff]), Ok(1));
    assert_eq!(
        a.write_shared(client, one(2 * max), true, false, None),
        refused
    );
    // Spans freed by ACKs admit separate writes again.
    let mut now = 200;
    let mut expected: Vec<u8> = (0..max).map(|n| (2 * n) as u8).collect();
    expected.push((2 * max - 1) as u8);
    expected.push(0xff);
    while a.acknowledged(client) != Ok(expected.len() as u64) {
        assert!(now < 100_000_000, "transfer did not finish");
        pump(&mut a, &mut b, now);
        now += 210_000;
        a.on_timeout(now, 64).unwrap();
        b.on_timeout(now, 64).unwrap();
    }
    assert_eq!(
        a.write_shared(client, one(2 * max + 2), true, false, None),
        Ok(1)
    );
    expected.push((2 * max + 2) as u8);
    while a.acknowledged(client) != Ok(expected.len() as u64) {
        assert!(now < 200_000_000, "transfer did not finish");
        pump(&mut a, &mut b, now);
        now += 210_000;
        a.on_timeout(now, 64).unwrap();
        b.on_timeout(now, 64).unwrap();
    }
    let mut result = vec![0; expected.len()];
    assert_eq!(b.read(server, &mut result), Ok(expected.len()));
    assert_eq!(result, expected);
    assert_eq!(
        a.enable_shared_output(max + 1),
        Err(EndpointError::Connection(Error::InvalidArgument))
    );
    assert_eq!(a.enable_shared_output(max), Ok(()));
}
