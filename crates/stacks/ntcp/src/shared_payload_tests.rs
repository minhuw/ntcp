use super::*;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

fn connected() -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 100);
    let server = b.accept(listener).unwrap();
    a.enable_output_reservations().unwrap();
    a.enable_shared_output(8).unwrap();
    (a, b, client, server)
}

fn loan(a: &mut Endpoint, id: ConnectionId, now: u64) -> (Transmit, TransmitAttempt, Vec<u8>, Vec<Payload>) {
    let mut header = vec![0xa5; 2048];
    let mut payload = Vec::with_capacity(8);
    let (out, token) = a.poll_reserved_transmit_shared_for(now, id, &mut header, &mut payload, 32).unwrap();
    let packet = out.packet.unwrap();
    let n = packet.len - payload.iter().map(Payload::len).sum::<usize>();
    assert!(header[n..].iter().all(|&v| v == 0xa5));
    header.truncate(n);
    (packet, token.unwrap(), header, payload)
}
fn wire_bytes(header: &[u8], payload: &[Payload]) -> Vec<u8> {
    let mut bytes = header.to_vec();
    for p in payload { bytes.extend_from_slice(p.as_slice()); }
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
    assert_eq!(a.write_shared(client, base.clone().with_release(move || { state.fetch_add(1, Ordering::SeqCst); }), false, false, None), Ok(130));
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
    a.write_shared(client, base.with_release(move || { state.fetch_add(1, Ordering::SeqCst); }), false, false, None).unwrap();
    let (first, token, header, old_backend) = loan(&mut a, client, 101);
    a.accept_transmit(101, token).unwrap();
    let sequence = wire::parse(first.ip, &wire_bytes(&header, &old_backend)).unwrap().header.sequence;
    let expiry = a.next_deadline().unwrap();
    a.on_timeout(expiry, 32).unwrap();
    let (retry, token, header, new_backend) = loan(&mut a, client, expiry);
    assert_eq!(new_backend[0].as_slice().as_ptr(), pointer);
    let bytes = wire_bytes(&header, &new_backend);
    assert_eq!(wire::parse(retry.ip, &bytes).unwrap().header.sequence, sequence);
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
    a.write_shared(client, Payload::from_vec(vec![3; 11]), true, false, None).unwrap();
    a.write(client, &[5; 13]).unwrap();
    a.write_shared(client, Payload::from_vec(vec![7; 17]), false, false, None).unwrap();
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
    buffer.prepare_shared(4096).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let state = count.clone();
    let base = Payload::from_vec(vec![2; 13]);
    buffer.write_shared(base.clone().with_release(move || { state.fetch_add(1, Ordering::SeqCst); }));
    buffer.write(&[3; 7]);
    buffer.prepare_shared(4096).unwrap();
    buffer.write_shared(Payload::from_vec(vec![4; 11]));
    buffer.mark_end_of_record();
    buffer.acknowledge(5).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 0);
    buffer = buffer.resized(256).unwrap();
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
    assert_eq!(&out[..10], &[3,3,3,3,3,3,3,4,4,4]);
}
