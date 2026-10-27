use super::*;
use crate::{RxTimestamp, TimestampClock};

fn stamps(value: u64) -> RxPacketTimestamps {
    RxPacketTimestamps {
        software: Some(RxTimestamp {
            value,
            clock: TimestampClock::RealtimeNanoseconds,
        }),
        hardware: Some(RxTimestamp {
            value: value + 100,
            clock: TimestampClock::DeviceTicks {
                identity: 3,
                units_per_second: None,
            },
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn input_rx(
    to: &mut Connection,
    now: u64,
    seq: Seq,
    ack: Seq,
    flags: u8,
    ts: Option<u32>,
    payload: &[u8],
    stamps: RxPacketTimestamps,
) {
    let metadata = ip(reverse(to.tuple()));
    let mut options = vec![];
    if let Some(ts) = ts {
        options.extend_from_slice(&[1, 1, 8, 10]);
        options.extend_from_slice(&ts.to_be_bytes());
        options.extend_from_slice(&0u32.to_be_bytes());
    }
    let mut bytes = vec![0; 20 + options.len() + payload.len()];
    let size = wire::encode(
        metadata,
        Header {
            source_port: to.tuple.remote.port(),
            destination_port: to.tuple.local.port(),
            sequence: seq.0,
            acknowledgment: ack.0,
            flags,
            window: 64,
            urgent_pointer: 0,
        },
        &options,
        payload,
        &mut bytes,
    )
    .unwrap();
    let segment = wire::parse(metadata, &bytes[..size]).unwrap();
    crate::allocation_tests::fail_after(0, || to.input_with_timestamps(now, 0, &segment, stamps))
        .unwrap();
}

#[test]
fn rx_timestamp_overlap_first_acceptance_partial_peek_wrap_fin_and_retry() {
    for iss in [100, u32::MAX - 3] {
        let (_, mut b) = pair(config(16, 8), iss);
        b.rx_timestamps.resize(8, usize::MAX).unwrap();
        let base = b.receive.next();
        let ack = b.snd_nxt;
        input_rx(
            &mut b,
            40,
            base.wrapping_add(4),
            ack,
            ACK,
            None,
            b"EFGH",
            stamps(2),
        );
        assert_eq!(b.peek_rx_timestamps(1), Err(Error::InvalidArgument));
        input_rx(
            &mut b,
            41,
            base.wrapping_add(2),
            ack,
            ACK,
            None,
            b"cdzz",
            stamps(3),
        );
        input_rx(&mut b, 42, base, ack, ACK, None, b"ab??????ij", stamps(1));
        let status = b.rx_timestamps.status();
        input_rx(&mut b, 43, base, ack, ACK, None, b"XXXXXXXXXX", stamps(9));
        assert_eq!(b.rx_timestamps.status(), status);
        let expected = [1, 1, 3, 3, 2, 2, 2, 2, 1, 1];
        for count in 1..=10 {
            let info = b.peek_rx_timestamps(count).unwrap().unwrap();
            assert_eq!(
                (info.start, info.end, info.timestamps),
                (0, count as u64, stamps(expected[count - 1]))
            );
        }
        assert_eq!(b.transmit(43, &mut []), Err(Error::OutputTooSmall));
        assert_eq!(b.peek(&mut []), Err(Error::InvalidArgument));
        assert_eq!(b.rx_timestamps.status(), status);
        let mut out = [0; 10];
        for _ in 0..2 {
            // Simulate failed staged copyout: no consumption.
            assert_eq!(b.peek(&mut out), Ok(10));
            assert_eq!(&out, b"abcdEFGHij");
            assert_eq!(
                b.peek_rx_timestamps(10).unwrap().unwrap().timestamps,
                stamps(1)
            );
        }
        assert_eq!(b.read(&mut out[..3]), Ok(3));
        let info = b.peek_rx_timestamps(5).unwrap().unwrap();
        assert_eq!((info.start, info.end, info.timestamps), (3, 8, stamps(2)));
        // Both buffer grow and logical shrink preserve retained OOO/contiguous provenance.
        b.set_buffer_capacities(16, 32, usize::MAX).unwrap();
        b.set_buffer_capacities(16, 4, usize::MAX).unwrap();
        assert_eq!(b.peek_rx_timestamps(5).unwrap(), Some(info));
        assert_eq!(b.read(&mut out), Ok(7));
        assert_eq!(&out[..7], b"dEFGHij");
        assert_eq!(b.rx_timestamps.status().retained_ranges, 0);
        input_rx(
            &mut b,
            44,
            base.wrapping_add(10),
            ack,
            ACK,
            None,
            b"kl",
            RxPacketTimestamps::default(),
        );
        input_rx(
            &mut b,
            45,
            base.wrapping_add(10),
            ack,
            ACK,
            None,
            b"ZZ",
            stamps(8),
        );
        assert_eq!(
            b.peek_rx_timestamps(2).unwrap().unwrap().timestamps,
            RxPacketTimestamps::default()
        );
        assert_eq!(b.read(&mut out), Ok(2));
        input_rx(
            &mut b,
            46,
            base.wrapping_add(12),
            ack,
            ACK | FIN,
            None,
            b"",
            stamps(7),
        );
        assert_eq!(b.read(&mut out), Ok(0));
        assert_eq!(b.peek_rx_timestamps(0), Ok(None));
        assert_eq!(b.peek_rx_timestamps(1), Err(Error::InvalidArgument));
        assert_eq!(b.rx_timestamps.status().retained_ranges, 0);
    }
}

#[test]
fn rx_timestamp_capacity_loss_never_repairs_duplicates_or_blocks_data() {
    let (_, mut b) = pair(config(16, 8), u32::MAX - 3);
    b.rx_timestamps.resize(1, usize::MAX).unwrap();
    let base = b.receive.next();
    let ack = b.snd_nxt;
    input_rx(
        &mut b,
        40,
        base.wrapping_add(4),
        ack,
        ACK,
        None,
        b"ef",
        stamps(1),
    );
    input_rx(&mut b, 41, base, ack, ACK, None, b"abcd", stamps(2));
    assert_eq!(b.rx_timestamps.status().lost_bytes, 4);
    assert_eq!(
        b.peek_rx_timestamps(4).unwrap().unwrap().timestamps,
        RxPacketTimestamps::default()
    );
    assert_eq!(
        b.peek_rx_timestamps(6).unwrap().unwrap().timestamps,
        stamps(1)
    );
    input_rx(&mut b, 42, base, ack, ACK, None, b"abcd", stamps(3));
    assert_eq!(b.rx_timestamps.status().lost_bytes, 4);
    assert_eq!(
        b.peek_rx_timestamps(4).unwrap().unwrap().timestamps,
        RxPacketTimestamps::default()
    );
    let mut out = [0; 8];
    assert_eq!(b.read(&mut out), Ok(6));
    assert_eq!(&out[..6], b"abcdef");
    input_rx(
        &mut b,
        43,
        base.wrapping_add(6),
        ack,
        ACK,
        None,
        b"gh",
        stamps(2),
    );
    input_rx(
        &mut b,
        44,
        base.wrapping_add(8),
        ack,
        ACK,
        None,
        b"ij",
        stamps(2),
    );
    assert_eq!(b.rx_timestamps.status().retained_ranges, 1); // Adjacent equal runs merge at capacity.
    assert_eq!(b.rx_timestamps.status().lost_bytes, 4);
    assert_eq!(
        b.peek_rx_timestamps(4).unwrap().unwrap().timestamps,
        stamps(2)
    );
    assert_eq!(b.read(&mut out), Ok(4));
    b.rx_timestamps.resize(0, 0).unwrap();
    input_rx(
        &mut b,
        45,
        base.wrapping_add(10),
        ack,
        ACK,
        None,
        b"kl",
        stamps(2),
    );
    assert_eq!(b.rx_timestamps.status().lost_bytes, 4); // Disabled is not overflow.
    assert_eq!(
        b.peek_rx_timestamps(2).unwrap().unwrap().timestamps,
        RxPacketTimestamps::default()
    );
}

#[test]
fn rx_timestamp_paws_ack_security_window_and_terminal_drain() {
    let (_, mut b) = pair(
        ConnectionConfig {
            timestamps: true,
            ..config(64, 32)
        },
        100,
    );
    b.rx_timestamps.resize(2, usize::MAX).unwrap();
    let base = b.receive.next();
    let ack = b.snd_nxt;
    b.ts_recent = 100;
    b.ts_recent_at = 30;
    input_rx(&mut b, 40, base, ack, ACK, Some(99), b"bad", stamps(9));
    input_rx(
        &mut b,
        41,
        base,
        ack.wrapping_add(1),
        ACK,
        Some(101),
        b"bad",
        stamps(9),
    );
    input_rx(
        &mut b,
        42,
        base.wrapping_add(1000),
        ack,
        ACK,
        Some(101),
        b"bad",
        stamps(9),
    );
    assert_eq!(b.rx_timestamps.status().retained_ranges, 0);
    assert_eq!(b.rx_timestamps.status().lost_bytes, 0);
    assert_eq!(b.readable_bytes(), 0);
    input_rx(&mut b, 43, base, ack, ACK, Some(101), b"abc", stamps(1));
    let info = b.peek_rx_timestamps(3).unwrap().unwrap();
    b.abort();
    let mut out = [0; 3];
    assert_eq!(b.peek(&mut out), Err(Error::InvalidState));
    assert_eq!(b.peek_terminal(&mut out), Ok(3));
    assert_eq!(b.peek_rx_timestamps(3).unwrap(), Some(info));
    assert_eq!(b.read_terminal(&mut out), Ok(3));
    assert_eq!(b.rx_timestamps.status().retained_ranges, 0);
}

#[test]
fn send_progress_syn_payload_ack_flush_fin_wrap_is_read_only() {
    for iss in [100, u32::MAX - 2] {
        let mut a = Connection::active(tuple(), config(16, 8), iss, 0).unwrap();
        let initial = a.send_progress();
        assert_eq!(
            initial,
            SendProgress {
                acknowledged: 0,
                queued_end: 0,
                unacknowledged_sequence: iss,
                next_write_sequence: iss.wrapping_add(1)
            }
        );
        a.write(b"abcd").unwrap();
        assert_eq!(a.send_progress().queued_end, 4);
        assert_eq!(a.send_progress().unacknowledged_sequence, iss);
        assert_eq!(a.send_progress().next_write_sequence, iss.wrapping_add(5));
        let syn = packet(&mut a, 0);
        let syn = wire::parse(ip(tuple()), &syn).unwrap();
        let mut b = Connection::passive(reverse(tuple()), config(16, 8), 900, 10, &syn).unwrap();
        deliver(&mut b, &mut a, 20);
        assert_eq!(a.send_progress().acknowledged, 0);
        assert_eq!(
            a.send_progress().unacknowledged_sequence,
            iss.wrapping_add(1)
        );
        deliver(&mut a, &mut b, 30);
        b.immediate_ack();
        deliver(&mut b, &mut a, 40);
        assert_eq!(a.send_progress().acknowledged, 4);
        assert_eq!(a.send_progress().queued_end, 4);
        let next = a.receive.next();
        let ack = a.snd_nxt;
        inject(&mut a, 41, next, ack, ACK, 0, &[]);
        a.write(b"efgh").unwrap();
        assert_eq!(a.send_progress().queued_end, 8);
        assert_eq!(a.flush(), Ok(4));
        assert_eq!(a.send_progress().queued_end, 4);
        inject(&mut a, 42, next, ack, ACK, 16, &[]);
        a.shutdown().unwrap();
        let before = a.send_progress();
        deliver(&mut a, &mut b, 50);
        deliver(&mut b, &mut a, 60);
        let after = a.send_progress();
        assert_eq!(after.acknowledged, 4);
        assert_eq!(after.queued_end, 4);
        assert_eq!(after.next_write_sequence, before.next_write_sequence); // Payload edge excludes FIN.
        assert_eq!(after.unacknowledged_sequence, iss.wrapping_add(6)); // Wire ACK includes FIN.
        assert_eq!(a.send_progress(), after);
    }
}

#[test]
fn rx_timestamp_syn_payload_and_fragmented_bitmap_runs_coalesce_without_allocation() {
    let mut a = Connection::active(tuple(), config(16, 8), 100, 0).unwrap();
    a.rx_timestamps.resize(2, usize::MAX).unwrap();
    packet(&mut a, 0);
    input_rx(
        &mut a,
        10,
        Seq(u32::MAX - 1),
        Seq(101),
        SYN | ACK,
        None,
        b"ab",
        stamps(1),
    );
    assert_eq!(a.state(), State::Established);
    assert_eq!(
        a.peek_rx_timestamps(2).unwrap().unwrap().timestamps,
        stamps(1)
    );
    let base = a.receive.next();
    let ack = a.snd_nxt;
    input_rx(
        &mut a,
        11,
        base.wrapping_add(2),
        ack,
        ACK,
        None,
        b"ef",
        stamps(1),
    );
    assert_eq!(a.rx_timestamps.status().retained_ranges, 2);
    input_rx(&mut a, 12, base, ack, ACK, None, b"cd", stamps(1));
    assert_eq!(a.rx_timestamps.status().retained_ranges, 1); // Bridges two equal runs.
    let mut out = [0; 8];
    assert_eq!(a.read(&mut out), Ok(6));
    assert_eq!(&out[..6], b"abcdef");
    a.rx_timestamps.resize(8, usize::MAX).unwrap();
    let base = a.receive.next();
    for offset in [1, 3, 5, 7] {
        input_rx(
            &mut a,
            20 + offset as u64,
            base.wrapping_add(offset),
            ack,
            ACK,
            None,
            b"X",
            stamps(2),
        );
    }
    input_rx(&mut a, 30, base, ack, ACK, None, b"01234567", stamps(3));
    assert_eq!(a.rx_timestamps.status().retained_ranges, 8);
    assert_eq!(a.rx_timestamps.status().lost_bytes, 0);
    for count in 1..=8 {
        assert_eq!(
            a.peek_rx_timestamps(count).unwrap().unwrap().timestamps,
            stamps(if count % 2 == 0 { 2 } else { 3 })
        );
    }
    assert_eq!(a.read(&mut out), Ok(8));
    assert_eq!(&out, b"0X2X4X6X");
    assert_eq!(a.rx_timestamps.status().retained_ranges, 0);
}

#[test]
fn rx_timestamp_pending_fin_clips_metadata_to_actual_payload() {
    let (_, mut b) = pair(config(16, 8), u32::MAX - 3);
    b.rx_timestamps.resize(1, usize::MAX).unwrap();
    let base = b.receive.next();
    let ack = b.snd_nxt;
    input_rx(
        &mut b,
        40,
        base.wrapping_add(4),
        ack,
        ACK | FIN,
        None,
        b"",
        stamps(1),
    );
    assert_eq!(b.rx_timestamps.status().retained_ranges, 0);
    input_rx(&mut b, 41, base, ack, ACK, None, b"abcdefgh", stamps(2));
    assert_eq!(b.readable_bytes(), 4);
    assert_eq!(
        b.peek_rx_timestamps(4).unwrap().unwrap().timestamps,
        stamps(2)
    );
    assert_eq!(b.peek_rx_timestamps(5), Err(Error::InvalidArgument));
    let status = b.rx_timestamps.status();
    input_rx(
        &mut b,
        42,
        base.wrapping_add(5),
        ack,
        ACK,
        None,
        b"ignored",
        stamps(3),
    );
    assert_eq!(b.rx_timestamps.status(), status);
    let mut bytes = [0; 8];
    assert_eq!(b.read(&mut bytes), Ok(4));
    assert_eq!(&bytes[..4], b"abcd");
    assert_eq!(b.read(&mut bytes), Ok(0));
    assert_eq!(b.rx_timestamps.status().retained_ranges, 0);
}
