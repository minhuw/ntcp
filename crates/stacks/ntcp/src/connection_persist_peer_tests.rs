use crate::{
    CongestionAlgorithm, ConnectionConfig, ConnectionId, Endpoint, EndpointConfig, InitialWindow,
    IpMetadata, ListenerId, wire,
};
use alloc::collections::BTreeMap;
use alloc::{vec, vec::Vec};

struct Packet {
    from_a: bool,
    ip: IpMetadata,
    bytes: Vec<u8>,
    ecn: u8,
}

struct Network {
    a: Endpoint,
    b: Endpoint,
    aid: ConnectionId,
    bid: Option<ConnectionId>,
    listener: ListenerId,
    now: u64,
    queue: BTreeMap<u64, Vec<Packet>>,
    reading: bool,
    drop_update: bool,
    delivered: Vec<u8>,
    first_read: Option<u64>,
    last_read: Option<u64>,
    shared_slots: usize,
    shared_seq: Option<u32>,
    shared_ranges: Vec<(usize, usize, usize)>,
    held: Vec<crate::Payload>,
    reject_mixed: bool,
    rejections: usize,
    shrink_after_reject: bool,
    accepted_shared_sizes: Vec<usize>,
}

impl Network {
    fn new(ipv6: bool, sack: bool, ecn: bool) -> Self {
        Self::with_pmtud(ipv6, sack, ecn, false)
    }

    fn with_pmtud(ipv6: bool, sack: bool, ecn: bool, pmtud: bool) -> Self {
        let mut c = ConnectionConfig {
            mss: 1000,
            pmtud: pmtud.then_some(crate::PmtudConfig::new(1500)),
            send_capacity: 65536,
            receive_capacity: 65536,
            timestamps: false,
            sack,
            rack: sack,
            tlp: sack,
            prr: true,
            prr_pacing: false,
            pacing: None,
            initial_window: InitialWindow::Iw10,
            congestion_algorithm: CongestionAlgorithm::Cubic,
            rto_min_us: 200_000,
            delayed_ack_us: 0,
            ecn,
            ..Default::default()
        };
        let make = |connection| {
            Endpoint::new(
                EndpointConfig {
                    connection,
                    max_connections: 2,
                    max_listeners: 1,
                    max_buffer_bytes: 16 * 1024 * 1024,
                    ..Default::default()
                },
                [42; 32],
                0,
                |_| true,
            )
            .unwrap()
        };
        let mut a = make(c.clone());
        c.receive_capacity = 10_000;
        let mut b = make(c);
        let local = if ipv6 {
            "[2001:db8::1]:40000"
        } else {
            "192.0.2.1:40000"
        }
        .parse()
        .unwrap();
        let remote = if ipv6 {
            "[2001:db8::2]:8080"
        } else {
            "192.0.2.2:8080"
        }
        .parse()
        .unwrap();
        let listener = b.listen(remote, 1).unwrap();
        let aid = a.connect(0, local, remote).unwrap();
        Self {
            a,
            b,
            aid,
            bid: None,
            listener,
            now: 0,
            queue: BTreeMap::new(),
            reading: false,
            drop_update: false,
            delivered: Vec::new(),
            first_read: None,
            last_read: None,
            shared_slots: 0,
            shared_seq: None,
            shared_ranges: Vec::new(),
            held: Vec::new(),
            reject_mixed: false,
            rejections: 0,
            shrink_after_reject: false,
            accepted_shared_sizes: Vec::new(),
        }
    }

    fn output(&mut self, from_a: bool) {
        for _ in 0..4096 {
            let mut bytes = vec![0; 2048];
            let out = if from_a && self.shared_slots != 0 {
                let mut parts = Vec::with_capacity(self.shared_slots);
                let (out, attempt) = self
                    .a
                    .poll_reserved_transmit_shared_for(
                        self.now, self.aid, &mut bytes, &mut parts, 64,
                    )
                    .unwrap();
                if let Some(tx) = out.packet {
                    let count = parts.iter().map(crate::Payload::len).sum::<usize>();
                    if count != 0 && self.reading && self.reject_mixed {
                        assert!(self.a.reject_unsubmitted(attempt.unwrap()).unwrap());
                        self.reject_mixed = false;
                        self.rejections += 1;
                        if self.shrink_after_reject {
                            self.a.set_first_hop_mtu(self.now, self.aid, 440).unwrap();
                            self.shrink_after_reject = false;
                        }
                        continue;
                    }
                    bytes.truncate(tx.len - count);
                    for part in &parts {
                        bytes.extend_from_slice(part.as_slice());
                    }
                    let p = wire::parse(tx.ip, &bytes).unwrap();
                    if count != 0 {
                        let base = *self.shared_seq.get_or_insert(p.header.sequence);
                        let mut offset = p.header.sequence.wrapping_sub(base) as usize;
                        for part in &parts {
                            let &(start, pointer, length) = self
                                .shared_ranges
                                .iter()
                                .find(|&&(start, _, length)| {
                                    offset >= start && offset < start + length
                                })
                                .unwrap();
                            assert_eq!(part.as_slice().as_ptr() as usize, pointer + offset - start);
                            assert!(part.len() <= start + length - offset);
                            offset += part.len();
                        }
                    }
                    if self.reading && count != 0 {
                        self.accepted_shared_sizes.push(count);
                    }
                    assert!(self.a.accept_transmit(self.now, attempt.unwrap()).unwrap());
                    self.held.extend(parts);
                }
                out
            } else if from_a {
                self.a.poll_transmit(self.now, &mut bytes, 64).unwrap()
            } else {
                self.b.poll_transmit(self.now, &mut bytes, 64).unwrap()
            };
            if let Some(tx) = out.packet {
                bytes.truncate(tx.len);
                let segment = wire::parse(tx.ip, &bytes).unwrap();
                if !from_a
                    && self.drop_update
                    && segment.payload.is_empty()
                    && segment.header.window > 0
                    && segment.header.flags == wire::ACK
                {
                    // Lose only the receiver's reopening advertisement. The
                    // next old-sequence probe must solicit an ACK from the peer.
                    self.drop_update = false;
                } else {
                    self.queue
                        .entry(self.now + 10_000)
                        .or_default()
                        .push(Packet {
                            from_a,
                            ip: tx.ip,
                            bytes,
                            ecn: tx.ecn,
                        });
                }
            }
            if !out.more_work && out.packet.is_none() {
                return;
            }
        }
        panic!("output did not quiesce");
    }

    fn service(&mut self, now: u64) {
        self.now = now;
        self.a.on_timeout(now, 64).unwrap();
        self.b.on_timeout(now, 64).unwrap();
        if let Some(packets) = self.queue.remove(&now) {
            for p in packets {
                if p.from_a {
                    self.b
                        .input_with_traffic_class(now, p.ip, p.ecn, &p.bytes)
                        .unwrap();
                } else {
                    self.a
                        .input_with_traffic_class(now, p.ip, p.ecn, &p.bytes)
                        .unwrap();
                }
                if self.bid.is_none() {
                    self.bid = self.b.accept(self.listener).ok();
                }
                self.read();
                self.output(!p.from_a);
            }
        }
        self.output(true);
        self.output(false);
        self.read();
        if self.reading {
            let info = self.a.transport_info(self.aid).unwrap();
            assert!(!info.loss && !info.recovery);
            assert_eq!(info.rto_backoff, 0);
            // ACK spacing may grow cwnd; flow-control handoff cannot shrink it.
            assert!(info.cwnd >= 10 * info.mss);
        }
    }

    fn read(&mut self) {
        if !self.reading {
            return;
        }
        let id = self.bid.unwrap();
        while self.b.readable_bytes(id).unwrap() != 0 {
            let mut bytes = [0; 2048];
            let n = self.b.read(id, &mut bytes).unwrap();
            assert!(n != 0);
            self.first_read.get_or_insert(self.now);
            self.last_read = Some(self.now);
            self.delivered.extend_from_slice(&bytes[..n]);
        }
    }

    fn until(&mut self, end: u64) {
        self.service(self.now);
        for _ in 0..20_000 {
            if self.now >= end {
                return;
            }
            let next = self
                .queue
                .first_key_value()
                .map(|(t, _)| *t)
                .into_iter()
                .chain(self.a.next_deadline())
                .chain(self.b.next_deadline())
                .min()
                .unwrap_or(end)
                .min(end);
            assert!(next >= self.now);
            self.service(next);
        }
        panic!("timers did not quiesce");
    }
}

#[test]
fn persist_reopen_real_receiver_delivers_without_false_loss() {
    for reopen_at in [400_000, 1_600_000] {
        for ipv6 in [false, true] {
            for sack in [false, true] {
                for ecn in [false, true] {
                    for bytes in [1, 1000, 20_000] {
                        // 0: no committed probe; 1: receiver rejects one or
                        // three probes; 2: reopening ACK lost, probe accepted.
                        for mode in 0..3 {
                            let mut n = Network::new(ipv6, sack, ecn);
                            n.until(40_000);
                            assert_eq!(n.a.write(n.aid, &[0x11; 10_000]).unwrap(), 10_000);
                            n.until(90_000);
                            assert_eq!(n.b.readable_bytes(n.bid.unwrap()).unwrap(), 10_000);
                            let payload: Vec<_> = (0..bytes).map(|i| (i % 251) as u8).collect();
                            if mode != 0 {
                                n.until(if mode == 1 {
                                    100_000
                                } else {
                                    reopen_at - 190_000
                                });
                                assert_eq!(n.a.write(n.aid, &payload).unwrap(), bytes);
                            }
                            n.until(reopen_at);
                            if mode == 0 {
                                assert_eq!(n.a.write(n.aid, &payload).unwrap(), bytes);
                            }
                            n.drop_update = mode == 2;
                            let mut warm = [0; 10_000];
                            assert_eq!(n.b.read(n.bid.unwrap(), &mut warm).unwrap(), 10_000);
                            assert_eq!(warm, [0x11; 10_000]);
                            n.reading = true;
                            n.until(reopen_at + 500_000);
                            assert_eq!(n.delivered, payload);
                            // A delivered window update permits first data in
                            // one RTT. A lost update requires an empty probe/
                            // reply round trip before the actual first data.
                            assert_eq!(
                                n.first_read,
                                Some(reopen_at + if mode == 2 { 40_000 } else { 20_000 })
                            );
                            assert_eq!(n.a.transport_info(n.aid).unwrap().unacked, 0);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn empty_probe_real_shared_peer_rejection_sg_bounds_and_lifetime() {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    for ipv6 in [false, true] {
        for sack in [false, true] {
            for ecn in [false, true] {
                for split in [false, true] {
                    for slots in [1, 2] {
                        for reject in [false, true] {
                            for size in [1000, 20000] {
                                let mut n = Network::new(ipv6, sack, ecn);
                                n.until(40000);
                                n.a.write(n.aid, &[0x11; 10000]).unwrap();
                                n.until(100000);
                                n.a.enable_output_reservations().unwrap();
                                n.a.enable_shared_output(slots).unwrap();
                                n.shared_slots = slots;
                                n.reject_mixed = reject;
                                let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                                let completed = Arc::new(AtomicUsize::new(0));
                                let spans = if split {
                                    vec![(0, 1), (1, size)]
                                } else {
                                    vec![(0, size)]
                                };
                                for &(start, end) in &spans {
                                    let done = completed.clone();
                                    let owned =
                                        crate::Payload::from_vec(payload[start..end].to_vec())
                                            .with_release(move || {
                                                done.fetch_add(1, Ordering::SeqCst);
                                            });
                                    n.shared_ranges.push((
                                        start,
                                        owned.as_slice().as_ptr() as usize,
                                        end - start,
                                    ));
                                    assert_eq!(
                                        n.a.write_shared(n.aid, owned, end != size, false, None)
                                            .unwrap(),
                                        end - start
                                    );
                                }
                                n.until(400000);
                                let mut warm = [0; 10000];
                                assert_eq!(n.b.read(n.bid.unwrap(), &mut warm).unwrap(), 10000);
                                n.reading = true;
                                n.until(900000);
                                assert_eq!(n.delivered, payload);
                                assert_eq!(n.rejections, usize::from(reject));
                                assert_eq!(completed.load(Ordering::SeqCst), 0);
                                assert_eq!(n.a.transport_info(n.aid).unwrap().unacked, 0);
                                if size == 1000 {
                                    assert_eq!(
                                        n.last_read,
                                        Some(if split && slots == 1 { 440000 } else { 420000 })
                                    );
                                }
                                n.held.clear();
                                assert_eq!(completed.load(Ordering::SeqCst), spans.len());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn empty_probe_shared_endpoint_reject_and_smaller_mtu_delivers_actual_fragments() {
    for sack in [false, true] {
        for ecn in [false, true] {
            let mut n = Network::with_pmtud(false, sack, ecn, true);
            n.until(40000);
            n.a.write(n.aid, &[0x11; 10000]).unwrap();
            n.until(100000);
            n.a.enable_output_reservations().unwrap();
            n.a.enable_shared_output(2).unwrap();
            n.shared_slots = 2;
            n.reject_mixed = true;
            n.shrink_after_reject = true;
            let data = crate::Payload::from_vec(vec![0x55; 1000]);
            n.shared_ranges
                .push((0, data.as_slice().as_ptr() as usize, 1000));
            n.a.write_shared(n.aid, data, false, false, None).unwrap();
            n.until(400000);
            let mut warm = [0; 10000];
            assert_eq!(n.b.read(n.bid.unwrap(), &mut warm).unwrap(), 10000);
            n.reading = true;
            n.until(900000);
            assert_eq!(n.rejections, 1);
            assert_eq!(n.accepted_shared_sizes, vec![400, 400, 200]);
            assert_eq!(n.delivered, vec![0x55; 1000]);
            assert_eq!(n.last_read, Some(420000));
            assert_eq!(n.a.path_mtu_info(n.aid).unwrap().unwrap().current_mtu, 440);
        }
    }
}
