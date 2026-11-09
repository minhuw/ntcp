// A bounded inbox of packets that any thread may hand to one consumer.
// Packets are copied in; the consumer reads each in place and the inbox
// keeps its buffer for the next. A full inbox refuses the packet, which the
// producer counts as dropped.
//
// The inbox is a ring of slots sequenced as in Vyukov's bounded queue, in
// the form crossbeam's ArrayQueue uses, whose positions carry a lap above
// the slot index so that any slot count works. A producer claims the next
// position by advancing `tail` with one compare-exchange, copies the packet
// into that slot's buffer and publishes it through the slot's stamp. The one
// consumer reads published slots in position order and frees each through
// its stamp. Each buffer sits behind its own Mutex only so that safe code
// can write it: the stamps give a slot to one side at a time, so the lock is
// never contended, and the consumer holds it while its callback runs without
// any producer waiting on it.
//
// The alternative was a Mutex<VecDeque> with a recycled buffer pool, whose
// consumer takes a whole batch under the lock and hands its buffers back
// under a second short one. Measured in a release build on a Xeon Gold
// 6230R, producers and consumer on their own cores, the consumer polling
// between other work: TSC cycles spent in push and in drain per packet, with
// one, two and four producers,
//   64 octets:   ring 277+294, 334+296, 393+312;
//                batch queue 474+461, 491+455, 2455+981;
//   1500 octets: ring 443+380, 637+356, 757+369;
//                batch queue 500+465, 1269+822, 3359+1218.
// Every packet moves cache lines between cores either way, and the batch
// queue's shared lock costs more than its batching saves. Only one thread
// pushing 32 packets and draining them itself, with no line changing cores,
// favored it (60 ns against 114 ns per 1500-octet packet).
//
// `is_empty` compares `tail` with `head` rather than reading a count of
// waiting packets: a count would cost every push an atomic add on a line the
// consumer writes too (76, 186 and 297 more cycles per 64-octet push with
// one, two and four producers), while the consumer's load of its own `head`
// stays in its cache.
//
// A packet longer than `packet_bytes` (a reassembled datagram) gets a buffer
// of its own. When the consumer frees the slot it shrinks the buffer back to
// `packet_bytes`, so an inbox at rest holds `packets` buffers of that size
// whatever it carried, and the reallocation falls on the consumer, not on
// the producers.
use crate::{Error, Result};
use std::{
    hint,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering, fence},
    },
};

pub(crate) struct Inbox<M> {
    slots: Vec<Slot<M>>,
    // The smallest power of two above the slot count: a position is
    // `lap * k + index`, and the slot's next position is one lap later.
    lap: usize,
    packet_bytes: usize,
    // The position the next producer claims.
    tail: Line<AtomicUsize>,
    // The position the consumer reads next. Only the consumer writes it;
    // producers read it to tell a full inbox.
    head: Line<AtomicUsize>,
}

// Keeps what producers write apart from what the consumer writes. Two
// lines, because x86 prefetches lines in adjacent pairs.
#[repr(align(128))]
struct Line<T>(T);

#[repr(align(128))]
struct Slot<M> {
    // The position whose producer may fill the slot, or that position plus
    // one once its packet is in.
    stamp: AtomicUsize,
    packet: Mutex<Packet<M>>,
}

struct Packet<M> {
    bytes: Vec<u8>,
    meta: Option<M>,
}

impl<M: Copy + Send> Inbox<M> {
    /// Room for `packets` packets, each with `packet_bytes` preallocated
    /// (a longer packet allocates).
    pub(crate) fn new(packets: usize, packet_bytes: usize) -> Result<Self> {
        if packets == 0 {
            return Err(Error::InvalidConfig("an inbox holds at least one packet"));
        }
        let lap = packets
            .checked_add(1)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::Capacity)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(packets)
            .map_err(|_| Error::Capacity)?;
        for index in 0..packets {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(packet_bytes)
                .map_err(|_| Error::Capacity)?;
            slots.push(Slot {
                stamp: AtomicUsize::new(index),
                packet: Mutex::new(Packet { bytes, meta: None }),
            });
        }
        Ok(Self {
            slots,
            lap,
            packet_bytes,
            tail: Line(AtomicUsize::new(0)),
            head: Line(AtomicUsize::new(0)),
        })
    }

    /// From any thread: false, keeping nothing, if the inbox is full (or
    /// cannot allocate for a packet longer than its buffers).
    pub(crate) fn push(&self, packet: &[u8], meta: M) -> bool {
        // Allocated before a position is claimed: a claimed position must be
        // published, so a failure after the claim could not be refused.
        let mut own = None;
        if packet.len() > self.packet_bytes {
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(packet.len()).is_err() {
                return false;
            }
            own = Some(bytes);
        }
        let mut tail = self.tail.0.load(Ordering::Relaxed);
        loop {
            let slot = self.slot(tail);
            if slot.stamp.load(Ordering::Acquire) == tail {
                match self.tail.0.compare_exchange_weak(
                    tail,
                    self.next(tail),
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let mut held = slot.packet.lock().unwrap_or_else(PoisonError::into_inner);
                        if let Some(bytes) = own {
                            held.bytes = bytes;
                        }
                        held.bytes.clear();
                        held.bytes.extend_from_slice(packet);
                        held.meta = Some(meta);
                        drop(held);
                        slot.stamp.store(tail + 1, Ordering::Release);
                        return true;
                    }
                    Err(current) => tail = current,
                }
            } else {
                // The slot still holds the packet from a lap before, or
                // another producer took this position since `tail` was read.
                // Only the first, with the consumer a whole lap behind, is a
                // full inbox; the second retries at the new tail.
                fence(Ordering::SeqCst);
                if self.head.0.load(Ordering::Relaxed).wrapping_add(self.lap) == tail {
                    return false;
                }
                tail = self.tail.0.load(Ordering::Relaxed);
            }
            hint::spin_loop();
        }
    }

    /// The consumer: hands at most `budget` packets to `f` in the order
    /// they were pushed and returns how many it handed. It stops early at a
    /// position claimed by a producer that is still copying its packet in.
    pub(crate) fn drain(&self, budget: usize, mut f: impl FnMut(&[u8], M)) -> usize {
        let mut handed = 0;
        while handed < budget {
            let head = self.head.0.load(Ordering::Relaxed);
            let slot = self.slot(head);
            if slot.stamp.load(Ordering::Acquire) != head + 1 {
                break;
            }
            let free = Free { inbox: self, head };
            let mut held = slot.packet.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(meta) = held.meta.take() {
                f(&held.bytes, meta);
                handed += 1;
            }
            if held.bytes.capacity() > self.packet_bytes {
                held.bytes.clear();
                held.bytes.shrink_to(self.packet_bytes);
            }
            drop(held);
            drop(free);
        }
        handed
    }

    /// Whether nothing is waiting, without a lock: a load of `tail` and
    /// one of the consumer's own `head`, which stays in its cache.
    pub(crate) fn is_empty(&self) -> bool {
        self.tail.0.load(Ordering::Acquire) == self.head.0.load(Ordering::Relaxed)
    }
}

impl<M> Inbox<M> {
    fn slot(&self, position: usize) -> &Slot<M> {
        &self.slots[position & (self.lap - 1)]
    }

    fn next(&self, position: usize) -> usize {
        if (position & (self.lap - 1)) + 1 < self.slots.len() {
            position + 1
        } else {
            (position & !(self.lap - 1)).wrapping_add(self.lap)
        }
    }
}

// Frees the consumer's slot for the next lap, also when the callback
// unwinds: a panic then loses that one packet instead of leaving a slot that
// is never freed and an inbox that refuses every push from then on.
struct Free<'a, M> {
    inbox: &'a Inbox<M>,
    head: usize,
}

impl<M> Drop for Free<'_, M> {
    fn drop(&mut self) {
        let inbox = self.inbox;
        inbox
            .slot(self.head)
            .stamp
            .store(self.head.wrapping_add(inbox.lap), Ordering::Release);
        inbox.head.0.store(inbox.next(self.head), Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        panic::{self, AssertUnwindSafe},
        sync::{Arc, atomic::AtomicBool},
        thread,
    };

    fn drained<M: Copy + Send>(inbox: &Inbox<M>, budget: usize) -> Vec<(Vec<u8>, M)> {
        let mut packets = Vec::new();
        let handed = inbox.drain(budget, |bytes, meta| packets.push((bytes.to_vec(), meta)));
        assert_eq!(handed, packets.len());
        packets
    }

    fn capacities<M>(inbox: &Inbox<M>) -> Vec<(usize, *const u8)> {
        inbox
            .slots
            .iter()
            .map(|slot| {
                let held = slot.packet.lock().unwrap();
                (held.bytes.capacity(), held.bytes.as_ptr())
            })
            .collect()
    }

    #[test]
    fn inbox_is_shared_between_threads() {
        fn shared<T: Send + Sync>() {}
        shared::<Inbox<ntcp::RxPacketMetadata>>();
        shared::<Inbox<(u32, u64)>>();
    }

    #[test]
    fn inbox_needs_a_packet() {
        assert!(matches!(
            Inbox::<u32>::new(0, 64),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn inbox_drains_in_order_within_budget() {
        let inbox = Inbox::new(8, 64).unwrap();
        for i in 0..5u32 {
            assert!(inbox.push(&[i as u8; 3], i));
        }
        assert_eq!(inbox.drain(0, |_, _| panic!("no budget")), 0);
        let first = drained(&inbox, 2);
        assert_eq!(first, [(vec![0; 3], 0), (vec![1; 3], 1)]);
        let rest = drained(&inbox, 10);
        assert_eq!(
            rest.iter().map(|(_, meta)| *meta).collect::<Vec<_>>(),
            [2, 3, 4]
        );
        assert!(drained(&inbox, 10).is_empty());
    }

    #[test]
    fn inbox_refuses_when_full_and_recovers() {
        // Three slots, not a power of two, through many laps.
        let inbox = Inbox::new(3, 16).unwrap();
        let mut next = 0u32;
        let mut expected = Vec::new();
        for _ in 0..50 {
            while inbox.push(&next.to_be_bytes(), next) {
                expected.push(next);
                next += 1;
            }
            assert!(!inbox.push(&[0xff], u32::MAX), "refused again");
            let budget = 1 + next as usize % 3;
            let packets = drained(&inbox, budget);
            assert_eq!(packets.len(), budget);
            for (bytes, meta) in packets {
                assert_eq!(meta, expected.remove(0));
                assert_eq!(bytes, meta.to_be_bytes());
            }
        }
        let packets = drained(&inbox, usize::MAX);
        assert_eq!(
            packets
                .into_iter()
                .map(|(_, meta)| meta)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(inbox.is_empty());
    }

    #[test]
    fn inbox_carries_empty_and_reassembled_packets() {
        let inbox = Inbox::new(4, 1500).unwrap();
        let before = capacities(&inbox);
        let long: Vec<u8> = (0..65535u32).map(|i| (i % 251) as u8).collect();
        assert!(inbox.push(&[], 0u8));
        assert!(inbox.push(&long, 1));
        assert!(inbox.push(&long[..1500], 2));
        let packets = drained(&inbox, usize::MAX);
        assert_eq!(packets[0], (Vec::new(), 0));
        assert_eq!(packets[1], (long.clone(), 1));
        assert_eq!(packets[2], (long[..1500].to_vec(), 2));
        // The long packet's buffer was given back at the preallocated size;
        // the others never left theirs.
        let after = capacities(&inbox);
        assert!(after.iter().all(|&(capacity, _)| capacity == 1500));
        assert_eq!(after[0], before[0]);
        assert_eq!(after[2..], before[2..]);
    }

    #[test]
    fn inbox_keeps_metadata() {
        let inbox = Inbox::new(4, 64).unwrap();
        let late = ntcp::RxPacketMetadata {
            tcp_segment_size: std::num::NonZeroU16::new(1448),
            ..Default::default()
        };
        assert!(inbox.push(b"a", ntcp::RxPacketMetadata::default()));
        assert!(inbox.push(b"b", late));
        let packets = drained(&inbox, usize::MAX);
        assert_eq!(packets[0].1, ntcp::RxPacketMetadata::default());
        assert_eq!(packets[1], (b"b".to_vec(), late));
    }

    #[test]
    fn inbox_reports_emptiness() {
        let inbox = Inbox::new(2, 64).unwrap();
        assert!(inbox.is_empty());
        assert!(inbox.push(b"x", ()));
        assert!(!inbox.is_empty());
        assert_eq!(inbox.drain(0, |_, _| {}), 0);
        assert!(!inbox.is_empty());
        assert!(inbox.push(b"y", ()));
        assert!(!inbox.push(b"z", ()));
        assert_eq!(inbox.drain(1, |_, _| {}), 1);
        assert!(!inbox.is_empty());
        assert_eq!(inbox.drain(5, |_, _| {}), 1);
        assert!(inbox.is_empty());
        assert_eq!(inbox.drain(5, |_, _| {}), 0);
    }

    #[test]
    fn inbox_reuses_its_buffers() {
        let inbox = Inbox::new(8, 256).unwrap();
        let packet = [7u8; 256];
        let round = |inbox: &Inbox<usize>, count: usize| {
            for i in 0..count {
                assert!(inbox.push(&packet[..i * 37 % 257], i));
            }
            assert_eq!(inbox.drain(usize::MAX, |_, _| {}), count);
        };
        for count in 1..=8 {
            round(&inbox, count);
        }
        let warm = capacities(&inbox);
        assert!(warm.iter().all(|&(capacity, _)| capacity == 256));
        for count in (1..=8).cycle().take(200) {
            round(&inbox, count);
        }
        assert_eq!(capacities(&inbox), warm);
    }

    #[test]
    fn inbox_callback_may_push() {
        let inbox = Inbox::new(2, 64).unwrap();
        let other = Inbox::new(2, 64).unwrap();
        assert!(inbox.push(b"a", 1));
        assert!(inbox.push(b"b", 2));
        let handed = inbox.drain(2, |bytes, meta| {
            assert!(other.push(bytes, meta));
            // Full while the first slot is in hand; once it is freed, a push
            // takes it.
            assert_eq!(inbox.push(b"c", 3), meta == 2);
        });
        assert_eq!(handed, 2);
        assert_eq!(drained(&other, usize::MAX).len(), 2);
        assert!(inbox.push(b"d", 4));
        let rest = drained(&inbox, usize::MAX);
        assert_eq!(rest, [(b"c".to_vec(), 3), (b"d".to_vec(), 4)]);
    }

    #[test]
    fn inbox_survives_a_panicking_callback() {
        let inbox = Inbox::new(2, 64).unwrap();
        assert!(inbox.push(b"a", 1));
        assert!(inbox.push(b"b", 2));
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            inbox.drain(usize::MAX, |_, _| panic!("callback"))
        }));
        assert!(result.is_err());
        // The packet in hand is lost; its slot and the rest are not.
        assert_eq!(drained(&inbox, usize::MAX), [(b"b".to_vec(), 2)]);
        assert!(inbox.push(b"c", 3));
        assert!(inbox.push(b"d", 4));
        assert_eq!(drained(&inbox, usize::MAX).len(), 2);
    }

    #[test]
    fn inbox_takes_packets_from_many_threads() {
        const PRODUCERS: usize = 4;
        const PACKETS: u64 = 100_000;
        let inbox = Arc::new(Inbox::new(64, 128).unwrap());
        let start = Arc::new(AtomicBool::new(false));
        let producers: Vec<_> = (0..PRODUCERS)
            .map(|producer| {
                let inbox = Arc::clone(&inbox);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    while !start.load(Ordering::Acquire) {
                        hint::spin_loop();
                    }
                    let mut refused = 0u64;
                    let mut packet = [0u8; 300];
                    for sequence in 0..PACKETS {
                        // Mostly short packets, now and then one longer than
                        // the buffers.
                        let len = if sequence % 997 == 0 {
                            300
                        } else {
                            8 + (sequence % 120) as usize
                        };
                        packet[..8].copy_from_slice(&sequence.to_be_bytes());
                        packet[8..len].fill(producer as u8);
                        if !inbox.push(&packet[..len], (producer, sequence)) {
                            refused += 1;
                        }
                    }
                    refused
                })
            })
            .collect();
        start.store(true, Ordering::Release);
        let mut next = [0u64; PRODUCERS];
        let mut received = [0u64; PRODUCERS];
        let mut check = |bytes: &[u8], (producer, sequence): (usize, u64)| {
            // In order per producer, each at most once, and intact.
            assert!(sequence >= next[producer]);
            next[producer] = sequence + 1;
            received[producer] += 1;
            assert_eq!(bytes[..8], sequence.to_be_bytes());
            assert!(bytes[8..].iter().all(|&octet| octet == producer as u8));
        };
        while !producers.iter().all(|producer| producer.is_finished()) {
            inbox.drain(32, &mut check);
        }
        let refused: Vec<u64> = producers
            .into_iter()
            .map(|producer| producer.join().unwrap())
            .collect();
        inbox.drain(usize::MAX, &mut check);
        assert!(inbox.is_empty());
        for producer in 0..PRODUCERS {
            assert_eq!(received[producer] + refused[producer], PACKETS);
        }
        assert!(
            capacities(&inbox)
                .iter()
                .all(|&(capacity, _)| capacity == 128)
        );
    }
}
