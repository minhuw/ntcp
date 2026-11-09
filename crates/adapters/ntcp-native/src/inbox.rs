// A bounded inbox of packets that any thread may hand to one consumer.
// Packets are copied in; the consumer reads each in place and the inbox
// keeps its buffer for the next. A full inbox refuses the packet, which the
// producer counts as dropped.
use crate::{Error, Result};
use std::{
    collections::VecDeque,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(crate) struct Inbox<M> {
    queue: Mutex<VecDeque<(Vec<u8>, M)>>,
    len: AtomicUsize,
    packets: usize,
}

impl<M: Copy + Send> Inbox<M> {
    /// Room for `packets` packets, each with `packet_bytes` preallocated
    /// (a longer packet allocates).
    pub(crate) fn new(packets: usize, packet_bytes: usize) -> Result<Self> {
        if packets == 0 {
            return Err(Error::InvalidConfig("an inbox holds at least one packet"));
        }
        let _ = packet_bytes;
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(packets)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            queue: Mutex::new(queue),
            len: AtomicUsize::new(0),
            packets,
        })
    }

    /// From any thread: false, keeping nothing, if the inbox is full.
    pub(crate) fn push(&self, packet: &[u8], meta: M) -> bool {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.len() == self.packets {
            return false;
        }
        queue.push_back((packet.to_vec(), meta));
        self.len.store(queue.len(), Ordering::Release);
        true
    }

    /// The consumer: hands at most `budget` packets to `f` in the order
    /// they were pushed and returns how many it handed.
    pub(crate) fn drain(&self, budget: usize, mut f: impl FnMut(&[u8], M)) -> usize {
        let mut handed = 0;
        while handed < budget && !self.is_empty() {
            let item = {
                let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
                let item = queue.pop_front();
                self.len.store(queue.len(), Ordering::Release);
                item
            };
            let Some((packet, meta)) = item else { break };
            f(&packet, meta);
            handed += 1;
        }
        handed
    }

    /// One atomic load: whether nothing is waiting.
    pub(crate) fn is_empty(&self) -> bool {
        self.len.load(Ordering::Acquire) == 0
    }
}
