extern crate alloc;

use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

// A slot index always fits below END, since Rust's Vec length is bounded by
// `isize::MAX` (so `usize::MAX` is never a valid index). The head and every
// unqueued slot link to themselves as predecessors. A singleton also has
// no successor, so it needs no slot write to arrive or leave.
const END: usize = usize::MAX;

#[derive(Clone, Copy)]
struct Links {
    previous: usize,
    next: usize,
}

pub(crate) struct ReadyQueue {
    links: Vec<Links>,
    first: usize,
    last: usize,
}

impl ReadyQueue {
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        let mut links = Vec::new();
        links.try_reserve_exact(capacity).map_err(|_| ())?;
        links.extend((0..capacity).map(|index| Links {
            previous: index,
            next: END,
        }));
        Ok(Self {
            links,
            first: END,
            last: END,
        })
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        core::iter::successors(self.first(), |&index| self.next_of(index))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.first == END
    }

    pub(crate) fn first(&self) -> Option<usize> {
        (self.first != END).then_some(self.first)
    }

    pub(crate) fn sole(&self, index: usize) -> bool {
        self.first == index && self.last == index
    }

    pub(crate) fn next_of(&self, index: usize) -> Option<usize> {
        let next = self.links[index].next;
        (next != END).then_some(next)
    }

    pub(crate) fn contains(&self, index: usize) -> bool {
        self.first == index || self.first != END && self.links[index].previous != index
    }

    pub(crate) fn push(&mut self, index: usize) {
        debug_assert!(index < self.links.len());
        if self.first == END {
            self.first = index;
            self.last = index;
        } else if self.first != index && self.links[index].previous == index {
            self.links[self.last].next = index;
            self.links[index].previous = self.last;
            self.last = index;
        }
    }

    pub(crate) fn remove(&mut self, index: usize) {
        if self.first == index {
            self.pop();
            return;
        }
        if self.first == END {
            return;
        }
        let Links { previous, next } = self.links[index];
        if previous == index {
            return;
        }
        self.links[previous].next = next;
        if next == END {
            self.last = previous;
        } else {
            self.links[next].previous = previous;
        }
        self.links[index] = Links {
            previous: index,
            next: END,
        };
    }

    pub(crate) fn move_to_back(&mut self, index: usize) {
        if self.last != index {
            self.remove(index);
            self.push(index);
        }
    }

    pub(crate) fn pop(&mut self) -> Option<usize> {
        let index = self.first()?;
        if index == self.last {
            self.first = END;
            self.last = END;
        } else {
            let next = core::mem::replace(&mut self.links[index].next, END);
            self.links[next].previous = next;
            self.first = next;
        }
        Some(index)
    }
}

pub(crate) struct Deadlines {
    heap: Vec<(u64, usize)>,
    positions: Vec<Option<usize>>,
}

impl Deadlines {
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        let mut heap = Vec::new();
        heap.try_reserve_exact(capacity).map_err(|_| ())?;
        let mut positions = Vec::new();
        positions.try_reserve_exact(capacity).map_err(|_| ())?;
        positions.resize(capacity, None);
        Ok(Self { heap, positions })
    }

    #[inline]
    pub(crate) fn first(&self) -> Option<(u64, usize)> {
        self.heap.first().copied()
    }

    #[cfg(test)]
    fn time(&self, index: usize) -> Option<u64> {
        self.positions[index].map(|position| self.heap[position].0)
    }

    fn first_except(&self, index: usize) -> Option<(u64, usize)> {
        let first = self.first()?;
        if first.1 != index {
            return Some(first);
        }
        // The next smallest entry is one of the root's children.
        let left = *self.heap.get(1)?;
        Some(self.heap.get(2).map_or(left, |&right| left.min(right)))
    }

    // Move each intervening entry once, filling the hole with the new
    // entry only when its final position is known.
    fn place(&mut self, position: usize, entry: (u64, usize)) {
        self.heap[position] = entry;
        self.positions[entry.1] = Some(position);
    }

    fn up(&mut self, mut position: usize, entry: (u64, usize)) {
        while position != 0 {
            let parent = (position - 1) / 2;
            let other = self.heap[parent];
            if other <= entry {
                break;
            }
            self.place(position, other);
            position = parent;
        }
        self.place(position, entry);
    }

    fn down(&mut self, mut position: usize, entry: (u64, usize)) {
        while position < self.heap.len() / 2 {
            let left = position * 2 + 1;
            let right = left + 1;
            let child = if right < self.heap.len() && self.heap[right] < self.heap[left] {
                right
            } else {
                left
            };
            let other = self.heap[child];
            if entry <= other {
                break;
            }
            self.place(position, other);
            position = child;
        }
        self.place(position, entry);
    }

    pub(crate) fn set(&mut self, index: usize, deadline: Option<u64>) {
        match (self.positions[index], deadline) {
            (None, None) => {}
            (None, Some(time)) => {
                let position = self.heap.len();
                self.heap.push((time, index));
                self.up(position, (time, index));
            }
            (Some(position), Some(time)) => {
                let old = self.heap[position].0;
                if time < old {
                    self.up(position, (time, index));
                } else if time > old {
                    self.down(position, (time, index));
                }
            }
            (Some(position), None) => {
                let last = self.heap.pop().unwrap();
                self.positions[index] = None;
                if position < self.heap.len() {
                    if last < self.heap[position] {
                        self.up(position, last);
                    } else {
                        self.down(position, last);
                    }
                }
            }
        }
    }
}

// Input, an application read/write and the reservation of an outgoing frame
// can each rearm the same connection. Keep its current deadline separately
// and adjust its heap entry once when a different connection is serviced.
// The heap remains ordered throughout; its minimum excluding that connection
// stays valid until the switch. Queries always include the current deadline.
pub(crate) struct ConnectionTimers {
    stored: Deadlines,
    current: usize,
    deadline: Option<u64>,
    other: Option<(u64, usize)>,
}

impl ConnectionTimers {
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        Ok(Self {
            stored: Deadlines::new(capacity)?,
            current: END,
            deadline: None,
            other: None,
        })
    }

    #[inline]
    pub(crate) fn set(&mut self, index: usize, deadline: Option<u64>) {
        if index != self.current {
            self.change_owner(index);
        }
        self.deadline = deadline;
    }

    fn change_owner(&mut self, index: usize) {
        if self.current != END {
            self.stored.set(self.current, self.deadline);
        }
        self.other = self.stored.first_except(index);
        self.current = index;
    }

    #[inline]
    pub(crate) fn first(&self) -> Option<(u64, usize)> {
        self.first_with(self.deadline)
    }

    #[inline]
    pub(crate) fn first_with(&self, deadline: Option<u64>) -> Option<(u64, usize)> {
        match (deadline, self.other) {
            (Some(at), Some(other)) => Some(other.min((at, self.current))),
            (Some(at), None) => Some((at, self.current)),
            (None, other) => other,
        }
    }
}

// Index one lower bound per group of adjacent sockets. Rearming or
// cancelling a timer usually only writes its slot. A group's obsolete
// minimum is reconciled when a wake or an exact query reaches it.
const TIMERS_PER_GROUP: usize = 16;
const NO_TIMER: (u64, usize) = (u64::MAX, END);

pub(crate) struct SocketTimers {
    index: RefCell<ConnectionTimers>,
    minima: Vec<Cell<(u64, usize)>>,
    deadlines: Vec<Option<u64>>,
    earliest: Cell<u64>,
}

impl SocketTimers {
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        let groups = capacity.div_ceil(TIMERS_PER_GROUP);
        let mut minima = Vec::new();
        minima.try_reserve_exact(groups).map_err(|_| ())?;
        minima.resize(groups, Cell::new(NO_TIMER));
        let mut deadlines = Vec::new();
        deadlines.try_reserve_exact(capacity).map_err(|_| ())?;
        deadlines.resize(capacity, None);
        Ok(Self {
            index: RefCell::new(ConnectionTimers::new(groups)?),
            earliest: Cell::new(u64::MAX),
            minima,
            deadlines,
        })
    }

    #[inline]
    pub(crate) fn set(&mut self, slot: usize, deadline: Option<u64>) {
        self.deadlines[slot] = deadline;
        if let Some(at) = deadline {
            let group = slot / TIMERS_PER_GROUP;
            let key = (at, slot);
            if key < self.minima[group].get() {
                self.minima[group].set(key);
                self.earliest.set(self.earliest.get().min(at));
                self.index.get_mut().set(group, Some(at));
            }
        }
    }

    fn due_by(&self, through: u64) -> Option<(u64, usize)> {
        let mut index = self.index.borrow_mut();
        loop {
            let Some((at, group)) = index.first() else {
                self.earliest.set(u64::MAX);
                return None;
            };
            self.earliest.set(at);
            if at > through {
                return None;
            }
            let key = self.minima[group].get();
            debug_assert_eq!(at, key.0);
            if self.deadlines[key.1] == Some(at) {
                return Some(key);
            }
            let begin = group * TIMERS_PER_GROUP;
            let end = (begin + TIMERS_PER_GROUP).min(self.deadlines.len());
            let next = self.deadlines[begin..end]
                .iter()
                .enumerate()
                .filter_map(|(i, &deadline)| deadline.map(|time| (time, begin + i)))
                .min();
            self.minima[group].set(next.unwrap_or(NO_TIMER));
            index.set(group, next.map(|(time, _)| time));
        }
    }

    pub(crate) fn first(&self) -> Option<(u64, usize)> {
        self.due_by(u64::MAX)
    }

    pub(crate) fn due(&self, now: u64) -> bool {
        now >= self.earliest.get() && self.due_by(now).is_some()
    }

    pub(crate) fn earliest_possible(&self) -> u64 {
        self.earliest.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_queue_deduplicates_removes_and_reuses_slots() {
        let mut queue = ReadyQueue::new(3).unwrap();
        queue.push(0);
        queue.push(1);
        queue.push(0);
        queue.push(2);
        queue.remove(1);
        queue.push(1);
        assert_eq!(queue.pop(), Some(0));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(1));
        assert!(queue.is_empty());
        queue.push(2);
        queue.remove(2);
        queue.remove(2);
        queue.push(2);
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn indexed_deadlines_match_oracle_without_stale_entries() {
        let mut deadlines = Deadlines::new(17).unwrap();
        let mut oracle = [None; 17];
        let mut seed = 7u64;
        for _ in 0..10000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let slot = (seed >> 32) as usize % 17;
            let time = if seed & 7 == 0 {
                None
            } else {
                Some(seed % 1000)
            };
            oracle[slot] = time;
            deadlines.set(slot, time);
            assert_eq!(
                deadlines.first(),
                oracle
                    .iter()
                    .enumerate()
                    .filter_map(|(i, t)| t.map(|t| (t, i)))
                    .min()
            );
            assert_eq!(
                deadlines.heap.len(),
                oracle.iter().filter(|x| x.is_some()).count()
            );
            for (position, &(_, index)) in deadlines.heap.iter().enumerate() {
                assert_eq!(deadlines.positions[index], Some(position));
            }
        }
        for i in 0..17 {
            deadlines.set(i, None);
        }
        assert_eq!(deadlines.first(), None);
    }

    fn assert_deadlines_consistent(deadlines: &Deadlines) {
        let mut seen = 0usize;
        for (position, &entry) in deadlines.heap.iter().enumerate() {
            assert_eq!(deadlines.positions[entry.1], Some(position));
            if position > 0 {
                assert!(deadlines.heap[(position - 1) / 2] <= entry);
            }
        }
        for (index, &position) in deadlines.positions.iter().enumerate() {
            if let Some(pos) = position {
                assert_eq!(deadlines.heap[pos].1, index);
                seen += 1;
            }
        }
        assert_eq!(seen, deadlines.heap.len());
    }

    #[test]
    fn ready_queue_matches_fifo_oracle() {
        let mut queue = ReadyQueue::new(19).unwrap();
        let mut oracle: Vec<usize> = Vec::new();
        let mut seed = 0x5eed_1234_u64;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let slot = (seed >> 32) as usize % 19;
            match (seed >> 16) % 4 {
                0 | 1 => {
                    queue.push(slot);
                    if !oracle.contains(&slot) {
                        oracle.push(slot);
                    }
                }
                2 => {
                    queue.remove(slot);
                    if let Some(pos) = oracle.iter().position(|&x| x == slot) {
                        oracle.remove(pos);
                    }
                }
                _ => {
                    let expected = if oracle.is_empty() {
                        None
                    } else {
                        Some(oracle.remove(0))
                    };
                    assert_eq!(queue.pop(), expected);
                }
            }
            assert_eq!(queue.is_empty(), oracle.is_empty());
            assert_eq!(queue.first(), oracle.first().copied());
            let items: Vec<usize> = queue.iter().collect();
            assert_eq!(items, oracle);
            for i in 0..19 {
                assert_eq!(queue.contains(i), oracle.contains(&i));
            }
        }
        while !oracle.is_empty() {
            assert_eq!(queue.pop(), Some(oracle.remove(0)));
        }
        assert!(queue.is_empty());
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn repeated_timer_updates_match_the_minimum_after_every_change() {
        // Explicitly cover 0, 1, 2, 3 active entries with root-owner changes.
        let mut small = ConnectionTimers::new(4).unwrap();
        assert_eq!(small.first(), None);
        // 1 active entry, switching owner between root and non-root.
        small.set(0, Some(10));
        assert_eq!(small.first(), Some((10, 0)));
        small.set(1, None);
        assert_eq!(small.first(), Some((10, 0)));
        assert_deadlines_consistent(&small.stored);
        // 2 active entries: root (0, 10) + left child (1, 20), then take root ownership.
        small.set(1, Some(20));
        assert_eq!(small.first(), Some((10, 0)));
        small.set(0, Some(30));
        assert_eq!(small.first(), Some((20, 1)));
        small.set(0, None);
        assert_eq!(small.first(), Some((20, 1)));
        assert_deadlines_consistent(&small.stored);
        // 3 active entries: root + both children, covering both left < right and right < left.
        small.set(0, Some(5));
        small.set(2, Some(15));
        // Now stored has (1, 20), (0, 5) with current = 2 (15). Switch to root 0.
        small.set(0, Some(25));
        assert_eq!(small.first(), Some((15, 2)));
        assert_deadlines_consistent(&small.stored);
        small.set(2, Some(50));
        assert_eq!(small.first(), Some((20, 1)));
        assert_deadlines_consistent(&small.stored);
        // Clear all back to 0 active entries.
        small.set(0, None);
        small.set(1, None);
        small.set(2, None);
        assert_eq!(small.first(), None);
        assert_deadlines_consistent(&small.stored);

        let mut timers = ConnectionTimers::new(17).unwrap();
        let mut oracle = [None; 17];
        let mut seed = 11u64;
        let mut slot = 0;
        for _ in 0..10000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            if seed & 3 == 0 {
                slot = (seed >> 32) as usize % oracle.len();
            }
            let time = (seed & 7 != 0).then_some((seed >> 24) % 23);
            oracle[slot] = time;
            timers.set(slot, time);
            let expected = oracle
                .iter()
                .enumerate()
                .filter_map(|(index, &time)| time.map(|at| (at, index)))
                .min();
            assert_eq!(timers.first(), expected);
            assert_deadlines_consistent(&timers.stored);
            for (index, &expected_time) in oracle.iter().enumerate() {
                if index == timers.current {
                    assert_eq!(timers.deadline, expected_time);
                } else {
                    match (timers.stored.positions[index], expected_time) {
                        (Some(pos), Some(at)) => assert_eq!(timers.stored.heap[pos], (at, index)),
                        (None, None) => {}
                        other => panic!("stored mismatch for slot {index}: {other:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn rearming_an_unchanged_deadline_leaves_the_heap_as_it_was() {
        let mut deadlines = Deadlines::new(64).unwrap();
        let mut seed = 11u64;
        for round in 0..2000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let slot = (seed >> 32) as usize % 64;
            // Few distinct times, so ties between slots are common.
            deadlines.set(slot, (seed & 15 != 0).then_some(seed % 8));
            if round % 50 != 49 {
                continue;
            }
            let heap = deadlines.heap.clone();
            let positions = deadlines.positions.clone();
            for &(time, index) in &heap {
                deadlines.set(index, Some(time));
            }
            assert!(deadlines.heap == heap);
            assert!(deadlines.positions == positions);
        }
    }

    fn assert_ready_queue_invariants(
        queue: &ReadyQueue,
        model: &alloc::collections::VecDeque<usize>,
    ) {
        assert_eq!(queue.is_empty(), model.is_empty());
        assert_eq!(queue.first(), model.front().copied());
        if model.is_empty() {
            assert_eq!(queue.first, END);
            assert_eq!(queue.last, END);
        } else {
            let head = *model.front().unwrap();
            let tail = *model.back().unwrap();
            assert_eq!(queue.first, head);
            assert_eq!(queue.last, tail);
            assert_eq!(queue.links[head].previous, head);
            assert_eq!(queue.links[tail].next, END);
        }
        let items: Vec<usize> = queue.iter().collect();
        let expected: Vec<usize> = model.iter().copied().collect();
        assert_eq!(items, expected);
        for slot in 0..queue.links.len() {
            let present = model.contains(&slot);
            assert_eq!(queue.contains(slot), present, "contains({slot})");
            assert_eq!(
                queue.sole(slot),
                model.len() == 1 && model.front() == Some(&slot),
                "sole({slot})"
            );
            if !present {
                assert_eq!(queue.links[slot].previous, slot);
                assert_eq!(queue.links[slot].next, END);
            }
        }
    }

    #[test]
    fn ready_queue_differential_model_against_vecdeque() {
        use alloc::collections::VecDeque;

        // Deterministic edge cases: singleton, head, middle, tail, unqueued.
        let mut queue = ReadyQueue::new(5).unwrap();
        let mut model = VecDeque::new();
        assert_ready_queue_invariants(&queue, &model);

        // Remove from empty.
        queue.remove(0);
        assert_ready_queue_invariants(&queue, &model);

        // Singleton push, sole, duplicate push, move_to_back, remove, pop.
        queue.push(2);
        model.push_back(2);
        assert!(queue.sole(2));
        assert_ready_queue_invariants(&queue, &model);

        queue.push(2);
        assert_ready_queue_invariants(&queue, &model);

        queue.move_to_back(2);
        assert_ready_queue_invariants(&queue, &model);

        queue.remove(2);
        model.pop_front();
        assert_ready_queue_invariants(&queue, &model);

        // Build [0, 1, 2, 3]: remove head (0), middle (2), tail (3), singleton (1).
        for s in 0..4 {
            queue.push(s);
            model.push_back(s);
        }
        assert_ready_queue_invariants(&queue, &model);

        // Remove head.
        queue.remove(0);
        model.retain(|&x| x != 0);
        assert_ready_queue_invariants(&queue, &model);

        // Remove middle.
        queue.remove(2);
        model.retain(|&x| x != 2);
        assert_ready_queue_invariants(&queue, &model);

        // Remove tail.
        queue.remove(3);
        model.retain(|&x| x != 3);
        assert_ready_queue_invariants(&queue, &model);

        // Remaining singleton (1).
        assert!(queue.sole(1));
        assert_eq!(queue.pop(), model.pop_front());
        assert_ready_queue_invariants(&queue, &model);

        // Randomized differential test across small and medium capacities.
        for cap in [1usize, 2, 3, 7, 19] {
            let mut queue = ReadyQueue::new(cap).unwrap();
            let mut model = VecDeque::new();
            let mut seed = 0x1234_5678_9abc_def0u64 ^ (cap as u64);
            let mut next = || {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                seed
            };

            for _ in 0..4000 {
                let slot = (next() >> 32) as usize % cap;
                match (next() >> 16) % 5 {
                    0 | 1 => {
                        queue.push(slot);
                        if !model.contains(&slot) {
                            model.push_back(slot);
                        }
                    }
                    2 => {
                        queue.remove(slot);
                        if let Some(pos) = model.iter().position(|&x| x == slot) {
                            model.remove(pos);
                        }
                    }
                    3 => {
                        queue.move_to_back(slot);
                        if model.back() != Some(&slot) {
                            if let Some(pos) = model.iter().position(|&x| x == slot) {
                                model.remove(pos);
                            }
                            model.push_back(slot);
                        }
                    }
                    _ => {
                        assert_eq!(queue.pop(), model.pop_front());
                    }
                }
                assert_ready_queue_invariants(&queue, &model);
            }
            while let Some(expected) = model.pop_front() {
                assert_eq!(queue.pop(), Some(expected));
                assert_ready_queue_invariants(&queue, &model);
            }
            assert_eq!(queue.pop(), None);
        }
    }

    #[test]
    fn deadlines_time_and_connection_timers_first_with() {
        let mut deadlines = Deadlines::new(4).unwrap();
        assert_eq!(deadlines.time(0), None);
        deadlines.set(1, Some(50));
        deadlines.set(2, Some(20));
        assert_eq!(deadlines.time(0), None);
        assert_eq!(deadlines.time(1), Some(50));
        assert_eq!(deadlines.time(2), Some(20));
        deadlines.set(2, None);
        assert_eq!(deadlines.time(2), None);

        let mut timers = ConnectionTimers::new(4).unwrap();
        timers.set(0, Some(100));
        timers.set(1, Some(40));
        // Current owner is 1, other minimum is (100, 0).
        assert_eq!(timers.first_with(Some(25)), Some((25, 1)));
        assert_eq!(timers.first_with(Some(100)), Some((100, 0)));
        assert_eq!(timers.first_with(Some(200)), Some((100, 0)));
        assert_eq!(timers.first_with(None), Some((100, 0)));
    }

    fn oracle_first(oracle: &[Option<u64>]) -> Option<(u64, usize)> {
        oracle
            .iter()
            .enumerate()
            .filter_map(|(slot, &deadline)| deadline.map(|at| (at, slot)))
            .min()
    }

    #[test]
    fn socket_timers_differential_model_against_oracle() {
        // Edge cases: empty, full, equal timestamps, u64::MAX / 0 boundaries,
        // postponing, moving earlier, clearing, and reusing slots.
        let mut st = SocketTimers::new(4).unwrap();
        assert_eq!(st.earliest_possible(), u64::MAX);
        assert!(!st.due(0));
        assert!(!st.due(u64::MAX));
        assert_eq!(st.first(), None);

        // Equal timestamps tie-break by lowest slot index, even when inserted out of order.
        st.set(3, Some(50));
        st.set(1, Some(50));
        st.set(2, Some(50));
        st.set(0, Some(50));
        assert!(st.earliest_possible() <= 50);
        assert!(!st.due(49));
        assert!(st.due(50));
        assert_eq!(st.first(), Some((50, 0)));
        // Postpone slot 0 and clear slot 1; slot 2 must win next.
        st.set(0, Some(100));
        st.set(1, None);
        assert_eq!(st.first(), Some((50, 2)));
        // Boundary timestamps 0 and u64::MAX.
        st.set(1, Some(u64::MAX));
        st.set(2, None);
        st.set(3, None);
        st.set(0, None);
        assert!(!st.due(u64::MAX - 1));
        assert!(st.due(u64::MAX));
        assert_eq!(st.first(), Some((u64::MAX, 1)));
        st.set(2, Some(0));
        assert!(st.due(0));
        assert_eq!(st.first(), Some((0, 2)));
        st.set(1, None);
        st.set(2, None);
        assert_eq!(st.first(), None);
        assert_eq!(st.earliest_possible(), u64::MAX);

        // Randomized model test across capacities 1, 2, 3, 7, 19.
        for cap in [1usize, 2, 3, 7, 19] {
            let mut timers = SocketTimers::new(cap).unwrap();
            let mut oracle: Vec<Option<u64>> = alloc::vec![None; cap];
            let mut seed = 0x50c4_e771_dead_beefu64 ^ (cap as u64);
            let mut next = || {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                seed
            };

            for _ in 0..8000 {
                let op = (next() >> 16) % 10;
                match op {
                    0..=4 => {
                        // Set or update a slot's deadline (earlier, later, equal, or boundary).
                        let slot = (next() >> 32) as usize % cap;
                        let val = match (next() >> 24) % 8 {
                            0 => 0,
                            1 => u64::MAX,
                            2 => 42, // Frequent equal timestamps to stress tie-breaking
                            3 => 43,
                            _ => (next() >> 20) % 200,
                        };
                        timers.set(slot, Some(val));
                        oracle[slot] = Some(val);
                    }
                    5 | 6 => {
                        // Clear a slot.
                        let slot = (next() >> 32) as usize % cap;
                        timers.set(slot, None);
                        oracle[slot] = None;
                    }
                    7 => {
                        // Query due(now) without forcing a full first() reconciliation.
                        let now = match (next() >> 24) % 6 {
                            0 => 0,
                            1 => u64::MAX,
                            2 => oracle_first(&oracle).map_or(0, |(t, _)| t.saturating_sub(1)),
                            3 => oracle_first(&oracle).map_or(0, |(t, _)| t),
                            _ => (next() >> 20) % 200,
                        };
                        let expected_due = oracle_first(&oracle).is_some_and(|(t, _)| t <= now);
                        assert_eq!(timers.due(now), expected_due);
                    }
                    8 => {
                        // Query exact first().
                        assert_eq!(timers.first(), oracle_first(&oracle));
                    }
                    _ => {
                        // Fill or drain the table to exercise full/empty transitions.
                        if (next() & 1) == 0 {
                            let base = (next() >> 20) % 100;
                            for (slot, entry) in oracle.iter_mut().enumerate() {
                                let at = base.saturating_add((slot % 3) as u64);
                                timers.set(slot, Some(at));
                                *entry = Some(at);
                            }
                        } else {
                            for (slot, entry) in oracle.iter_mut().enumerate() {
                                timers.set(slot, None);
                                *entry = None;
                            }
                        }
                    }
                }
                // Lower-bound invariant must hold after EVERY operation without reconciling.
                let min_deadline = oracle_first(&oracle).map_or(u64::MAX, |(t, _)| t);
                assert!(
                    timers.earliest_possible() <= min_deadline,
                    "earliest_possible={} exceeded true min={}",
                    timers.earliest_possible(),
                    min_deadline
                );
            }
            // Final full reconciliation and drain.
            assert_eq!(timers.first(), oracle_first(&oracle));
            for slot in 0..cap {
                timers.set(slot, None);
                oracle[slot] = None;
                assert_eq!(timers.first(), oracle_first(&oracle));
            }
            assert_eq!(timers.first(), None);
            assert_eq!(timers.earliest_possible(), u64::MAX);
        }
    }
}
