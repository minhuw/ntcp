extern crate alloc;

use alloc::vec::Vec;

// A slot index always fits below END, since Rust's Vec length is bounded by
// `isize::MAX` (so `usize::MAX` is never a valid index). An unqueued slot
// links to itself as its predecessor.
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

    pub(crate) fn next_of(&self, index: usize) -> Option<usize> {
        let next = self.links[index].next;
        (next != END).then_some(next)
    }

    pub(crate) fn contains(&self, index: usize) -> bool {
        self.links[index].previous != index
    }

    pub(crate) fn push(&mut self, index: usize) {
        if self.contains(index) {
            return;
        }
        self.links[index] = Links {
            previous: self.last,
            next: END,
        };
        if self.last == END {
            self.first = index;
        } else {
            self.links[self.last].next = index;
        }
        self.last = index;
    }

    pub(crate) fn remove(&mut self, index: usize) {
        let Links { previous, next } = self.links[index];
        if previous == index {
            return;
        }
        if previous == END {
            self.first = next;
        } else {
            self.links[previous].next = next;
        }
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

    pub(crate) fn pop(&mut self) -> Option<usize> {
        let index = self.first()?;
        self.remove(index);
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
        match (self.deadline, self.other) {
            (Some(at), Some(other)) => Some(other.min((at, self.current))),
            (Some(at), None) => Some((at, self.current)),
            (None, other) => other,
        }
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
}
