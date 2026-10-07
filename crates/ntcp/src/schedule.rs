extern crate alloc;

use alloc::vec::Vec;

#[derive(Clone, Copy, Default)]
struct Links {
    previous: Option<usize>,
    next: Option<usize>,
    queued: bool,
}

pub(crate) struct ReadyQueue {
    links: Vec<Links>,
    first: Option<usize>,
    last: Option<usize>,
}

impl ReadyQueue {
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        let mut links = Vec::new();
        links.try_reserve_exact(capacity).map_err(|_| ())?;
        links.resize(capacity, Links::default());
        Ok(Self {
            links,
            first: None,
            last: None,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    pub(crate) fn push(&mut self, index: usize) {
        if self.links[index].queued {
            return;
        }
        self.links[index] = Links {
            previous: self.last,
            next: None,
            queued: true,
        };
        if let Some(last) = self.last {
            self.links[last].next = Some(index);
        } else {
            self.first = Some(index);
        }
        self.last = Some(index);
    }

    pub(crate) fn remove(&mut self, index: usize) {
        let links = self.links[index];
        if !links.queued {
            return;
        }
        if let Some(previous) = links.previous {
            self.links[previous].next = links.next;
        } else {
            self.first = links.next;
        }
        if let Some(next) = links.next {
            self.links[next].previous = links.previous;
        } else {
            self.last = links.previous;
        }
        self.links[index] = Links::default();
    }

    pub(crate) fn pop(&mut self) -> Option<usize> {
        let index = self.first?;
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

    pub(crate) fn first(&self) -> Option<(u64, usize)> {
        self.heap.first().copied()
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        self.positions[self.heap[a].1] = Some(a);
        self.positions[self.heap[b].1] = Some(b);
    }

    fn up(&mut self, mut position: usize) -> usize {
        while position != 0 {
            let parent = (position - 1) / 2;
            if self.heap[parent] <= self.heap[position] {
                break;
            }
            self.swap(parent, position);
            position = parent;
        }
        position
    }

    fn down(&mut self, mut position: usize) {
        loop {
            let left = position * 2 + 1;
            if left >= self.heap.len() {
                return;
            }
            let right = left + 1;
            let child = if right < self.heap.len() && self.heap[right] < self.heap[left] {
                right
            } else {
                left
            };
            if self.heap[position] <= self.heap[child] {
                return;
            }
            self.swap(position, child);
            position = child;
        }
    }

    pub(crate) fn set(&mut self, index: usize, deadline: Option<u64>) {
        match (self.positions[index], deadline) {
            (None, None) => {}
            (None, Some(time)) => {
                let position = self.heap.len();
                self.heap.push((time, index));
                self.positions[index] = Some(position);
                self.up(position);
            }
            (Some(position), Some(time)) => {
                self.heap[position].0 = time;
                let position = self.up(position);
                self.down(position);
            }
            (Some(position), None) => {
                let last = self.heap.len() - 1;
                self.swap(position, last);
                self.heap.pop();
                self.positions[index] = None;
                if position < self.heap.len() {
                    let position = self.up(position);
                    self.down(position);
                }
            }
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
}
