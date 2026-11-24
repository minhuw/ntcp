use alloc::collections::VecDeque;

// Singleton mode may hold only PUSH (bit 0) and EOR (bit 1); PTB and
// retransmission bits always live in the materialized ring so PTB queries
// can inspect `ring` directly without checking singleton state.
const SINGLETON_BITS: u8 = 0b11;

// An unmarked stream, or a single marked byte, needs only its length and
// that position. The backing ring is reserved at write admission so a later
// PUSH, record boundary, or loss repair can mark arbitrary bytes infallibly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct SendMarks {
    pub(super) ring: VecDeque<u8>,
    len: usize,
    position: usize,
    bits: u8,
}

impl SendMarks {
    pub(super) fn reserve(&mut self, capacity: usize) -> Result<(), ()> {
        self.ring
            .try_reserve_exact(capacity.saturating_sub(self.ring.len()))
            .map_err(|_| ())
    }

    pub(super) fn capacity(&self) -> usize {
        self.ring.capacity()
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn singleton(&self) -> Option<(usize, u8)> {
        if self.ring.is_empty() {
            debug_assert_eq!(
                self.bits & !SINGLETON_BITS,
                0,
                "singleton mode may only hold PUSH/EOR bits"
            );
            debug_assert!(self.bits == 0 || self.position < self.len);
            Some((self.position, self.bits))
        } else {
            None
        }
    }

    pub(super) fn extend_to(&mut self, len: usize) {
        debug_assert!(len >= self.len);
        if !self.ring.is_empty() {
            self.ring.resize(len, 0);
        }
        self.len = len;
    }

    pub(super) fn materialize(&mut self) -> &mut VecDeque<u8> {
        if self.ring.is_empty() {
            debug_assert_eq!(
                self.bits & !SINGLETON_BITS,
                0,
                "singleton mode may only hold PUSH/EOR bits"
            );
            self.ring.resize(self.len, 0);
            if self.bits != 0 {
                self.ring[self.position] = self.bits;
                self.bits = 0;
            }
        } else {
            debug_assert_eq!(self.bits, 0);
            debug_assert_eq!(self.ring.len(), self.len);
        }
        &mut self.ring
    }

    pub(super) fn or_at(&mut self, index: usize, bits: u8) -> bool {
        if index >= self.len {
            return false;
        }
        if bits == 0 {
            return true;
        }
        if self.ring.is_empty() && (self.bits == 0 || self.position == index) {
            debug_assert_eq!(
                bits & !SINGLETON_BITS,
                0,
                "singleton mode may only hold PUSH/EOR bits"
            );
            self.position = index;
            self.bits |= bits;
            return true;
        }
        self.materialize()[index] |= bits;
        true
    }

    pub(super) fn or_back(&mut self, bits: u8) -> bool {
        let Some(last) = self.len.checked_sub(1) else {
            return false;
        };
        self.or_at(last, bits)
    }

    pub(super) fn last(&self, bit: u8) -> Option<usize> {
        if self.ring.is_empty() {
            debug_assert_eq!(
                self.bits & !SINGLETON_BITS,
                0,
                "singleton mode may only hold PUSH/EOR bits"
            );
            (self.bits & bit != 0).then_some(self.position)
        } else {
            self.ring.iter().rposition(|mark| mark & bit != 0)
        }
    }

    pub(super) fn clear(&mut self) {
        self.len = 0;
        self.bits = 0;
        self.ring.clear();
    }

    pub(super) fn drop_prefix(&mut self, count: usize) {
        self.len -= count;
        if self.ring.is_empty() {
            if self.position < count {
                self.bits = 0;
            } else {
                self.position -= count;
            }
        } else {
            self.ring.drain(..count);
        }
    }

    pub(super) fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
        if self.position >= self.len {
            self.bits = 0;
        }
        self.ring.truncate(len);
    }

    #[cfg(test)]
    pub(super) fn iter(&self) -> impl Iterator<Item = &u8> {
        (0..self.len).map(|i| {
            self.ring
                .get(i)
                .unwrap_or(if i == self.position { &self.bits } else { &0 })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "singleton mode may only hold PUSH/EOR bits")]
    fn singleton_rejects_ptb_bits() {
        let mut marks = SendMarks::default();
        marks.reserve(8).unwrap();
        marks.extend_to(4);
        let _ = marks.or_at(1, 1 << 2);
    }

    #[test]
    fn randomized_model_matches_vecdeque_oracle() {
        let mut marks = SendMarks::default();
        let mut oracle: VecDeque<u8> = VecDeque::new();
        let mut capacity = 16usize;
        marks.reserve(capacity).unwrap();
        let mut state = 0x51a7_3c19_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };

        let mut saw_singleton_with_bits = false;
        let mut saw_materialized = false;
        let mut saw_return_to_singleton = false;

        for _ in 0..5000 {
            let was_materialized = marks.singleton().is_none();
            match next(7) {
                0 | 1 => {
                    let add = next(24);
                    let new_len = oracle.len() + add;
                    if new_len > capacity {
                        capacity = new_len.next_power_of_two().max(16);
                        marks.reserve(capacity).unwrap();
                    }
                    marks.extend_to(new_len);
                    oracle.resize(new_len, 0);
                }
                2 => {
                    let index = next(oracle.len() + 2);
                    let bits = next(4) as u8; // PUSH/EOR subset only
                    let ok = marks.or_at(index, bits);
                    assert_eq!(ok, index < oracle.len());
                    if let Some(slot) = oracle.get_mut(index) {
                        *slot |= bits;
                    }
                }
                3 => {
                    let bits = next(4) as u8;
                    let ok = marks.or_back(bits);
                    assert_eq!(ok, !oracle.is_empty());
                    if let Some(slot) = oracle.back_mut() {
                        *slot |= bits;
                    }
                }
                4 => {
                    // Materialize and write arbitrary PTB/retransmitted bits.
                    let ring = marks.materialize();
                    if !oracle.is_empty() {
                        let idx = next(oracle.len());
                        let bits = (next(32) as u8) & 0x1f;
                        ring[idx] |= bits;
                        oracle[idx] |= bits;
                    }
                }
                5 => {
                    let count = next(oracle.len() + 1);
                    if count == oracle.len() && next(2) == 0 {
                        marks.clear();
                        oracle.clear();
                    } else {
                        marks.drop_prefix(count);
                        oracle.drain(..count);
                    }
                }
                _ => {
                    let new_len = next(oracle.len() + 1);
                    marks.truncate(new_len);
                    oracle.truncate(new_len);
                }
            }

            assert_eq!(marks.len(), oracle.len());
            assert!(marks.capacity() >= capacity);
            assert!(marks.iter().copied().eq(oracle.iter().copied()));
            for bit in [1u8, 2, 4, 8, 16] {
                assert_eq!(marks.last(bit), oracle.iter().rposition(|&m| m & bit != 0));
            }
            if let Some((pos, bits)) = marks.singleton() {
                assert_eq!(bits & !SINGLETON_BITS, 0);
                if bits != 0 {
                    saw_singleton_with_bits = true;
                    assert!(pos < oracle.len());
                    assert_eq!(oracle[pos], bits);
                }
                if was_materialized {
                    saw_return_to_singleton = true;
                }
            } else {
                saw_materialized = true;
                assert_eq!(marks.ring.len(), oracle.len());
            }
        }

        assert!(saw_singleton_with_bits);
        assert!(saw_materialized);
        assert!(saw_return_to_singleton);
    }
}
