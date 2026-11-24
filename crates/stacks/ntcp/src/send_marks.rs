use alloc::vec::Vec;
use core::mem::size_of;

const INLINE_CAP: usize = 4;

/// Sorted, disjoint, non-adjacent half-open `[start, end)` byte intervals
/// relative to `SendBuffer::head`.
///
/// Up to `INLINE_CAP` disjoint runs are stored inline with zero heap
/// allocation, keeping common-case PMTUD/PTB feedback and retransmission
/// marking strictly allocation-free.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RangeSet {
    Inline {
        len: u8,
        items: [(u32, u32); INLINE_CAP],
    },
    Heap(Vec<(u32, u32)>),
}

impl Default for RangeSet {
    #[inline]
    fn default() -> Self {
        Self::Inline {
            len: 0,
            items: [(0, 0); INLINE_CAP],
        }
    }
}

impl RangeSet {
    #[inline]
    fn as_slice(&self) -> &[(u32, u32)] {
        match self {
            Self::Inline { len, items } => &items[..*len as usize],
            Self::Heap(v) => v.as_slice(),
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    #[inline]
    fn clear(&mut self) {
        *self = Self::default();
    }

    #[inline]
    fn storage_bytes(&self) -> usize {
        match self {
            Self::Inline { .. } => 0,
            Self::Heap(v) => v.capacity() * size_of::<(u32, u32)>(),
        }
    }

    #[cfg(debug_assertions)]
    fn debug_check(&self) {
        let s = self.as_slice();
        for w in s {
            debug_assert!(w.0 < w.1, "empty or inverted range {w:?}");
        }
        for pair in s.windows(2) {
            debug_assert!(
                pair[0].1 < pair[1].0,
                "ranges not strictly sorted/non-adjacent: {pair:?}"
            );
        }
    }

    /// Inserts `[start, end)` merging overlapping or adjacent runs.
    /// Returns the number of newly added bytes.
    fn insert(&mut self, start: u32, end: u32) -> usize {
        if start >= end {
            return 0;
        }
        let slice = self.as_slice();
        let i = slice.partition_point(|&(_, e)| e < start);
        let j = i + slice[i..].partition_point(|&(s, _)| s <= end);
        let mut already = 0usize;
        for &(s, e) in &slice[i..j] {
            already += e.min(end).saturating_sub(s.max(start)) as usize;
        }
        let added = (end - start) as usize - already;
        let merged_start = if i < j { slice[i].0.min(start) } else { start };
        let merged_end = if i < j {
            slice[j - 1].1.max(end)
        } else {
            end
        };

        if i < j {
            match self {
                Self::Inline { len, items } => {
                    let old_len = *len as usize;
                    items[i] = (merged_start, merged_end);
                    let tail = old_len - j;
                    if j > i + 1 {
                        items.copy_within(j..old_len, i + 1);
                    }
                    *len = (i + 1 + tail) as u8;
                }
                Self::Heap(v) => {
                    v[i] = (merged_start, merged_end);
                    if j > i + 1 {
                        v.drain(i + 1..j);
                    }
                }
            }
        } else {
            match self {
                Self::Inline { len, items } if (*len as usize) < INLINE_CAP => {
                    let old_len = *len as usize;
                    if i < old_len {
                        items.copy_within(i..old_len, i + 1);
                    }
                    items[i] = (merged_start, merged_end);
                    *len = (old_len + 1) as u8;
                }
                Self::Inline { len, items } => {
                    let old_len = *len as usize;
                    let mut v = Vec::with_capacity(INLINE_CAP * 2);
                    v.extend_from_slice(&items[..i]);
                    v.push((merged_start, merged_end));
                    v.extend_from_slice(&items[i..old_len]);
                    *self = Self::Heap(v);
                }
                Self::Heap(v) => {
                    v.insert(i, (merged_start, merged_end));
                }
            }
        }
        #[cfg(debug_assertions)]
        self.debug_check();
        added
    }

    /// Removes `[start, end)` from the set.
    /// Returns the number of bytes removed.
    fn remove(&mut self, start: u32, end: u32) -> usize {
        if start >= end {
            return 0;
        }
        let slice = self.as_slice();
        let i = slice.partition_point(|&(_, e)| e <= start);
        let j = i + slice[i..].partition_point(|&(s, _)| s < end);
        if i == j {
            return 0;
        }
        let mut removed = 0usize;
        for &(s, e) in &slice[i..j] {
            removed += (e.min(end) - s.max(start)) as usize;
        }
        let mut rep = [(0u32, 0u32); 2];
        let mut rep_len = 0usize;
        if slice[i].0 < start {
            rep[rep_len] = (slice[i].0, start);
            rep_len += 1;
        }
        if slice[j - 1].1 > end {
            rep[rep_len] = (end, slice[j - 1].1);
            rep_len += 1;
        }
        let old_span = j - i;
        if rep_len <= old_span {
            match self {
                Self::Inline { len, items } => {
                    let old_len = *len as usize;
                    items[i..i + rep_len].copy_from_slice(&rep[..rep_len]);
                    if j < old_len && i + rep_len != j {
                        items.copy_within(j..old_len, i + rep_len);
                    }
                    *len = (old_len - (old_span - rep_len)) as u8;
                }
                Self::Heap(v) => {
                    v[i..i + rep_len].copy_from_slice(&rep[..rep_len]);
                    if old_span > rep_len {
                        v.drain(i + rep_len..j);
                    }
                    if v.is_empty() {
                        *self = Self::default();
                    }
                }
            }
        } else {
            debug_assert_eq!(old_span, 1);
            debug_assert_eq!(rep_len, 2);
            match self {
                Self::Inline { len, items } if (*len as usize) < INLINE_CAP => {
                    let old_len = *len as usize;
                    if i + 1 < old_len {
                        items.copy_within(i + 1..old_len, i + 2);
                    }
                    items[i] = rep[0];
                    items[i + 1] = rep[1];
                    *len = (old_len + 1) as u8;
                }
                Self::Inline { len, items } => {
                    let old_len = *len as usize;
                    let mut v = Vec::with_capacity(INLINE_CAP * 2);
                    v.extend_from_slice(&items[..i]);
                    v.push(rep[0]);
                    v.push(rep[1]);
                    v.extend_from_slice(&items[i + 1..old_len]);
                    *self = Self::Heap(v);
                }
                Self::Heap(v) => {
                    v[i] = rep[0];
                    v.insert(i + 1, rep[1]);
                }
            }
        }
        #[cfg(debug_assertions)]
        self.debug_check();
        removed
    }

    /// Inserts `[start, end) \ excluded`, returning the count of newly added bytes.
    fn insert_excluding(&mut self, start: u32, end: u32, excluded: &RangeSet) -> usize {
        if start >= end {
            return 0;
        }
        let ex = excluded.as_slice();
        if ex.is_empty() {
            return self.insert(start, end);
        }
        let mut cur = start;
        let mut added = 0usize;
        let mut k = ex.partition_point(|&(_, e)| e <= start);
        while k < ex.len() && cur < end {
            let (ex_s, ex_e) = ex[k];
            if ex_s >= end {
                break;
            }
            if cur < ex_s {
                added += self.insert(cur, ex_s);
            }
            cur = ex_e.min(end);
            k += 1;
        }
        if cur < end {
            added += self.insert(cur, end);
        }
        added
    }

    fn count(&self, start: u32, end: u32) -> usize {
        if start >= end {
            return 0;
        }
        let slice = self.as_slice();
        let mut k = slice.partition_point(|&(_, e)| e <= start);
        let mut total = 0usize;
        while k < slice.len() {
            let (s, e) = slice[k];
            if s >= end {
                break;
            }
            total += (e.min(end) - s.max(start)) as usize;
            k += 1;
        }
        total
    }

    /// First contiguous marked run inside `[offset, end)`, clamped to at most
    /// `limit` bytes.
    fn next_run(&self, offset: u32, end: u32, limit: usize) -> Option<(usize, usize)> {
        if offset >= end {
            return None;
        }
        let slice = self.as_slice();
        let k = slice.partition_point(|&(_, e)| e <= offset);
        let &(s, e) = slice.get(k)?;
        if s >= end {
            return None;
        }
        let run_start = s.max(offset);
        let run_end = e.min(end);
        let len = ((run_end - run_start) as usize).min(limit);
        Some((run_start as usize, len))
    }

    #[cfg(test)]
    fn contains(&self, offset: u32) -> bool {
        let slice = self.as_slice();
        let k = slice.partition_point(|&(_, e)| e <= offset);
        slice
            .get(k)
            .is_some_and(|&(s, e)| offset >= s && offset < e)
    }

    fn drop_prefix(&mut self, count: u32) {
        if count == 0 || self.is_empty() {
            return;
        }
        match self {
            Self::Inline { len, items } => {
                let old_len = *len as usize;
                let mut dst = 0usize;
                for src in 0..old_len {
                    let (s, e) = items[src];
                    if e <= count {
                        continue;
                    }
                    items[dst] = (s.saturating_sub(count), e - count);
                    dst += 1;
                }
                *len = dst as u8;
            }
            Self::Heap(v) => {
                let first = v.partition_point(|&(_, e)| e <= count);
                if first > 0 {
                    v.drain(..first);
                }
                for (s, e) in v.iter_mut() {
                    *s = s.saturating_sub(count);
                    *e -= count;
                }
                if v.is_empty() {
                    *self = Self::default();
                }
            }
        }
        #[cfg(debug_assertions)]
        self.debug_check();
    }

    fn truncate(&mut self, limit: u32) {
        if self.is_empty() {
            return;
        }
        match self {
            Self::Inline { len, items } => {
                let old_len = *len as usize;
                let mut new_len = old_len;
                while new_len > 0 && items[new_len - 1].0 >= limit {
                    new_len -= 1;
                }
                if new_len > 0 && items[new_len - 1].1 > limit {
                    items[new_len - 1].1 = limit;
                }
                *len = new_len as u8;
            }
            Self::Heap(v) => {
                while v.last().is_some_and(|&(s, _)| s >= limit) {
                    v.pop();
                }
                if let Some((_, e)) = v.last_mut()
                    && *e > limit
                {
                    *e = limit;
                }
                if v.is_empty() {
                    *self = Self::default();
                }
            }
        }
        #[cfg(debug_assertions)]
        self.debug_check();
    }
}

/// Sparse per-range marks for Packet Too Big repair (`PTB_PENDING`, `PTB_COPY`)
/// and retransmission eligibility (`RETRANSMITTED`), relative to
/// `SendBuffer::head`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct PtbMarks {
    pending: RangeSet,
    copy: RangeSet,
    retransmitted: RangeSet,
}

#[inline]
fn clamp_range(offset: usize, count: usize, buf_len: usize) -> (u32, u32) {
    debug_assert!(buf_len <= u32::MAX as usize);
    let start = offset.min(buf_len);
    let end = start.saturating_add(count).min(buf_len);
    (start as u32, end as u32)
}

#[inline]
fn clamp_bounds(offset: usize, end: usize, buf_len: usize) -> (u32, u32) {
    debug_assert!(buf_len <= u32::MAX as usize);
    let end = end.min(buf_len);
    let start = offset.min(end);
    (start as u32, end as u32)
}

impl PtbMarks {
    pub(super) fn storage_bytes(&self) -> usize {
        self.pending.storage_bytes()
            + self.copy.storage_bytes()
            + self.retransmitted.storage_bytes()
    }

    pub(super) fn mark_ptb(&mut self, offset: usize, count: usize, buf_len: usize) -> usize {
        let (s, e) = clamp_range(offset, count, buf_len);
        self.pending.insert_excluding(s, e, &self.retransmitted)
    }

    pub(super) fn release_ptb(
        &mut self,
        offset: usize,
        count: usize,
        buf_len: usize,
    ) -> (usize, usize) {
        let (s, e) = clamp_range(offset, count, buf_len);
        (self.pending.remove(s, e), self.copy.remove(s, e))
    }

    pub(super) fn mark_ptb_copy(&mut self, offset: usize, count: usize, buf_len: usize) -> usize {
        let (s, e) = clamp_range(offset, count, buf_len);
        self.copy.insert(s, e)
    }

    pub(super) fn clear_ptb_copy(&mut self, offset: usize, count: usize, buf_len: usize) -> usize {
        let (s, e) = clamp_range(offset, count, buf_len);
        self.copy.remove(s, e)
    }

    pub(super) fn mark_retransmitted(
        &mut self,
        offset: usize,
        count: usize,
        buf_len: usize,
    ) -> usize {
        let (s, e) = clamp_range(offset, count, buf_len);
        let cleared = self.pending.remove(s, e);
        self.retransmitted.insert(s, e);
        cleared
    }

    pub(super) fn next_ptb(
        &self,
        offset: usize,
        end: usize,
        limit: usize,
        buf_len: usize,
    ) -> Option<(usize, usize)> {
        let (s, e) = clamp_bounds(offset, end, buf_len);
        self.pending.next_run(s, e, limit)
    }

    pub(super) fn next_ptb_copy(
        &self,
        offset: usize,
        end: usize,
        buf_len: usize,
    ) -> Option<(usize, usize)> {
        let (s, e) = clamp_bounds(offset, end, buf_len);
        self.copy.next_run(s, e, usize::MAX)
    }

    pub(super) fn count_ptb(&self, offset: usize, count: usize, buf_len: usize) -> usize {
        let (s, e) = clamp_range(offset, count, buf_len);
        self.pending.count(s, e)
    }

    pub(super) fn drop_prefix(&mut self, count: usize) {
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        self.pending.drop_prefix(count);
        self.copy.drop_prefix(count);
        self.retransmitted.drop_prefix(count);
    }

    pub(super) fn truncate(&mut self, len: usize) {
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        self.pending.truncate(len);
        self.copy.truncate(len);
        self.retransmitted.truncate(len);
    }

    pub(super) fn clear(&mut self) {
        self.pending.clear();
        self.copy.clear();
        self.retransmitted.clear();
    }

    #[cfg(test)]
    pub(super) fn ptb_pending(&self, offset: usize, buf_len: usize) -> bool {
        offset < buf_len && self.pending.contains(offset as u32)
    }

    #[cfg(test)]
    pub(super) fn ptb_copy(&self, offset: usize, buf_len: usize) -> bool {
        offset < buf_len && self.copy.contains(offset as u32)
    }

    #[cfg(test)]
    pub(super) fn retransmitted(&self, offset: usize, buf_len: usize) -> bool {
        offset < buf_len && self.retransmitted.contains(offset as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const PENDING: u8 = 1 << 0;
    const COPY: u8 = 1 << 1;
    const RTX: u8 = 1 << 2;

    #[test]
    fn inline_runs_allocate_zero_heap_bytes() {
        let mut marks = PtbMarks::default();
        let len = 1024;
        crate::allocation_tests::fail_after(0, || {
            // Up to 4 disjoint runs per flag without any heap allocation.
            assert_eq!(marks.mark_ptb(10, 20, len), 20);
            assert_eq!(marks.mark_ptb(50, 20, len), 20);
            assert_eq!(marks.mark_ptb(100, 20, len), 20);
            assert_eq!(marks.mark_ptb(200, 20, len), 20);
            // Adjacent / overlapping merges stay inline.
            assert_eq!(marks.mark_ptb(30, 20, len), 20);
            assert_eq!(marks.next_ptb(0, len, usize::MAX, len), Some((10, 60)));
            // Splitting when < 4 runs stays inline.
            assert_eq!(marks.release_ptb(25, 10, len), (10, 0));
            assert_eq!(marks.mark_ptb_copy(10, 15, len), 15);
            assert_eq!(marks.mark_ptb_copy(50, 15, len), 15);
            assert_eq!(marks.mark_ptb_copy(100, 15, len), 15);
            assert_eq!(marks.mark_ptb_copy(200, 15, len), 15);
            assert_eq!(marks.clear_ptb_copy(50, 15, len), 15);
            assert_eq!(marks.mark_retransmitted(10, 5, len), 5);
            assert_eq!(marks.storage_bytes(), 0);
            marks.drop_prefix(12);
            marks.truncate(150);
            marks.clear();
            assert_eq!(marks.storage_bytes(), 0);
        });
    }

    #[test]
    fn randomized_ptb_marks_match_byte_vec_oracle() {
        let mut marks = PtbMarks::default();
        let mut oracle: Vec<u8> = Vec::new();
        let mut state = 0x51a7_3c19_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };

        let mut saw_heap = false;
        let mut saw_return_to_inline = false;

        for _ in 0..5000 {
            let was_heap = marks.storage_bytes() > 0;
            let len = oracle.len();
            match next(10) {
                0 | 1 => {
                    let add = next(64);
                    if len + add <= 512 {
                        oracle.resize(len + add, 0);
                    }
                }
                2 => {
                    let off = next(len + 4);
                    let cnt = next(32);
                    let got = marks.mark_ptb(off, cnt, len);
                    let mut exp = 0;
                    let s = off.min(len);
                    let e = s.saturating_add(cnt).min(len);
                    for b in &mut oracle[s..e] {
                        if *b & (PENDING | RTX) == 0 {
                            *b |= PENDING;
                            exp += 1;
                        }
                    }
                    assert_eq!(got, exp);
                }
                3 => {
                    let off = next(len + 4);
                    let cnt = next(32);
                    let got = marks.release_ptb(off, cnt, len);
                    let (mut p, mut c) = (0, 0);
                    let s = off.min(len);
                    let e = s.saturating_add(cnt).min(len);
                    for b in &mut oracle[s..e] {
                        p += usize::from(*b & PENDING != 0);
                        c += usize::from(*b & COPY != 0);
                        *b &= !(PENDING | COPY);
                    }
                    assert_eq!(got, (p, c));
                }
                4 => {
                    let off = next(len + 4);
                    let cnt = next(32);
                    let got = marks.mark_ptb_copy(off, cnt, len);
                    let mut exp = 0;
                    let s = off.min(len);
                    let e = s.saturating_add(cnt).min(len);
                    for b in &mut oracle[s..e] {
                        exp += usize::from(*b & COPY == 0);
                        *b |= COPY;
                    }
                    assert_eq!(got, exp);
                }
                5 => {
                    let off = next(len + 4);
                    let cnt = next(32);
                    let got = marks.clear_ptb_copy(off, cnt, len);
                    let mut exp = 0;
                    let s = off.min(len);
                    let e = s.saturating_add(cnt).min(len);
                    for b in &mut oracle[s..e] {
                        exp += usize::from(*b & COPY != 0);
                        *b &= !COPY;
                    }
                    assert_eq!(got, exp);
                }
                6 => {
                    let off = next(len + 4);
                    let cnt = next(32);
                    let got = marks.mark_retransmitted(off, cnt, len);
                    let mut exp = 0;
                    let s = off.min(len);
                    let e = s.saturating_add(cnt).min(len);
                    for b in &mut oracle[s..e] {
                        exp += usize::from(*b & PENDING != 0);
                        *b = (*b & !PENDING) | RTX;
                    }
                    assert_eq!(got, exp);
                }
                7 => {
                    let count = next(len + 1);
                    if count == len && next(2) == 0 {
                        marks.clear();
                        oracle.clear();
                    } else {
                        marks.drop_prefix(count);
                        oracle.drain(..count);
                    }
                }
                8 => {
                    let new_len = next(len + 1);
                    marks.truncate(new_len);
                    oracle.truncate(new_len);
                }
                _ => {
                    // Create many disjoint runs to exercise heap spill.
                    if len >= 40 {
                        for k in 0..8 {
                            let off = k * 4;
                            let got = marks.mark_ptb(off, 2, len);
                            let mut exp = 0;
                            for b in &mut oracle[off..off + 2] {
                                if *b & (PENDING | RTX) == 0 {
                                    *b |= PENDING;
                                    exp += 1;
                                }
                            }
                            assert_eq!(got, exp);
                        }
                    }
                }
            }

            let cur_len = oracle.len();
            if marks.storage_bytes() > 0 {
                saw_heap = true;
            } else if was_heap {
                saw_return_to_inline = true;
            }

            // Exhaustive probe check on every byte.
            for i in 0..cur_len {
                assert_eq!(marks.ptb_pending(i, cur_len), oracle[i] & PENDING != 0);
                assert_eq!(marks.ptb_copy(i, cur_len), oracle[i] & COPY != 0);
                assert_eq!(marks.retransmitted(i, cur_len), oracle[i] & RTX != 0);
            }

            // Query checks.
            let q_off = next(cur_len + 4);
            let q_cnt = next(cur_len + 4);
            let q_end = next(cur_len + 4);
            let q_lim = next(32);

            let exp_count = oracle
                .get(q_off.min(cur_len)..)
                .unwrap_or(&[])
                .iter()
                .take(q_cnt)
                .filter(|&&b| b & PENDING != 0)
                .count();
            assert_eq!(marks.count_ptb(q_off, q_cnt, cur_len), exp_count);

            let oracle_next = |flag: u8, off: usize, end: usize, lim: usize| {
                let end = end.min(cur_len);
                let start = (off..end).find(|&i| oracle[i] & flag != 0)?;
                let run = oracle[start..end]
                    .iter()
                    .take(lim)
                    .take_while(|&&b| b & flag != 0)
                    .count();
                Some((start, run))
            };
            assert_eq!(
                marks.next_ptb(q_off, q_end, q_lim, cur_len),
                oracle_next(PENDING, q_off, q_end, q_lim)
            );
            assert_eq!(
                marks.next_ptb_copy(q_off, q_end, cur_len),
                oracle_next(COPY, q_off, q_end, usize::MAX)
            );
        }

        assert!(saw_heap, "oracle test should exercise heap spill");
        assert!(
            saw_return_to_inline,
            "oracle test should exercise returning from heap to inline"
        );
    }
}
