extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};

use crate::seq::Seq;

#[derive(Debug)]
pub(crate) struct SendBuffer {
    // One bounded push mark per byte; ACK and truncation move marks with data.
    data: VecDeque<(u8, bool)>,
    capacity: usize,
}

impl SendBuffer {
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        let mut data = VecDeque::new();
        data.try_reserve_exact(capacity).map_err(|_| ())?;
        Ok(Self { data, capacity })
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn remaining(&self) -> usize {
        self.capacity - self.len()
    }

    pub(crate) fn write(&mut self, input: &[u8]) -> usize {
        let count = input.len().min(self.remaining());
        self.data
            .extend(input[..count].iter().map(|&byte| (byte, false)));
        count
    }

    pub(crate) fn mark_push(&mut self) {
        if let Some(last) = self.data.back_mut() {
            last.1 = true;
        }
    }

    pub(crate) fn pushed(&self, offset: usize, count: usize) -> bool {
        self.data.iter().skip(offset).take(count).any(|byte| byte.1)
    }

    pub(crate) fn collapse_push(&mut self, offset: usize, count: usize) {
        for byte in self.data.iter_mut().skip(offset).take(count) {
            byte.1 = false;
        }
        if let Some(last) = self.data.get_mut(offset + count - 1) {
            last.1 = true;
        }
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }

    // Storage only: the caller validates SEG.ACK and converts its advance into a data-byte
    // count.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //# The acknowledgment mechanism employed is cumulative so that an acknowledgment of
    //# sequence number X indicates that all octets up to but not including X have been
    //# received.
    pub(crate) fn acknowledge(&mut self, count: usize) -> Result<(), ()> {
        if count > self.len() {
            return Err(());
        }
        self.data.drain(..count);
        Ok(())
    }

    pub(crate) fn copy(&self, offset: usize, out: &mut [u8]) -> usize {
        let count = out.len().min(self.len().saturating_sub(offset));
        for (dst, src) in out[..count].iter_mut().zip(self.data.iter().skip(offset)) {
            *dst = src.0;
        }
        count
    }
}

#[derive(Debug)]
pub(crate) struct ReceiveOutcome {
    pub new_bytes: usize,
    // next() changed, including consumption of FIN.
    pub advanced: bool,
    // FIN became contiguous during this insertion, not merely accepted.
    pub fin: bool,
    // Nonempty segment starts away from the previous next(), even if rejected.
    pub out_of_order: bool,
}

#[derive(Debug)]
pub(crate) struct ReceiveBuffer {
    // Data and push marks share fixed slots; presence includes out-of-order data.
    data: Vec<(u8, bool)>,
    pushed: bool,
    present: Vec<bool>,
    read_base: Seq,
    head: usize,
    contiguous_len: usize,
    fin_sequence: Option<Seq>,
    eof: bool,
}

impl ReceiveBuffer {
    pub(crate) fn new(start: Seq, capacity: usize) -> Result<Self, ()> {
        if capacity == 0 || capacity >= 1usize << 31 {
            return Err(());
        }
        let mut data = Vec::new();
        data.try_reserve_exact(capacity).map_err(|_| ())?;
        data.resize(capacity, (0, false));
        let mut present = Vec::new();
        present.try_reserve_exact(capacity).map_err(|_| ())?;
        present.resize(capacity, false);
        Ok(Self {
            data,
            pushed: false,
            present,
            read_base: start,
            head: 0,
            contiguous_len: 0,
            fin_sequence: None,
            eof: false,
        })
    }

    pub(crate) fn reset_start(&mut self, start: Seq) -> Result<(), ()> {
        if self.fin_sequence.is_some() || self.present.iter().any(|&present| present) {
            return Err(());
        }
        self.read_base = start;
        Ok(())
    }

    // Reports the contiguous receive frontier; ACK scheduling and transmission belong to
    // the connection.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //# The acknowledgment mechanism employed is cumulative so that an acknowledgment of
    //# sequence number X indicates that all octets up to but not including X have been
    //# received.
    pub(crate) fn next(&self) -> Seq {
        self.read_base
            .wrapping_add(self.contiguous_len as u32)
            .wrapping_add(u32::from(self.eof))
    }

    pub(crate) fn right_edge(&self) -> Seq {
        self.read_base.wrapping_add(self.data.len() as u32)
    }

    pub(crate) fn readable(&self) -> usize {
        self.contiguous_len
    }

    pub(crate) fn has_data(&self) -> bool {
        self.present.iter().any(|&present| present)
    }

    pub(crate) fn take_push(&mut self) -> bool {
        core::mem::take(&mut self.pushed)
    }

    pub(crate) fn eof(&self) -> bool {
        self.eof
    }

    fn index(&self, offset: usize) -> usize {
        (self.head + offset) % self.data.len()
    }

    pub(crate) fn read(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.contiguous_len);
        for (offset, dst) in out[..count].iter_mut().enumerate() {
            let index = self.index(offset);
            *dst = self.data[index].0;
            self.present[index] = false;
        }
        self.head = self.index(count);
        self.read_base = self.read_base.wrapping_add(count as u32);
        self.contiguous_len -= count;
        count
    }

    // Retains in-capacity text and pending FIN; the connection performs state and segment
    // acceptability checks.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //# Segments with higher beginning sequence numbers SHOULD be held for later processing
    //# (SHLD-31).
    #[cfg(test)]
    pub(crate) fn insert(&mut self, sequence: Seq, payload: &[u8], fin: bool) -> ReceiveOutcome {
        self.insert_with_push(sequence, payload, fin, false)
    }

    pub(crate) fn insert_with_push(
        &mut self,
        sequence: Seq,
        payload: &[u8],
        fin: bool,
        push: bool,
    ) -> ReceiveOutcome {
        let previous_next = self.next();
        let mut outcome = ReceiveOutcome {
            new_bytes: 0,
            advanced: false,
            fin: false,
            out_of_order: (!payload.is_empty() || fin) && sequence != previous_next,
        };
        if self.eof || (payload.is_empty() && !fin) {
            return outcome;
        }

        let capacity = self.data.len();
        let data_limit = self
            .fin_sequence
            .map_or(capacity, |end| end.distance_from(self.read_base) as usize);
        for (offset, &byte) in payload.iter().enumerate() {
            let position = sequence.wrapping_add(offset as u32);
            let distance = position.distance_from(self.read_base) as usize;
            if distance >= data_limit {
                continue;
            }
            let index = self.index(distance);
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
            //# If a segment's contents straddle the boundary between old and new, only the
            //# new parts are processed.
            if !self.present[index] {
                self.data[index] = (byte, false);
                self.present[index] = true;
                outcome.new_bytes += 1;
            }
        }

        if push && !payload.is_empty() {
            let last = sequence.wrapping_add(payload.len() as u32 - 1);
            let distance = last.distance_from(self.read_base) as usize;
            // A duplicate may introduce PSH on buffered out-of-order text, but
            // never re-notify a mark already passed by the contiguous frontier.
            if distance >= self.contiguous_len && distance < data_limit {
                let index = self.index(distance);
                self.data[index].1 = true;
            }
        }

        if fin && self.fin_sequence.is_none() {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
            //# while the FIN is considered to occur after the last actual data octet in a
            //# segment in which it occurs.
            let end = sequence.wrapping_add(payload.len() as u32);
            let distance = end.distance_from(self.read_base) as usize;
            // ponytail: O(capacity) on a new FIN; track the highest occupied
            // position if this scan becomes material. Never erase accepted data.
            if distance < capacity
                && !(distance..capacity).any(|offset| self.present[self.index(offset)])
            {
                self.fin_sequence = Some(end);
            }
        }
        while self.contiguous_len < capacity && self.present[self.index(self.contiguous_len)] {
            let index = self.index(self.contiguous_len);
            self.pushed |= core::mem::take(&mut self.data[index].1);
            self.contiguous_len += 1;
        }
        // This buffer consumes FIN once after preceding data; SYN processing is in the
        // connection.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
        //# one and only one copy of the control will be acted upon
        if self.fin_sequence == Some(self.next()) {
            self.eof = true;
            outcome.fin = true;
        }
        outcome.advanced = self.next() != previous_next;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Checks prefix removal by byte count, not wire ACK validation.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //# The acknowledgment mechanism employed is cumulative so that an acknowledgment of
    //# sequence number X indicates that all octets up to but not including X have been
    //# received.
    fn send_retains_partial_copy_and_acknowledges_without_growth() {
        let mut send = SendBuffer::new(4).unwrap();
        assert_eq!(send.capacity(), 4);
        assert_eq!(send.remaining(), 4);
        assert_eq!(send.write(b"abcdef"), 4);
        assert_eq!(send.write(b"x"), 0);
        assert_eq!(send.acknowledge(5), Err(()));
        let mut out = [b'!'; 6];
        assert_eq!(send.copy(1, &mut out), 3);
        assert_eq!(&out, b"bcd!!!");
        assert_eq!(send.copy(usize::MAX, &mut out), 0);
        assert_eq!(send.len(), 4);
        assert_eq!(send.acknowledge(2), Ok(()));
        assert_eq!(send.write(b"efg"), 2);
        assert_eq!(send.copy(0, &mut out[..4]), 4);
        assert_eq!(&out[..4], b"cdef");
        assert_eq!(send.acknowledge(4), Ok(()));
        assert_eq!(send.acknowledge(0), Ok(()));
        assert_eq!(send.remaining(), 4);
        let mut empty = SendBuffer::new(0).unwrap();
        assert_eq!(empty.write(b"a"), 0);
        assert!(SendBuffer::new(usize::MAX).is_err());
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
    //= type=test
    //# If a segment's contents straddle the boundary between old and new, only the new
    //# parts are processed.
    fn wraps_trims_overlaps_and_reuses_read_credit() {
        let start = Seq(u32::MAX - 2);
        let mut recv = ReceiveBuffer::new(start, 6).unwrap();
        let result = recv.insert(start.wrapping_add(2), b"cdefgh", false);
        assert_eq!(result.new_bytes, 4);
        assert!(result.out_of_order);
        assert!(!result.advanced);
        // Out-of-order bytes are retained but unreadable until the gap is filled.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
        //= type=test
        //# Segments with higher beginning sequence numbers SHOULD be held for later
        //# processing (SHLD-31).
        assert_eq!(recv.readable(), 0);
        assert_eq!(recv.present.iter().filter(|&&p| p).count(), 4);
        let result = recv.insert(start.wrapping_add(u32::MAX), b"!abXYZ", false);
        assert_eq!(result.new_bytes, 2);
        assert!(result.advanced);
        assert_eq!(recv.next(), Seq(3));
        assert_eq!(recv.right_edge(), Seq(3));
        assert_eq!(recv.insert(start, b"XXXXXX", false).new_bytes, 0);
        assert_eq!(recv.insert(recv.right_edge(), b"g", false).new_bytes, 0);
        let mut out = [0; 8];
        assert_eq!(recv.read(&mut out[..2]), 2);
        assert_eq!(&out[..2], b"ab");
        assert_eq!(recv.next(), Seq(3));
        assert_eq!(recv.right_edge(), Seq(5));
        assert_eq!(recv.insert(Seq(3), b"ghi", false).new_bytes, 2);
        assert_eq!(recv.read(&mut out), 6);
        assert_eq!(&out[..6], b"cdefgh");
        assert_eq!(recv.read(&mut out), 0);
        assert_eq!(recv.next(), Seq(5));
        assert_eq!(recv.present.iter().filter(|&&p| p).count(), 0);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //# while the FIN is considered to occur after the last actual data octet in a segment
    //# in which it occurs.
    fn pending_fin_waits_for_gap_and_only_consumes_once() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 1), 8).unwrap();
        let pending = recv.insert(Seq(0), b"cd", true);
        assert_eq!(pending.new_bytes, 2);
        assert!(pending.out_of_order);
        assert!(!pending.fin);
        assert!(!pending.advanced);
        assert_eq!(recv.fin_sequence, Some(Seq(2)));
        assert!(!recv.insert(Seq(2), b"", true).fin);
        assert_eq!(recv.insert(Seq(2), b"ignored", false).new_bytes, 0);
        let completed = recv.insert(Seq(u32::MAX - 1), b"abXXtail", false);
        assert_eq!(completed.new_bytes, 2);
        assert!(completed.advanced && completed.fin);
        assert!(!completed.out_of_order);
        assert_eq!(recv.next(), Seq(3));
        assert!(recv.eof());
        let duplicate = recv.insert(Seq(2), b"", true);
        assert!(duplicate.out_of_order);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
        //= type=test
        //# one and only one copy of the control will be acted upon
        assert!(!duplicate.fin && !duplicate.advanced);
        assert_eq!(recv.insert(Seq(3), b"x", true).new_bytes, 0);
        let mut out = [0; 8];
        assert_eq!(recv.read(&mut out[..1]), 1);
        assert_eq!(out[0], b'a');
        assert_eq!(recv.next(), Seq(3));
        assert_eq!(recv.read(&mut out), 3);
        assert_eq!(&out[..3], b"bcd");
        assert_eq!(recv.next(), Seq(3));
        assert!(recv.eof());
        assert_eq!(recv.reset_start(Seq(100)), Err(()));
    }

    #[test]
    fn rejects_fin_conflicts_without_destroying_accepted_bytes() {
        let mut recv = ReceiveBuffer::new(Seq(10), 8).unwrap();
        recv.insert(Seq(14), b"e", false);
        for position in [9, 12, 14, 18] {
            assert!(!recv.insert(Seq(position), b"", true).fin);
            assert_eq!(recv.fin_sequence, None);
        }
        recv.insert(Seq(15), b"", true);
        assert_eq!(recv.fin_sequence, Some(Seq(15)));
        for position in [12, 16] {
            recv.insert(Seq(position), b"", true);
            assert_eq!(recv.fin_sequence, Some(Seq(15)));
        }
        let result = recv.insert(Seq(10), b"abcde", false);
        assert!(result.fin);
        assert_eq!(recv.next(), Seq(16));
        let mut out = [0; 6];
        assert_eq!(recv.read(&mut out), 5);
        assert_eq!(&out[..5], b"abcde");

        let mut recv = ReceiveBuffer::new(Seq(0), 4).unwrap();
        recv.insert(Seq(0), b"abcd", true); // FIN at right edge is excluded.
        assert_eq!(recv.fin_sequence, None);
        assert!(!recv.insert(Seq(2), b"", true).fin);
        assert_eq!(recv.read(&mut out[..1]), 1);
        let result = recv.insert(Seq(4), b"", true);
        assert!(result.fin && result.advanced);
        assert_eq!(recv.readable(), 3);
    }

    #[test]
    fn reading_preserves_out_of_order_data_and_pending_fin() {
        let mut recv = ReceiveBuffer::new(Seq(10), 6).unwrap();
        recv.insert(Seq(14), b"e", true);
        recv.insert(Seq(10), b"ab", false);
        let mut out = [0; 6];
        assert_eq!(recv.read(&mut out), 2);
        assert_eq!(&out[..2], b"ab");
        assert_eq!(recv.next(), Seq(12));
        assert_eq!(recv.right_edge(), Seq(18));
        assert_eq!(recv.insert(Seq(15), b"xyz", false).new_bytes, 0);
        let completed = recv.insert(Seq(12), b"cd", false);
        assert!(completed.fin && completed.advanced);
        assert_eq!(recv.read(&mut out), 3);
        assert_eq!(&out[..3], b"cde");
        assert_eq!(recv.next(), Seq(16));
    }

    #[test]
    fn adversarial_gaps_have_fixed_storage() {
        let mut recv = ReceiveBuffer::new(Seq(0), 64).unwrap();
        let data_storage = (recv.data.as_ptr(), recv.data.capacity());
        let presence_storage = (recv.present.as_ptr(), recv.present.capacity());
        for offset in (1..64).step_by(2) {
            assert_eq!(
                recv.insert(Seq(offset), &[offset as u8], false).new_bytes,
                1
            );
        }
        assert_eq!(recv.readable(), 0);
        assert_eq!(recv.present.iter().filter(|&&p| p).count(), 32);
        for offset in (0..64).step_by(2) {
            assert_eq!(
                recv.insert(Seq(offset), &[offset as u8], false).new_bytes,
                1
            );
        }
        assert_eq!(recv.readable(), 64);
        assert_eq!(recv.present.iter().filter(|&&p| p).count(), 64);
        let mut out = [0; 64];
        assert_eq!(recv.read(&mut out), 64);
        for (offset, &byte) in out.iter().enumerate() {
            assert_eq!(byte, offset as u8);
        }
        assert_eq!((recv.data.as_ptr(), recv.data.capacity()), data_storage);
        assert_eq!(
            (recv.present.as_ptr(), recv.present.capacity()),
            presence_storage
        );
    }

    #[test]
    fn empty_reset_and_outcome_flags() {
        assert!(ReceiveBuffer::new(Seq(0), 0).is_err());
        assert!(ReceiveBuffer::new(Seq(0), 1usize << 31).is_err());
        assert!(ReceiveBuffer::new(Seq(0), usize::MAX).is_err());
        let mut recv = ReceiveBuffer::new(Seq(0), 2).unwrap();
        assert_eq!(recv.reset_start(Seq(10)), Ok(()));
        let result = recv.insert(Seq(42), b"", false);
        assert_eq!(result.new_bytes, 0);
        assert!(!result.advanced && !result.fin && !result.out_of_order);
        assert_eq!(recv.next(), Seq(10));
        let rejected = recv.insert(Seq(42), b"x", false);
        assert!(rejected.out_of_order);
        assert_eq!(rejected.new_bytes, 0);
        recv.insert(Seq(11), b"b", false);
        assert_eq!(recv.reset_start(Seq(20)), Err(()));
        recv.insert(Seq(10), b"a", false);
        assert_eq!(recv.reset_start(Seq(20)), Err(()));
        assert_eq!(recv.read(&mut []), 0);
        assert_eq!(recv.read(&mut [0; 2]), 2);
        assert_eq!(recv.reset_start(Seq(20)), Ok(()));
        assert_eq!(recv.next(), Seq(20));
        recv.insert(Seq(21), b"", true);
        assert_eq!(recv.reset_start(Seq(30)), Err(()));

        let mut recv = ReceiveBuffer::new(Seq(7), 1).unwrap();
        let result = recv.insert(Seq(7), b"", true);
        assert!(result.fin && result.advanced);
        assert!(!result.out_of_order);
        assert_eq!(recv.next(), Seq(8));
        assert_eq!(recv.read(&mut [0]), 0);
    }
    #[test]
    fn push_marks_remain_bounded_across_gaps_overlaps_and_slot_reuse() {
        let mut recv = ReceiveBuffer::new(Seq(u32::MAX - 1), 64).unwrap();
        let storage = (recv.data.as_ptr(), recv.data.capacity());
        for cycle in 0..3 {
            let start = recv.next();
            for offset in (1..64).step_by(2) {
                recv.insert_with_push(start.wrapping_add(offset), b"x", false, true);
                assert!(!recv.take_push());
            }
            for offset in (0..64).step_by(2) {
                recv.insert_with_push(start.wrapping_add(offset), b"y", false, false);
                assert!(recv.take_push());
            }
            assert!(!recv.take_push());
            assert_eq!(recv.read(&mut [0; 64]), 64);
            assert_eq!(
                (recv.data.as_ptr(), recv.data.capacity()),
                storage,
                "cycle {cycle}"
            );
        }
        let start = recv.next();
        recv.insert_with_push(start.wrapping_add(3), b"d", false, false);
        recv.insert_with_push(start.wrapping_add(2), b"cd", false, true);
        assert!(!recv.take_push()); // New c carries a mark ending on already queued d.
        recv.insert_with_push(start, b"ab", false, false);
        assert!(recv.take_push());
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.3
    //= type=test
    //# A TCP receiver MAY pass a received PSH bit to the application layer via
    //# the PUSH flag in the interface (MAY-17), but it is not required
    fn duplicate_out_of_order_text_can_introduce_push() {
        for start in [Seq(100), Seq(u32::MAX - 3)] {
            let mut recv = ReceiveBuffer::new(start, 8).unwrap();
            let storage = (recv.data.as_ptr(), recv.data.capacity());
            recv.insert_with_push(start.wrapping_add(4), b"efgh", false, false);
            let duplicate = recv.insert_with_push(start.wrapping_add(4), b"efgh", false, true);
            assert_eq!(duplicate.new_bytes, 0);
            assert!(!recv.take_push());
            recv.insert_with_push(start, b"abcd", false, false);
            assert!(recv.take_push());
            assert!(!recv.take_push());
            recv.insert_with_push(start.wrapping_add(4), b"efgh", false, true);
            assert!(!recv.take_push()); // Already contiguous, even before read.
            let mut out = [0; 8];
            assert_eq!(recv.read(&mut out), 8);
            assert_eq!(&out, b"abcdefgh");
            recv.insert_with_push(start.wrapping_add(4), b"efgh", false, true);
            recv.insert_with_push(recv.next(), b"", false, true);
            assert!(!recv.take_push());
            assert_eq!((recv.data.as_ptr(), recv.data.capacity()), storage);
        }
    }

    #[test]
    fn duplicate_push_ignores_trimmed_endpoints_and_preserves_fin_conflicts() {
        let mut recv = ReceiveBuffer::new(Seq(100), 8).unwrap();
        recv.insert(Seq(104), b"efgh", false);
        recv.insert_with_push(Seq(104), b"efghi", false, true);
        recv.insert_with_push(Seq(106), b"", true, true); // FIN conflicts with gh.
        assert_eq!(recv.fin_sequence, None);
        recv.insert(Seq(100), b"abcd", false);
        assert!(!recv.take_push());
        assert_eq!(recv.read(&mut [0; 8]), 8);

        let mut recv = ReceiveBuffer::new(Seq(100), 8).unwrap();
        recv.insert(Seq(104), b"ef", true); // Pending FIN at 106.
        recv.insert_with_push(Seq(104), b"efgh", false, true);
        assert_eq!(recv.fin_sequence, Some(Seq(106)));
        recv.insert(Seq(100), b"abcd", false);
        assert!(!recv.take_push()); // Endpoint beyond FIN was trimmed.
        assert!(recv.eof());
        assert_eq!(recv.read(&mut [0; 8]), 6);
    }
}
