use core::cmp::Ordering;

use crate::seq::Seq;

const CAPACITY: usize = 64;
const HALF_SPACE: u32 = 1 << 31;
const EMPTY: (Seq, Seq) = (Seq(0), Seq(0));

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UpdateOutcome {
    pub(crate) newly_sacked: u32,
    pub(crate) dsack: bool,
    pub(crate) overflow: bool,
}

// Advisory byte ranges only: the caller retains data until cumulative ACK and
// calls clear on RTO. All edges, including high_data and high_rxt, are exclusive.
#[derive(Clone, Debug)]
pub(crate) struct Scoreboard {
    ranges: [(Seq, Seq); CAPACITY],
    len: usize,
    ack: Seq,
}

impl Scoreboard {
    pub(crate) fn new() -> Self {
        Self {
            ranges: [EMPTY; CAPACITY],
            len: 0,
            ack: Seq(0),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn update(
        &mut self,
        ack: Seq,
        high_data: Seq,
        blocks: &[Option<(u32, u32)>; 4],
    ) -> UpdateOutcome {
        let mut outcome = UpdateOutcome::default();
        let span = high_data.distance_from(ack);
        if span >= HALF_SPACE {
            self.clear();
            self.ack = ack;
            return outcome;
        }

        // Trim before counting new delivery, even when no SACK is present.
        let mut pending = [EMPTY; CAPACITY + 4];
        let mut count = 0;
        let mut old_bytes = 0;
        for &(left, right) in &self.ranges[..self.len] {
            if right.serial_cmp(ack) != Some(Ordering::Greater) {
                continue;
            }
            let left = if left.serial_cmp(ack) == Some(Ordering::Greater) {
                left
            } else {
                ack
            };
            pending[count] = (left, right);
            count += 1;
            old_bytes += right.distance_from(left);
        }
        self.ack = ack;

        let valid = |block: Option<(u32, u32)>| -> Option<(Seq, Seq)> {
            let (left, right) = block?;
            let left = Seq(left);
            let right = Seq(right);
            let start = left.distance_from(ack);
            let end = right.distance_from(ack);
            (start < end && end <= span).then_some((left, right))
        };

        // RFC 2883: inspect the wire's FIRST block, not the sorted union.
        if let Some((left, right)) = blocks[0] {
            let left = Seq(left);
            let right = Seq(right);
            let size = right.distance_from(left);
            let below = size > 0
                && size < HALF_SPACE
                && left.serial_cmp(ack) == Some(Ordering::Less)
                && matches!(
                    right.serial_cmp(ack),
                    Some(Ordering::Less | Ordering::Equal)
                );
            let contained = match (valid(blocks[0]), valid(blocks[1])) {
                (Some((a, b)), Some((c, d))) => {
                    a.distance_from(ack) >= c.distance_from(ack)
                        && b.distance_from(ack) <= d.distance_from(ack)
                }
                _ => false,
            };
            outcome.dsack = below || contained;
        }
        for (index, &block) in blocks.iter().enumerate() {
            if index == 0 && outcome.dsack {
                continue;
            }
            if let Some(range) = valid(block) {
                pending[count] = range;
                count += 1;
            }
        }

        // Temporary room for the four incoming blocks avoids false overflow
        // when a later block joins intervals introduced by an earlier block.
        pending[..count].sort_unstable_by_key(|&(left, _)| left.distance_from(ack));
        let mut merged = 0;
        for index in 0..count {
            let (left, right) = pending[index];
            if merged > 0 && left.distance_from(ack) <= pending[merged - 1].1.distance_from(ack) {
                if right.distance_from(ack) > pending[merged - 1].1.distance_from(ack) {
                    pending[merged - 1].1 = right;
                }
            } else {
                pending[merged] = (left, right);
                merged += 1;
            }
        }
        if merged > CAPACITY {
            self.clear();
            outcome.overflow = true;
            return outcome;
        }
        self.len = merged;
        self.ranges[..merged].copy_from_slice(&pending[..merged]);
        let bytes: u32 = self.ranges[..merged]
            .iter()
            .map(|&(left, right)| right.distance_from(left))
            .sum();
        outcome.newly_sacked = bytes - old_bytes;
        outcome
    }

    pub(crate) fn is_lost(&self, seq: Seq, mss: u32) -> bool {
        if seq.distance_from(self.ack) >= HALF_SPACE {
            return false;
        }
        let above = seq.wrapping_add(1);
        let mut ranges = 0;
        let mut bytes = 0u64;
        for &(left, right) in &self.ranges[..self.len] {
            if right.serial_cmp(above) != Some(Ordering::Greater) {
                continue;
            }
            ranges += 1;
            let start = if left.serial_cmp(above) == Some(Ordering::Greater) {
                left
            } else {
                above
            };
            bytes += u64::from(right.distance_from(start));
        }
        ranges >= 3 || bytes > 2 * u64::from(mss)
    }

    // Each yielded interval is wholly unsacked, so IsLost is constant within it:
    // every byte has the same discontiguous ranges and SACKed byte count above.
    fn holes(&self, ack: Seq, high_data: Seq) -> impl Iterator<Item = (Seq, Seq)> + '_ {
        let span = high_data.distance_from(ack);
        let mut cursor = 0;
        let mut index = 0;
        core::iter::from_fn(move || {
            if span >= HALF_SPACE {
                return None;
            }
            while index < self.len {
                let (left, right) = self.ranges[index];
                index += 1;
                if right.serial_cmp(ack) != Some(Ordering::Greater) {
                    continue;
                }
                let start = if left.serial_cmp(ack) == Some(Ordering::Greater) {
                    left.distance_from(ack).min(span)
                } else {
                    0
                };
                let end = right.distance_from(ack).min(span);
                let old = cursor;
                cursor = cursor.max(end);
                if old < start {
                    return Some((ack.wrapping_add(old), ack.wrapping_add(start)));
                }
            }
            if cursor < span {
                let start = cursor;
                cursor = span;
                Some((ack.wrapping_add(start), high_data))
            } else {
                None
            }
        })
    }

    // ponytail: bounded 65-by-64 range scans; cache suffix counts if profiling warrants it.
    pub(crate) fn pipe(&self, ack: Seq, high_data: Seq, high_rxt: Seq, mss: u32) -> u32 {
        let span = high_data.distance_from(ack);
        let retransmitted = if high_rxt.serial_cmp(ack) == Some(Ordering::Greater) {
            high_rxt.distance_from(ack).min(span)
        } else {
            0
        };
        let mut pipe = 0;
        for (left, right) in self.holes(ack, high_data) {
            if !self.is_lost(left, mss) {
                pipe += right.distance_from(left);
            }
            let start = left.distance_from(ack);
            let end = right.distance_from(ack).min(retransmitted);
            pipe += end.saturating_sub(start);
        }
        pipe
    }

    pub(crate) fn lowest_hole(
        &self,
        after: Seq,
        high_data: Seq,
        mss: u32,
        lost_only: bool,
    ) -> Option<(Seq, Seq)> {
        if mss == 0 || self.len == 0 || high_data.distance_from(self.ack) >= HALF_SPACE {
            return None;
        }
        let after = match after.serial_cmp(self.ack)? {
            Ordering::Less => 0,
            _ => after.distance_from(self.ack),
        };
        let highest = self.ranges[self.len - 1].1.distance_from(self.ack);
        for (left, right) in self.holes(self.ack, high_data) {
            let start = left.distance_from(self.ack).max(after);
            let end = right.distance_from(self.ack).min(highest);
            if start < end {
                let left = self.ack.wrapping_add(start);
                if !lost_only || self.is_lost(left, mss) {
                    return Some((left, left.wrapping_add((end - start).min(mss))));
                }
            }
        }
        None
    }

    pub(crate) fn tail_hole(&self, ack: Seq, high_data: Seq, mss: u32) -> Option<(Seq, Seq)> {
        if mss == 0 {
            return None;
        }
        let (left, right) = self.holes(ack, high_data).last()?;
        Some((
            left.wrapping_add(right.distance_from(left).saturating_sub(mss)),
            right,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(s: &mut Scoreboard, ack: u32, end: u32, blocks: &[(u32, u32)]) -> UpdateOutcome {
        let mut options = [None; 4];
        for (slot, &block) in options.iter_mut().zip(blocks) {
            *slot = Some(block);
        }
        s.update(Seq(ack), Seq(end), &options)
    }

    #[test]
    fn unaligned_union_adjacency_duplicates_and_ack_trim() {
        let mut s = Scoreboard::new();
        assert_eq!(
            update(&mut s, 10, 500, &[(111, 153), (33, 79)]).newly_sacked,
            88
        );
        assert_eq!(update(&mut s, 10, 500, &[(70, 120)]).newly_sacked, 32);
        assert_eq!(s.ranges[..s.len], [(Seq(33), Seq(153))]);
        assert_eq!(update(&mut s, 10, 500, &[(153, 177)]).newly_sacked, 24);
        assert_eq!(update(&mut s, 10, 500, &[(33, 177)]).newly_sacked, 0);
        assert_eq!(update(&mut s, 100, 500, &[]).newly_sacked, 0);
        assert_eq!(s.ranges[..s.len], [(Seq(100), Seq(177))]);
        update(&mut s, 177, 500, &[]);
        assert_eq!(s.len, 0);
    }

    #[test]
    fn invalid_reversed_ambiguous_future_and_straddling_blocks() {
        let mut s = Scoreboard::new();
        for block in [
            (100, 100),
            (180, 130),
            (100, 201),
            (99, 130),
            (100, 0x8000_0064),
            (0x8000_0064, 150),
            (250, 270),
        ] {
            assert_eq!(update(&mut s, 100, 200, &[block]).newly_sacked, 0);
            assert_eq!(s.len, 0);
        }
        assert_eq!(
            update(&mut s, 100, 200, &[(170, 201), (130, 157)]).newly_sacked,
            27
        );
        assert_eq!(
            update(&mut s, 100, 0x8000_0064, &[(140, 160)]),
            UpdateOutcome::default()
        );
        assert_eq!(s.len, 0);
    }

    #[test]
    fn first_dsack_below_ack_and_contained_above_ack_before_sorting() {
        let mut s = Scoreboard::new();
        let out = update(&mut s, 100, 500, &[(50, 100), (200, 250)]);
        assert!(out.dsack);
        assert_eq!(out.newly_sacked, 50);
        let out = update(&mut s, 100, 500, &[(310, 330), (300, 350), (150, 180)]);
        assert!(out.dsack);
        assert_eq!(out.newly_sacked, 80);
        assert_eq!(
            update(&mut s, 100, 500, &[(310, 330), (300, 350)]).newly_sacked,
            0
        );
        assert!(!update(&mut s, 100, 500, &[(400, 450), (40, 70)]).dsack);
        assert!(!update(&mut s, 100, 500, &[(480, 490), (470, 510)]).dsack);
        assert!(!update(&mut s, 100, 500, &[(80, 120)]).dsack);
        let mut s = Scoreboard::new();
        // Neither a future enclosing block nor its duplicate is delivery evidence.
        let out = update(&mut s, 100, 500, &[(510, 520), (500, 530)]);
        assert_eq!(out, UpdateOutcome::default());
    }

    #[test]
    fn wrap_update_trim_dsack_and_holes() {
        let base = u32::MAX - 99;
        let mut s = Scoreboard::new();
        assert_eq!(
            update(&mut s, base, 200, &[(u32::MAX - 49, 50)]).newly_sacked,
            100
        );
        assert_eq!(
            s.lowest_hole(Seq(base), Seq(200), 30, false),
            Some((Seq(base), Seq(base + 30)))
        );
        assert_eq!(
            s.tail_hole(Seq(base), Seq(200), 30),
            Some((Seq(170), Seq(200)))
        );
        assert_eq!(s.pipe(Seq(base), Seq(200), Seq(base), 100), 200);
        assert_eq!(s.pipe(Seq(base), Seq(200), Seq(u32::MAX - 74), 100), 225);
        let out = update(&mut s, 10, 200, &[(u32::MAX - 19, 0)]);
        assert!(out.dsack);
        assert_eq!(out.newly_sacked, 0);
        assert_eq!(s.ranges[..s.len], [(Seq(10), Seq(50))]);
    }

    #[test]
    fn loss_strict_two_mss_and_three_discontiguous_ranges() {
        let mut s = Scoreboard::new();
        update(&mut s, 0, 1000, &[(100, 300)]);
        assert!(!s.is_lost(Seq(0), 100));
        update(&mut s, 0, 1000, &[(300, 301)]);
        assert!(s.is_lost(Seq(99), 100));
        assert!(!s.is_lost(Seq(100), 100)); // strictly above this byte: 200
        assert!(!s.is_lost(Seq(0), u32::MAX));
        s.clear();
        update(&mut s, 0, 1000, &[(100, 101), (200, 201), (300, 301)]);
        assert!(s.is_lost(Seq(99), 100));
        assert!(!s.is_lost(Seq(101), 100));
        update(&mut s, 0, 1000, &[(101, 200)]);
        assert_eq!(s.len, 2);
        assert!(!s.is_lost(Seq(0), 100));
    }

    #[test]
    fn pipe_counts_unsacked_only_and_splits_retransmission_at_loss_boundary() {
        let mut s = Scoreboard::new();
        update(&mut s, 0, 600, &[(100, 301), (401, 501)]);
        // Lost [0,100), not-lost [301,401) and [501,600).
        // Retransmitted [0,100) plus [301,350); SACKed bytes count zero.
        assert_eq!(s.pipe(Seq(0), Seq(600), Seq(350), 100), 348);
        assert_eq!(s.pipe(Seq(0), Seq(600), Seq(0), 100), 199);
        assert_eq!(s.pipe(Seq(0), Seq(600), Seq(600), 100), 498);
        assert_eq!(
            s.lowest_hole(Seq(23), Seq(600), 100, true),
            Some((Seq(23), Seq(100)))
        );
        assert_eq!(s.lowest_hole(Seq(100), Seq(600), 100, true), None);
        assert_eq!(
            s.lowest_hole(Seq(330), Seq(600), 100, false),
            Some((Seq(330), Seq(401)))
        );
        assert_eq!(s.lowest_hole(Seq(501), Seq(600), 100, false), None);
        assert_eq!(
            s.tail_hole(Seq(0), Seq(600), 30),
            Some((Seq(570), Seq(600)))
        );
        update(&mut s, 0, 600, &[(501, 600)]);
        assert_eq!(
            s.tail_hole(Seq(0), Seq(600), 200),
            Some((Seq(301), Seq(401)))
        );
        assert_eq!(s.tail_hole(Seq(0), Seq(600), 0), None);
        assert_eq!(s.lowest_hole(Seq(0), Seq(600), 0, false), None);
    }

    #[test]
    fn overflow_clears_without_filling_gaps_and_rto_clear() {
        let mut s = Scoreboard::new();
        for i in 0..64 {
            assert_eq!(
                update(&mut s, 0, 1000, &[(2 * i + 1, 2 * i + 2)]).newly_sacked,
                1
            );
        }
        assert_eq!(s.len, 64);
        let out = update(&mut s, 0, 1000, &[(200, 201)]);
        assert_eq!(
            out,
            UpdateOutcome {
                newly_sacked: 0,
                dsack: false,
                overflow: true
            }
        );
        assert_eq!(s.len, 0);
        assert_eq!(s.pipe(Seq(0), Seq(1000), Seq(0), 10), 1000);
        assert_eq!(s.lowest_hole(Seq(0), Seq(1000), 10, false), None);
        assert_eq!(
            s.tail_hole(Seq(0), Seq(1000), 10),
            Some((Seq(990), Seq(1000)))
        );
        update(&mut s, 0, 1000, &[(100, 200), (300, 400), (500, 600)]);
        assert!(s.is_lost(Seq(0), 100));
        s.clear();
        assert!(!s.is_lost(Seq(0), 100));
        assert_eq!(s.pipe(Seq(0), Seq(1000), Seq(0), 100), 1000);
    }

    #[test]
    fn full_scoreboard_can_accept_a_union_that_bridges_new_ranges() {
        let mut s = Scoreboard::new();
        for i in 0..64 {
            update(&mut s, 0, 1000, &[(2 * i + 1, 2 * i + 2)]);
        }
        let out = update(&mut s, 0, 1000, &[(200, 201), (120, 200)]);
        assert!(!out.dsack);
        assert!(!out.overflow);
        assert_eq!(out.newly_sacked, 77);
        assert_eq!(s.len, 60);
    }

    #[test]
    fn maximal_live_span_and_empty_queries() {
        let mut s = Scoreboard::new();
        let ack = Seq(u32::MAX - 100);
        let end = ack.wrapping_add(HALF_SPACE - 1);
        s.update(ack, end, &[None; 4]);
        assert_eq!(s.pipe(ack, end, end, 100), u32::MAX - 1);
        assert_eq!(s.tail_hole(ack, end, u32::MAX), Some((ack, end)));
        assert_eq!(s.tail_hole(ack, ack, 100), None);
        assert_eq!(s.pipe(ack, ack, ack, 100), 0);
        assert_eq!(s.tail_hole(ack, ack.wrapping_add(HALF_SPACE), 100), None);
        update(&mut s, 100, 300, &[(200, 250)]);
        assert_eq!(
            s.lowest_hole(Seq(90), Seq(300), 10, false),
            Some((Seq(100), Seq(110)))
        );
        assert_eq!(
            s.lowest_hole(Seq(100 + HALF_SPACE), Seq(300), 10, false),
            None
        );
    }

    #[test]
    fn interval_pipe_matches_byte_reference_at_unaligned_and_wrapping_edges() {
        for base in [0u32, u32::MAX - 170] {
            let seq = |offset| Seq(base).wrapping_add(offset);
            let mut s = Scoreboard::new();
            let blocks = [(17, 48), (62, 103), (119, 177), (193, 251)]
                .map(|(a, b)| Some((seq(a).0, seq(b).0)));
            s.update(seq(0), seq(300), &blocks);
            for ack in [0, 20, 62, 90, 177, 201, 251] {
                s.update(seq(ack), seq(300), &[None; 4]);
                for mss in [1, 30, 50, 100, u32::MAX] {
                    for rxt in [0, 19, 63, 150, 249, 300] {
                        let mut reference = 0;
                        for byte in ack..300 {
                            let mut above_ranges = 0;
                            let mut above_bytes = 0u64;
                            for &(a, b) in &s.ranges[..s.len] {
                                let start = a.distance_from(seq(0)).max(byte + 1);
                                let end = b.distance_from(seq(0));
                                if start < end {
                                    above_ranges += 1;
                                    above_bytes += u64::from(end - start);
                                }
                            }
                            let lost = above_ranges >= 3 || above_bytes > 2 * u64::from(mss);
                            assert_eq!(s.is_lost(seq(byte), mss), lost);
                            if !s.ranges[..s.len].iter().any(|&(a, b)| {
                                byte >= a.distance_from(seq(0)) && byte < b.distance_from(seq(0))
                            }) {
                                reference += u32::from(!lost);
                                reference += u32::from(byte < rxt);
                            }
                        }
                        assert_eq!(
                            s.pipe(seq(ack), seq(300), seq(rxt), mss),
                            reference,
                            "base={base} ack={ack} mss={mss} rxt={rxt}"
                        );
                    }
                }
            }
        }
    }
}
