use core::cmp::Ordering;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Seq(pub(crate) u32);

// Half-space comparisons are deliberately undefined; callers must keep live spans below
// 2^31.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
//# Since the space is finite, all arithmetic dealing with sequence numbers must be
//# performed modulo 2^32.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
//# This unsigned arithmetic preserves the relationship of sequence numbers as they
//# cycle from 2^32 - 1 to 0 again.
impl Seq {
    pub(crate) fn serial_cmp(self, other: Self) -> Option<Ordering> {
        match self.distance_from(other) {
            0 => Some(Ordering::Equal),
            1..=0x7fff_ffff => Some(Ordering::Greater),
            0x8000_0000 => None,
            _ => Some(Ordering::Less),
        }
    }

    // False at a distance of exactly 2^31, where the order is undefined.
    pub(crate) fn after(self, other: Self) -> bool {
        self.serial_cmp(other) == Some(Ordering::Greater)
    }

    // False at a distance of exactly 2^31, where the order is undefined.
    pub(crate) fn at_or_after(self, other: Self) -> bool {
        matches!(
            self.serial_cmp(other),
            Some(Ordering::Equal | Ordering::Greater)
        )
    }

    pub(crate) fn wrapping_add(self, amount: u32) -> Self {
        Self(self.0.wrapping_add(amount))
    }

    pub(crate) fn distance_from(self, other: Self) -> u32 {
        self.0.wrapping_sub(other.0)
    }

    // Half-open sequence-position interval, not TCP segment acceptance.
    pub(crate) fn in_window(self, start: Self, len: u32) -> Option<bool> {
        if len >= 1 << 31 {
            return None;
        }
        Some(self.distance_from(start) < len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //# This unsigned arithmetic preserves the relationship of sequence numbers as they
    //# cycle from 2^32 - 1 to 0 again.
    fn serial_comparison() {
        for value in [0, 42, u32::MAX] {
            assert_eq!(Seq(value), Seq(value));
            assert_eq!(Seq(value).serial_cmp(Seq(value)), Some(Ordering::Equal));
        }
        for (before, after) in [(1, 2), (u32::MAX, 0), (0, 0x7fff_ffff)] {
            assert_eq!(Seq(before).serial_cmp(Seq(after)), Some(Ordering::Less));
            assert_eq!(Seq(after).serial_cmp(Seq(before)), Some(Ordering::Greater));
        }
        for (a, b) in [(0, 0x8000_0000), (u32::MAX, 0x7fff_ffff)] {
            assert_eq!(Seq(a).serial_cmp(Seq(b)), None);
            assert_eq!(Seq(b).serial_cmp(Seq(a)), None);
        }
    }

    #[test]
    fn after_and_at_or_after() {
        for base in [Seq(0), Seq(42), Seq(u32::MAX)] {
            assert!(!base.after(base));
            assert!(base.at_or_after(base));
            for distance in [1, 0x7fff_ffff] {
                let later = base.wrapping_add(distance);
                assert!(later.after(base));
                assert!(later.at_or_after(base));
                assert!(!base.after(later));
                assert!(!base.at_or_after(later));
            }
            // Exactly half the space apart, neither side is ahead.
            let opposite = base.wrapping_add(0x8000_0000);
            assert!(!opposite.after(base));
            assert!(!opposite.at_or_after(base));
            assert!(!base.after(opposite));
            assert!(!base.at_or_after(opposite));
            // Past half the space, the order flips.
            let beyond = base.wrapping_add(0x8000_0001);
            assert!(!beyond.after(base));
            assert!(!beyond.at_or_after(base));
            assert!(base.after(beyond));
            assert!(base.at_or_after(beyond));
        }
        // Across the u32 wrap.
        assert!(Seq(0).after(Seq(u32::MAX)));
        assert!(Seq(0).at_or_after(Seq(u32::MAX)));
        assert!(!Seq(u32::MAX).after(Seq(0)));
        assert!(!Seq(u32::MAX).at_or_after(Seq(0)));
        assert!(Seq(5).after(Seq(u32::MAX - 5)));
        assert!(!Seq(u32::MAX - 5).at_or_after(Seq(5)));
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //# Since the space is finite, all arithmetic dealing with sequence numbers must be
    //# performed modulo 2^32.
    fn addition_and_distance_wrap() {
        assert_eq!(Seq(42).wrapping_add(0), Seq(42));
        assert_eq!(Seq(42).wrapping_add(3), Seq(45));
        assert_eq!(Seq(u32::MAX).wrapping_add(2), Seq(1));
        assert_eq!(Seq(1).wrapping_add(u32::MAX), Seq(0));
        assert_eq!(Seq(42).distance_from(Seq(42)), 0);
        assert_eq!(Seq(45).distance_from(Seq(42)), 3);
        assert_eq!(Seq(1).distance_from(Seq(u32::MAX)), 2);
        assert_eq!(Seq(u32::MAX).distance_from(Seq(1)), u32::MAX - 1);
    }

    #[test]
    fn empty_and_unit_windows() {
        for start in [Seq(0), Seq(42), Seq(u32::MAX)] {
            for point in [start, start.wrapping_add(1), start.wrapping_add(u32::MAX)] {
                assert_eq!(point.in_window(start, 0), Some(false));
                assert_eq!(point.in_window(start, 1), Some(point == start));
            }
        }
    }

    #[test]
    fn wrapping_and_max_valid_window_endpoints() {
        for (start, len) in [
            (Seq(u32::MAX - 1), 4),
            (Seq(0), 0x7fff_ffff),
            (Seq(u32::MAX), 0x7fff_ffff),
        ] {
            assert_eq!(
                start.wrapping_add(u32::MAX).in_window(start, len),
                Some(false)
            );
            assert_eq!(start.in_window(start, len), Some(true));
            assert_eq!(
                start.wrapping_add(len - 1).in_window(start, len),
                Some(true)
            );
            assert_eq!(start.wrapping_add(len).in_window(start, len), Some(false));
        }
    }

    #[test]
    fn invalid_window_lengths() {
        for len in [0x8000_0000, u32::MAX] {
            for point in [Seq(0), Seq(42), Seq(u32::MAX)] {
                assert_eq!(point.in_window(Seq(42), len), None);
            }
        }
    }
}
