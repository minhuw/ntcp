//! The facts of one Endpoint lifecycle and its TCP admission deadline.
//!
//! An Endpoint that starts knows nothing of the connections and TIME-WAIT
//! records an earlier one kept on the same addresses, while their segments
//! may still be in the network. Until the deadline this module derives, the
//! Endpoint emits no TCP segment and assigns no initial sequence number,
//! timestamp offset or Fast Open cookie. The interval is 2*MSL of the
//! configured timebase, RFC 6191 Appendix A.1's figure rather than RFC 9293's
//! one MSL. Every fact is the embedding's to establish; simulated values in a
//! test model this logic only.

use crate::{CallerTimebase, Instant};

/// When TCP emission from an address ceased before the lifecycle started.
///
/// IP emission ceasing implies TCP emission ceased, so an embedding may state
/// the fact it holds about IP emission from the address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SourceContinuity {
    /// An earlier Endpoint may have emitted until the lifecycle started.
    #[default]
    Unknown,
    /// Emission ceased at least this many whole seconds before the start.
    CeasedFor(u64),
    /// Nothing was ever emitted from the address, for example one created
    /// for this lifecycle.
    Never,
}

impl SourceContinuity {
    /// The fact that leaves the longer wait: one secret and clock serve every
    /// address of an Endpoint, so its one deadline is the latest of theirs.
    pub fn latest(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Never, fact) | (fact, Self::Never) => fact,
            (Self::CeasedFor(a), Self::CeasedFor(b)) => Self::CeasedFor(a.min(b)),
        }
    }
}

/// The facts one Endpoint lifecycle starts from. The default asserts nothing
/// and waits the full interval.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lifecycle {
    /// Caller ticks since the host booted, at the lifecycle's start. Unknown
    /// counts as a boot at the start.
    pub boot_age: Option<Instant>,
    /// The latest continuity fact over the addresses the Endpoint can send
    /// from (`SourceContinuity::latest`). `Never` removes only the restart
    /// floor; host uptime alone never removes it.
    pub continuity: SourceContinuity,
}

impl Lifecycle {
    //= https://www.rfc-editor.org/rfc/rfc6191#appendix-A.1
    //= reason=Each Endpoint lifecycle has one TCP admission deadline from the configured MSL: the later of host boot + 2*MSL, from the provider's CLOCK_BOOTTIME boot age without the time namespace offset (unknown counts as a boot at the start), and the restart floor from the embedding's source continuity fact. Before it no active, passive, Fast Open or TIME-WAIT reuse factory creates a connection, no ISN, timestamp offset or cookie is assigned and no TCP segment, RST included, is emitted; host uptime alone never removes the restart floor. Core and native socket tests check refusal before and admission at the deadline; the rfc_host quiet.py namespace cases capture the wire.
    //# Firstly, as specified in [RFC0793], hosts must not establish new
    //# connections for a period of 2*MSL (Maximum Segment Lifetime) after they
    //# boot (this is the "quiet time" concept). As a result, in terms of
    //# specifications, this scenario should never occur.
    /// The later of the boot floor (host boot + 2*MSL) and the restart floor
    /// (cessation of earlier emission + 2*MSL) for a lifecycle started at
    /// `start`.
    pub fn deadline(self, start: Instant, timebase: CallerTimebase) -> Instant {
        let quiet = timebase.quiet_interval();
        let remaining = |elapsed: Instant| start.saturating_add(quiet.saturating_sub(elapsed));
        let boot = remaining(self.boot_age.unwrap_or(0));
        let restart = match self.continuity {
            SourceContinuity::Unknown => remaining(0),
            SourceContinuity::CeasedFor(seconds) => {
                remaining(seconds.saturating_mul(timebase.units_per_second))
            }
            SourceContinuity::Never => start,
        };
        boot.max(restart)
    }
}
