// An endpoint's buffer memory: the bytes it charges for connection storage
// against `EndpointConfig::max_buffer_bytes`, and the memory pressure state
// Linux keeps for TCP against tcp_mem (`__sk_mem_raise_allocated`,
// `__sk_mem_reduce_allocated`).
use crate::Instant;
use core::fmt;

/// An endpoint's buffer memory thresholds in bytes, Linux's tcp_mem
/// (`net.ipv4.tcp_mem`, in pages there): `low` (tcp_mem[0]), `pressure`
/// (tcp_mem[1]) and `high` (tcp_mem[2], the hard cap,
/// `EndpointConfig::max_buffer_bytes`). Pressure begins once the charge
/// exceeds `pressure` and ends once it is at most `low`.
/// `EndpointConfig::buffer_memory` resolves them. Displays as
/// `"low pressure high"`, as the sysctl prints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferMemory {
    pub low: usize,
    pub pressure: usize,
    pub high: usize,
}

impl BufferMemory {
    // ⌊high·2/3⌋ and ⌊high/2⌋: Linux's tcp_init_mem ratios, tcp_mem[1] =
    // limit and tcp_mem[0] = ¾·limit under tcp_mem[2] = 1½·limit.
    pub(crate) fn resolve(high: usize, pressure: Option<usize>, low: Option<usize>) -> Self {
        Self {
            low: low.unwrap_or(high / 2),
            pressure: pressure.unwrap_or((high as u128 * 2 / 3) as usize),
            high,
        }
    }
}

impl fmt::Display for BufferMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.low, self.pressure, self.high)
    }
}

// The bytes an endpoint has charged and its pressure state. The thresholds
// are the configuration's, resolved at each change.
pub(crate) struct Budget {
    charged: usize,
    // When the current pressure began (Linux keeps it in
    // tcp_memory_pressure).
    pressure_since: Option<Instant>,
}

impl Budget {
    pub(crate) fn new() -> Self {
        Self {
            charged: 0,
            pressure_since: None,
        }
    }

    pub(crate) fn charged(&self) -> usize {
        self.charged
    }

    pub(crate) fn under_pressure(&self) -> bool {
        self.pressure_since.is_some()
    }

    // Charge `bytes` more at `now`: as __sk_mem_raise_allocated, pressure
    // begins above `memory.pressure` and ends at or below `memory.low`.
    pub(crate) fn raise(&mut self, bytes: usize, now: Instant, memory: BufferMemory) {
        self.charged += bytes;
        if self.charged > memory.pressure {
            self.enter(now);
        } else if self.charged <= memory.low {
            self.leave();
        }
    }

    // Return `bytes`; whether pressure ended, as __sk_mem_reduce_allocated
    // leaves it once the charge falls to `memory.low`.
    pub(crate) fn reduce(&mut self, bytes: usize, memory: BufferMemory) -> bool {
        self.charged -= bytes;
        self.charged <= memory.low && self.leave()
    }

    // An allocation tried would have brought the charge to `total`: past
    // `memory.pressure` it enters pressure whether or not it is refused, as
    // __sk_mem_raise_allocated adds before it checks.
    pub(crate) fn attempted(&mut self, total: usize, now: Instant, memory: BufferMemory) {
        if total > memory.pressure {
            self.enter(now);
        }
    }

    fn enter(&mut self, now: Instant) {
        if self.pressure_since.is_none() {
            self.pressure_since = Some(now);
        }
    }

    fn leave(&mut self) -> bool {
        self.pressure_since.take().is_some()
    }
}
