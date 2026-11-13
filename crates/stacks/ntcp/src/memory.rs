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

/// An endpoint's buffer memory, after Linux's sockstat and MIB counters
/// (`Endpoint::memory_counters`). The counts are cumulative from the
/// endpoint's creation and never reset.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryCounters {
    /// The bytes charged now against `max_buffer_bytes`
    /// (`Endpoint::buffer_bytes`): /proc/net/sockstat's TCP `mem`, in
    /// bytes where Linux counts pages.
    pub buffer_bytes: usize,
    /// Whether the endpoint is under memory pressure now
    /// (`Endpoint::memory_pressure`): Linux's tcp_memory_pressure.
    pub memory_pressure: bool,
    /// Entries into memory pressure: Linux's TCPMemoryPressures.
    pub memory_pressures: u64,
    /// Microseconds spent under memory pressure, the current pressure
    /// included up to the endpoint's clock. Linux's
    /// TCPMemoryPressuresChrono counts milliseconds, and only once a
    /// pressure ends.
    pub memory_pressure_us: u64,
    /// Writes that took fewer bytes than offered, or none, because memory
    /// was refused, not because the send buffer was full
    /// (`Endpoint::memory_throttled_writes`): Linux's tcp_sendmsg waiting in
    /// sk_stream_wait_memory, which no MIB counts.
    pub memory_throttled_writes: u64,
    /// Opens refused because the cap or the allocator refused their
    /// storage: connects (Connection(NoMemory)), and SYNs and Fast Open
    /// children dropped for it, which also count in `listen_drops`. Linux
    /// has no MIB for this.
    pub memory_refused_opens: u64,
    /// Storage growths refused by the cap, by memory pressure or by the
    /// allocator: at write (send ring and ledgers, shared spans) and in
    /// `set_buffer_capacities`. Linux's __sk_mem_raise_allocated
    /// suppressing an allocation, which no MIB counts.
    pub memory_refused_growths: u64,
}

// The bytes an endpoint has charged and its pressure state. The thresholds
// are the configuration's, resolved at each change.
pub(crate) struct Budget {
    charged: usize,
    // When the current pressure began (Linux keeps it in
    // tcp_memory_pressure), entries into pressure, and the caller ticks of
    // the pressures that ended.
    pressure_since: Option<Instant>,
    pressures: u64,
    pressure_ticks: u64,
}

impl Budget {
    pub(crate) fn new() -> Self {
        Self {
            charged: 0,
            pressure_since: None,
            pressures: 0,
            pressure_ticks: 0,
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
            self.leave(now);
        }
    }

    // Return `bytes` at `now`: as __sk_mem_reduce_allocated, pressure ends
    // once the charge falls to `memory.low`.
    pub(crate) fn reduce(&mut self, bytes: usize, now: Instant, memory: BufferMemory) {
        self.charged -= bytes;
        if self.charged <= memory.low {
            self.leave(now);
        }
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
            self.pressures += 1;
        }
    }

    fn leave(&mut self, now: Instant) {
        if let Some(since) = self.pressure_since.take() {
            self.pressure_ticks += now.saturating_sub(since);
        }
    }

    // Entries into pressure, and the caller ticks spent in it up to `now`,
    // the current pressure included.
    pub(crate) fn pressure_totals(&self, now: Instant) -> (u64, u64) {
        let current = self
            .pressure_since
            .map_or(0, |since| now.saturating_sub(since));
        (self.pressures, self.pressure_ticks + current)
    }
}
