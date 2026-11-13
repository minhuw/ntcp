// An endpoint's buffer memory: the bytes it charges for connection storage
// against `EndpointConfig::max_buffer_bytes`, and the memory pressure state
// Linux keeps for TCP against tcp_mem (`__sk_mem_raise_allocated`,
// `__sk_mem_reduce_allocated`).
use crate::Instant;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

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
            // ⌊2·high/3⌋ without overflow.
            pressure: pressure.unwrap_or(high / 3 * 2 + high % 3 * 2 / 3),
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

/// One budget of buffer memory for a group of endpoints, each driven on its
/// own thread: Linux's tcp_memory_allocated, tcp_memory_pressure and
/// tcp_sockets_allocated, which every CPU's sockets share
/// (`Endpoint::share_buffer_memory`). The cap and the pressure thresholds
/// are the group's, and so is pressure: one member's charge can put every
/// member under pressure, and the end of pressure wakes every member's
/// waiting writers.
///
/// Each member charges through a local reserve and publishes it to the
/// group's counter only once it reaches `batch` bytes either way, as
/// sk_memory_allocated_add and _sub do with the per-CPU
/// per_cpu_fw_alloc against net.core.mem_pcpu_rsv
/// (SK_MEMORY_PCPU_RESERVE, 1 MiB with 4 KiB pages: `DEFAULT_BATCH`). A
/// member reads the group's counter plus its own reserve, so the group's
/// charge it sees may lag the true sum by at most (members - 1) × batch,
/// and the cap may be passed by as much, as in Linux. Clones name the same
/// group.
#[derive(Clone)]
pub struct SharedBufferMemory {
    group: Arc<Group>,
}

struct Group {
    // Published bytes: the sum over members of what each charged less its
    // unpublished reserve.
    allocated: AtomicUsize,
    // The thresholds: fixed, or the sum of what each present member's
    // configuration resolves (`summed`).
    low: AtomicUsize,
    pressure: AtomicUsize,
    high: AtomicUsize,
    summed: bool,
    batch: usize,
    // Live connections of every member (tcp_sockets_allocated), for the
    // fair share under pressure.
    sockets: AtomicUsize,
    // 0 outside pressure, else its start + 1 in the members' clock; the
    // group's entries into pressure and ticks of the pressures that ended.
    pressure_since: AtomicU64,
    pressures: AtomicU64,
    pressure_ticks: AtomicU64,
    // Bumped whenever memory comes back to the group, a member's reserve
    // published downward or the end of pressure, so that members whose
    // writers wait for memory wake them (`Endpoint::poll_shared_memory`).
    returns: AtomicU64,
    owners: Box<[Owner]>,
}

struct Owner {
    taken: AtomicBool,
    // The member has writers waiting for memory: another member that
    // returns memory wakes it (`SharedBufferMemory::waiting`).
    waiting: AtomicBool,
}

impl SharedBufferMemory {
    /// Linux's default net.core.mem_pcpu_rsv, SK_MEMORY_PCPU_RESERVE: 256
    /// pages of 4 KiB.
    pub const DEFAULT_BATCH: usize = 1 << 20;

    /// A group of `owners` members (numbered from 0). With `memory` its
    /// thresholds are fixed (low < pressure ≤ high); without, they are the
    /// sums of the thresholds each present member's `EndpointConfig`
    /// resolves (`EndpointConfig::buffer_memory`), as members join and
    /// leave. `batch` is at least 1.
    pub fn new(
        owners: usize,
        memory: Option<BufferMemory>,
        batch: usize,
    ) -> Result<Self, crate::Error> {
        if owners == 0
            || batch == 0
            || memory.is_some_and(|m| m.low >= m.pressure || m.pressure > m.high)
        {
            return Err(crate::Error::InvalidArgument);
        }
        let mut list = Vec::new();
        list.try_reserve_exact(owners)
            .map_err(|_| crate::Error::NoMemory)?;
        list.resize_with(owners, || Owner {
            taken: AtomicBool::new(false),
            waiting: AtomicBool::new(false),
        });
        let memory = memory.unwrap_or(BufferMemory {
            low: 0,
            pressure: 0,
            high: 0,
        });
        Ok(Self {
            group: Arc::new(Group {
                allocated: AtomicUsize::new(0),
                low: AtomicUsize::new(memory.low),
                pressure: AtomicUsize::new(memory.pressure),
                high: AtomicUsize::new(memory.high),
                summed: memory.high == 0,
                batch,
                sockets: AtomicUsize::new(0),
                pressure_since: AtomicU64::new(0),
                pressures: AtomicU64::new(0),
                pressure_ticks: AtomicU64::new(0),
                returns: AtomicU64::new(0),
                owners: list.into_boxed_slice(),
            }),
        })
    }

    /// The bytes the members have published (each member's charge less
    /// its reserve of at most `batch`).
    pub fn buffer_bytes(&self) -> usize {
        self.group.allocated.load(Ordering::Relaxed)
    }

    /// The group's thresholds now.
    pub fn buffer_memory(&self) -> BufferMemory {
        self.group.memory()
    }

    /// Whether the group is under memory pressure.
    pub fn memory_pressure(&self) -> bool {
        self.group.pressure_since.load(Ordering::Relaxed) != 0
    }

    /// The members' live connections.
    pub fn connections(&self) -> usize {
        self.group.sockets.load(Ordering::Relaxed)
    }

    /// Whether member `owner` has writers waiting for memory, which a
    /// member that returned memory (`Endpoint::take_memory_returned`)
    /// should wake by having it drive. Read after the return.
    pub fn waiting(&self, owner: usize) -> bool {
        self.group
            .owners
            .get(owner)
            .is_some_and(|o| o.waiting.load(Ordering::SeqCst))
    }
}

impl Group {
    fn memory(&self) -> BufferMemory {
        BufferMemory {
            low: self.low.load(Ordering::Relaxed),
            pressure: self.pressure.load(Ordering::Relaxed),
            high: self.high.load(Ordering::Relaxed),
        }
    }

    // Returns that a member must look at.
    fn returned(&self) {
        self.returns.fetch_add(1, Ordering::SeqCst);
    }

    fn enter(&self, now: Instant) {
        if self
            .pressure_since
            .compare_exchange(
                0,
                now.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            self.pressures.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Whether this call ended pressure.
    fn leave(&self, now: Instant) -> bool {
        if self.pressure_since.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let since = self.pressure_since.swap(0, Ordering::Relaxed);
        if since == 0 {
            return false;
        }
        self.pressure_ticks
            .fetch_add(now.saturating_sub(since - 1), Ordering::Relaxed);
        self.returned();
        true
    }
}

// An endpoint's membership of a group.
struct Share {
    group: Arc<Group>,
    owner: usize,
    // Charged and not yet published: as per_cpu_fw_alloc, within
    // (-batch, batch).
    reserve: isize,
    // What this member added to summed thresholds.
    contributed: Option<BufferMemory>,
    // The group's `returns` this member last looked at, and whether it
    // returned memory itself since `take_returned`.
    seen: u64,
    returned: bool,
    // The owner's `waiting` flag as last stored.
    waiting: bool,
}

// The bytes an endpoint has charged and its pressure state, its own or its
// group's (`share`). Its own thresholds are the configuration's, resolved
// at each change.
pub(crate) struct Budget {
    charged: usize,
    // Live connections.
    sockets: usize,
    // When the current pressure began (Linux keeps it in
    // tcp_memory_pressure), entries into pressure, and the caller ticks of
    // the pressures that ended: the endpoint's own, unless it shares.
    pressure_since: Option<Instant>,
    pressures: u64,
    pressure_ticks: u64,
    share: Option<Share>,
}

impl Budget {
    pub(crate) fn new() -> Self {
        Self {
            charged: 0,
            sockets: 0,
            pressure_since: None,
            pressures: 0,
            pressure_ticks: 0,
            share: None,
        }
    }

    // Join `shared` as member `owner`, publishing all this endpoint
    // charged and holds open; `own` is its configuration's thresholds.
    pub(crate) fn share(
        &mut self,
        shared: &SharedBufferMemory,
        owner: usize,
        own: BufferMemory,
        now: Instant,
    ) -> Result<(), crate::Error> {
        let group = &shared.group;
        if self.share.is_some()
            || group
                .owners
                .get(owner)
                .is_none_or(|o| o.taken.swap(true, Ordering::Relaxed))
        {
            return Err(crate::Error::InvalidArgument);
        }
        let contributed = group.summed.then(|| {
            group.low.fetch_add(own.low, Ordering::Relaxed);
            group.pressure.fetch_add(own.pressure, Ordering::Relaxed);
            group.high.fetch_add(own.high, Ordering::Relaxed);
            own
        });
        group.allocated.fetch_add(self.charged, Ordering::Relaxed);
        group.sockets.fetch_add(self.sockets, Ordering::Relaxed);
        self.share = Some(Share {
            group: group.clone(),
            owner,
            reserve: 0,
            contributed,
            seen: group.returns.load(Ordering::SeqCst),
            returned: false,
            waiting: false,
        });
        // The group's pressure replaces this endpoint's own.
        self.pressure_since = None;
        let memory = self.memory(own);
        self.raise(0, now, memory);
        Ok(())
    }

    pub(crate) fn charged(&self) -> usize {
        self.charged
    }

    // The thresholds in force: the group's, or `own`.
    pub(crate) fn memory(&self, own: BufferMemory) -> BufferMemory {
        self.share
            .as_ref()
            .map_or(own, |share| share.group.memory())
    }

    // The hard cap in force: the group's, or `own`.
    pub(crate) fn high(&self, own: usize) -> usize {
        self.share
            .as_ref()
            .map_or(own, |share| share.group.high.load(Ordering::Relaxed))
    }

    // The bytes charged against the thresholds: the group's as this member
    // sees it (published plus its own reserve), or its own.
    pub(crate) fn allocated(&self) -> usize {
        match &self.share {
            Some(share) => share
                .group
                .allocated
                .load(Ordering::Relaxed)
                .saturating_add_signed(share.reserve),
            None => self.charged,
        }
    }

    // Live connections counted for the fair share: the group's, or its own.
    pub(crate) fn sockets(&self) -> usize {
        match &self.share {
            Some(share) => share.group.sockets.load(Ordering::Relaxed),
            None => self.sockets,
        }
    }

    pub(crate) fn open_socket(&mut self) {
        self.sockets += 1;
        if let Some(share) = &self.share {
            share.group.sockets.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn close_socket(&mut self) {
        self.sockets -= 1;
        if let Some(share) = &self.share {
            share.group.sockets.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn under_pressure(&self) -> bool {
        match &self.share {
            Some(share) => share.group.pressure_since.load(Ordering::Relaxed) != 0,
            None => self.pressure_since.is_some(),
        }
    }

    // Charge `bytes` more at `now`: as __sk_mem_raise_allocated, pressure
    // begins above `memory.pressure` and ends at or below `memory.low`.
    pub(crate) fn raise(&mut self, bytes: usize, now: Instant, memory: BufferMemory) {
        self.charged += bytes;
        if let Some(share) = &mut self.share {
            // sk_memory_allocated_add.
            share.reserve += bytes as isize;
            if share.reserve >= share.group.batch as isize {
                share
                    .group
                    .allocated
                    .fetch_add(share.reserve as usize, Ordering::Relaxed);
                share.reserve = 0;
            }
        }
        let allocated = self.allocated();
        if allocated > memory.pressure {
            self.enter(now);
        } else if allocated <= memory.low {
            self.leave(now);
        }
    }

    // Return `bytes` at `now`: as __sk_mem_reduce_allocated, pressure ends
    // once the charge falls to `memory.low`.
    pub(crate) fn reduce(&mut self, bytes: usize, now: Instant, memory: BufferMemory) {
        self.charged -= bytes;
        if let Some(share) = &mut self.share {
            // sk_memory_allocated_sub: a reserve this far below zero goes
            // back to the group, whose other members' writers may now fit.
            share.reserve -= bytes as isize;
            if share.reserve <= -(share.group.batch as isize) {
                share
                    .group
                    .allocated
                    .fetch_sub(share.reserve.unsigned_abs(), Ordering::Relaxed);
                share.reserve = 0;
                share.group.returned();
                share.returned = true;
            }
        }
        if self.allocated() <= memory.low {
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
        if let Some(share) = &self.share {
            share.group.enter(now);
        } else if self.pressure_since.is_none() {
            self.pressure_since = Some(now);
            self.pressures += 1;
        }
    }

    fn leave(&mut self, now: Instant) {
        if let Some(share) = &mut self.share {
            share.returned |= share.group.leave(now);
        } else if let Some(since) = self.pressure_since.take() {
            self.pressure_ticks += now.saturating_sub(since);
        }
    }

    // Entries into pressure, and the caller ticks spent in it up to `now`,
    // the current pressure included: the group's for a member, the same in
    // every member.
    pub(crate) fn pressure_totals(&self, now: Instant) -> (u64, u64) {
        let (pressures, ticks, since) = match &self.share {
            Some(share) => {
                let group = &share.group;
                let since = group.pressure_since.load(Ordering::Relaxed);
                (
                    group.pressures.load(Ordering::Relaxed),
                    group.pressure_ticks.load(Ordering::Relaxed),
                    since.checked_sub(1),
                )
            }
            None => (self.pressures, self.pressure_ticks, self.pressure_since),
        };
        (
            pressures,
            ticks + since.map_or(0, |since| now.saturating_sub(since)),
        )
    }

    // Whether memory came back to the group since the last call, from any
    // member: its waiting writers should look again. False alone.
    #[inline]
    pub(crate) fn poll_returns(&mut self) -> bool {
        let Some(share) = &mut self.share else {
            return false;
        };
        let returns = share.group.returns.load(Ordering::SeqCst);
        if returns == share.seen {
            return false;
        }
        share.seen = returns;
        true
    }

    // Whether this member returned memory to its group since the last
    // call.
    #[inline]
    pub(crate) fn take_returned(&mut self) -> bool {
        self.share
            .as_mut()
            .is_some_and(|share| core::mem::take(&mut share.returned))
    }

    // Whether this member has writers waiting for memory. Set, it is
    // followed by a look at the group's returns (`poll_returns`): a member
    // that returns memory bumps them before it reads the flag, so one of
    // the two sees the other.
    pub(crate) fn set_waiting(&mut self, waiting: bool) {
        if let Some(share) = &mut self.share
            && share.waiting != waiting
        {
            share.waiting = waiting;
            share.group.owners[share.owner]
                .waiting
                .store(waiting, Ordering::SeqCst);
        }
    }
}

impl Budget {
    // Leave the group at `now`, if a member (`Endpoint::leave_buffer_memory`,
    // and as the endpoint drops): its reserve is published, so the group's
    // counter holds its whole charge, and then the charge, its connections
    // and its thresholds go out of the group. Pressure ends if what the
    // group holds is now at most its low threshold, as
    // __sk_mem_reduce_allocated checks after a return, and the return bumps
    // the group's `returns` for the waiting members to look again. The
    // endpoint keeps its charge and connections on a budget of its own,
    // outside pressure until its next change. Whether it was a member.
    pub(crate) fn leave_group(&mut self, now: Instant) -> bool {
        let Some(share) = self.share.take() else {
            return false;
        };
        let group = &share.group;
        // The reserve published (proto_memory_pcpu_drain) and the whole
        // charge returned, in one step: what this member published goes.
        let published = self.charged.checked_add_signed(-share.reserve).unwrap();
        group.allocated.fetch_sub(published, Ordering::Relaxed);
        group.sockets.fetch_sub(self.sockets, Ordering::Relaxed);
        if let Some(own) = share.contributed {
            group.low.fetch_sub(own.low, Ordering::Relaxed);
            group.pressure.fetch_sub(own.pressure, Ordering::Relaxed);
            group.high.fetch_sub(own.high, Ordering::Relaxed);
        }
        let owner = &group.owners[share.owner];
        owner.waiting.store(false, Ordering::SeqCst);
        owner.taken.store(false, Ordering::Relaxed);
        if group.allocated.load(Ordering::Relaxed) <= group.low.load(Ordering::Relaxed) {
            group.leave(now);
        }
        group.returned();
        true
    }
}
