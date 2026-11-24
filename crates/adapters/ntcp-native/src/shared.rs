// One Ethernet port's IPv4 neighbor (ARP) table, shared by the Networks
// that serve the port's queues. The port has one MAC, ARP arrives on
// whichever queue it is steered to, and a next hop is one station for every
// queue: one cache answers for every member's address, learns from every
// member's input and sends one request per destination for all of them.
//
// Each member keeps a front cache of the mappings it uses, valid while the
// shared mapping epoch is the one its drive loaded and its validity time
// has not passed, so a resolved next hop costs no lock and no atomic
// read-modify-write per packet. A miss, ARP input, a confirmation the
// shared state needs, and the port's timers and control output take the
// lock. Held output stays in its member's transmit slot; the cache records
// its tag, and whichever member ends a resolution wakes the members whose
// output it held.
use crate::{Error, Instant, Result};
use ntcp_arp::{AddressKind, Arp, ArpCache, ArpLimits, ArpState, ArpTimers, Event};
use ntcp_host::{ArpCounters, Entropy, Host, Ipv4NeighborTable, NeighborHold, path::LinkId};
use std::{
    any::Any,
    fs::File,
    io::Write,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

/// Storage of one port's shared table, allocated by `SharedNeighbors::new`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedNeighborLimits {
    /// Networks that are members at once.
    pub members: usize,
    /// Dynamic and permanent entries of the port, the members' static
    /// neighbors included.
    pub entries: usize,
    /// Output attempts held while their next hop resolves. Each member
    /// reserves its output owners (`max_connections + 1`) when it joins, so
    /// this is at least their sum.
    pub held: usize,
    /// ARP replies queued for transmission.
    pub replies: usize,
}

/// The IPv4 neighbor table of one Ethernet port, shared by the Networks
/// built on it with `Network::with_shared_neighbors` (one per queue and
/// worker thread). Clones name the same table.
///
/// Every member feeds the table caller time from one clock, in the units
/// given here and from the same origin: entries, requests and replies are
/// timed by whichever member handles them, and time a member reads behind
/// another's is clamped to the latest seen. Each member's drive applies the
/// port's due timers and sends its due ARP frames on its own queue unless
/// another member holds the table, in which case it skips them; the frames
/// stay due for the next drive of any member. The bounds are the port's:
/// exhausted entries or held records are backpressure, as on a Network's
/// own table, and a member's counters of failed resolutions are the port's.
#[derive(Clone)]
pub struct SharedNeighbors {
    shared: Arc<Shared>,
}

struct Shared {
    mac: [u8; 6],
    units_per_second: u64,
    // Timer and attempt counts of the cache, in caller units.
    delay_first_probe: u64,
    table: Mutex<Table>,
    // The cache's mapping epoch and next deadline (u64::MAX: none), stored
    // after every change under the lock: members read them without it.
    generation: AtomicU64,
    deadline: AtomicU64,
    // Per member slot: one of the member's held resolutions ended, or a
    // neighbor it must report lost failed, since its last drive.
    wakes: Box<[AtomicBool]>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Tag {
    member: usize,
    hold: NeighborHold,
}

struct Table {
    // One link: the port.
    cache: ArpCache<(), Tag>,
    latest: Instant,
    members: Vec<Option<Record>>,
    // Held records reserved by the members.
    reserved: usize,
    held: usize,
    entries: usize,
}

struct Record {
    addresses: Vec<Ipv4Addr>,
    owners: usize,
    // Neighbors found unreachable that the member has not reported to its
    // Host (which ends the Redirects through them), at most one per entry.
    // Further failures before the member drives are not recorded: traffic
    // that still uses such a neighbor resolves it again, and that failure
    // is reported.
    lost: Vec<Ipv4Addr>,
    // Written when another member wakes this one; the Network's shared
    // flows may write the same descriptor.
    wake: Option<Arc<File>>,
}

impl SharedNeighbors {
    /// The table of the port whose MAC is `local_mac`, its members' caller
    /// time in `units_per_second`.
    pub fn new(
        local_mac: [u8; 6],
        units_per_second: u64,
        limits: SharedNeighborLimits,
    ) -> Result<Self> {
        if local_mac == [0; 6] || local_mac[0] & 1 != 0 {
            return Err(Error::InvalidConfig(
                "a shared neighbor table needs a unicast MAC",
            ));
        }
        if limits.members == 0 || limits.entries == 0 {
            return Err(Error::InvalidConfig(
                "a shared neighbor table needs members and entries",
            ));
        }
        let arp = |error| Error::Host(ntcp_host::Error::from(error));
        let mut cache = ArpCache::new(
            ArpLimits {
                links: 1,
                entries: limits.entries,
                held: limits.held,
                replies: limits.replies,
                addresses: limits.members,
            },
            ArpTimers::default(),
            units_per_second,
        )
        .map_err(arp)?;
        let mut entropy = crate::entropy();
        cache
            .add_link((), local_mac, &mut draw(Some(&mut entropy)))
            .map_err(arp)?;
        let mut members = Vec::new();
        members
            .try_reserve_exact(limits.members)
            .map_err(|_| Error::Capacity)?;
        members.resize_with(limits.members, || None);
        let mut wakes = Vec::new();
        wakes
            .try_reserve_exact(limits.members)
            .map_err(|_| Error::Capacity)?;
        wakes.resize_with(limits.members, || AtomicBool::new(false));
        let delay_first_probe = ArpTimers::default()
            .delay_first_probe_ms
            .saturating_mul(units_per_second)
            / 1000;
        let table = Table {
            cache,
            latest: 0,
            members,
            reserved: 0,
            held: limits.held,
            entries: limits.entries,
        };
        let shared = Shared {
            mac: local_mac,
            units_per_second,
            delay_first_probe,
            generation: AtomicU64::new(table.cache.mapping_epoch()),
            deadline: AtomicU64::new(u64::MAX),
            table: Mutex::new(table),
            wakes: wakes.into_boxed_slice(),
        };
        Ok(Self {
            shared: Arc::new(shared),
        })
    }
    pub fn local_mac(&self) -> [u8; 6] {
        self.shared.mac
    }
    pub fn units_per_second(&self) -> u64 {
        self.shared.units_per_second
    }
    /// Cumulative counters of the port's table.
    pub fn counters(&self) -> ArpCounters {
        self.shared.lock().cache.counters()
    }
    // A new member with `owners` output owners and room for `front`
    // mappings in its front cache.
    pub(crate) fn join(&self, owners: usize, front: usize) -> Result<Member> {
        let mut table = self.shared.lock();
        let index = table
            .members
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let reserved = table
            .reserved
            .checked_add(owners)
            .filter(|&n| n <= table.held)
            .ok_or(Error::Capacity)?;
        let mut lost = Vec::new();
        lost.try_reserve_exact(table.entries)
            .map_err(|_| Error::Capacity)?;
        let mut reported = Vec::new();
        reported
            .try_reserve_exact(table.entries)
            .map_err(|_| Error::Capacity)?;
        let mut cache = Vec::new();
        cache
            .try_reserve_exact(front)
            .map_err(|_| Error::Capacity)?;
        table.members[index] = Some(Record {
            addresses: Vec::new(),
            owners,
            lost,
            wake: None,
        });
        table.reserved = reserved;
        self.shared.wakes[index].store(false, Ordering::Relaxed);
        Ok(Member {
            shared: self.shared.clone(),
            index,
            link: None,
            generation: table.cache.mapping_epoch(),
            local: Arc::new(Local::default()),
            front: cache,
            reported,
        })
    }
}

impl Shared {
    // A member that panicked while holding the table does not stop the
    // port's resolution: each cache call completes its changes before it
    // returns.
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn publish(&self, table: &Table) {
        self.generation
            .store(table.cache.mapping_epoch(), Ordering::Release);
        self.deadline.store(
            table.cache.next_deadline().unwrap_or(u64::MAX),
            Ordering::Release,
        );
    }
}

impl Table {
    fn now(&mut self, now: Instant) -> Instant {
        self.latest = self.latest.max(now);
        self.latest
    }
    // Wake every member whose held resolution ended or that has a lost
    // neighbor to report; true when `me` has.
    fn notify(&self, wakes: &[AtomicBool], me: usize) -> bool {
        let mut own = false;
        let mut wake = |member: usize| {
            if member == me {
                own = true;
            } else if !wakes[member].swap(true, Ordering::Release)
                && let Some(Some(Record {
                    wake: Some(file), ..
                })) = self.members.get(member)
            {
                // An eventfd's count only grows; a descriptor that would
                // block is already readable.
                let _ = (&**file).write(&1u64.to_ne_bytes());
            }
        };
        self.cache.ended(|tag| wake(tag.member));
        for (member, record) in self.members.iter().enumerate() {
            if record.as_ref().is_some_and(|r| !r.lost.is_empty()) {
                wake(member);
            }
        }
        own
    }
    fn answered_elsewhere(&self, me: usize, address: Ipv4Addr) -> bool {
        self.members
            .iter()
            .enumerate()
            .any(|(k, r)| k != me && r.as_ref().is_some_and(|r| r.addresses.contains(&address)))
    }
    // Member `me` leaves the port: its addresses are no longer answered
    // unless another member has them, and its held records are forgotten.
    fn depart(&mut self, me: usize) {
        self.cache.release_matching(|tag| tag.member == me);
        let addresses = match &mut self.members[me] {
            Some(record) => core::mem::take(&mut record.addresses),
            None => return,
        };
        for address in addresses {
            if !self.answered_elsewhere(me, address) {
                self.cache.remove_address((), address);
            }
        }
    }
}

// Four octets of a member's entropy per draw, None when it is absent or
// fails.
fn draw(entropy: Option<&mut Entropy>) -> impl FnMut() -> Option<u32> {
    let mut entropy = entropy;
    move || {
        let entropy = entropy.as_mut()?;
        let mut bytes = [0; 4];
        entropy(&mut bytes).ok().map(|_| u32::from_be_bytes(bytes))
    }
}

fn host_error(error: ntcp_arp::Error) -> ntcp_host::Error {
    ntcp_host::Error::from(error)
}

// A mapping as the member last resolved it.
#[derive(Clone, Copy)]
struct Front {
    address: Ipv4Addr,
    mac: [u8; 6],
    state: ArpState,
    // The mapping epoch it was resolved in.
    generation: u64,
    // Until when (exclusive) resolution returns it unchanged.
    until: Instant,
}

/// One Network's membership in a shared table, installed as its Host's IPv4
/// neighbor table. Dropping it leaves the table.
pub(crate) struct Member {
    shared: Arc<Shared>,
    index: usize,
    link: Option<LinkId>,
    // The mapping epoch loaded at the start of the drive, or read later
    // under the lock.
    generation: u64,
    // Its wake to settle and its latest time, which its Network's probe
    // reads too.
    local: Arc<Local>,
    front: Vec<Front>,
    // Lost neighbors taken from the table, reported without the lock.
    reported: Vec<Ipv4Addr>,
}

// A member's own state, which its Network reaches without the Host through
// the member's probe: one thread uses it at a time, the Network's. Aligned
// apart from the other members', which their own threads write.
#[derive(Default)]
#[repr(align(128))]
struct Local {
    // A held resolution of this member ended, or it has lost neighbors to
    // report: settled once by the drive.
    woken: AtomicBool,
    // The latest caller time the member saw.
    latest: AtomicU64,
}

impl Local {
    fn woken(&self) -> bool {
        self.woken.load(Ordering::Relaxed)
    }
    fn set_woken(&self, woken: bool) {
        self.woken.store(woken, Ordering::Relaxed);
    }
    fn latest(&self) -> Instant {
        self.latest.load(Ordering::Relaxed)
    }
    // The member's time, moved to `now` when that is later.
    #[inline]
    fn advance(&self, now: Instant) -> Instant {
        let latest = self.latest().max(now);
        self.latest.store(latest, Ordering::Relaxed);
        latest
    }
}

// A Network's look at its member's wake and at the table's mapping epoch,
// without reaching the member through its Host. The member's epoch is
// always one the table published, and both only grow: while no wake waits
// and the table still publishes the epoch the member loaded when it last
// began (`began`), the member holds that epoch and `Member::begin` would
// change nothing.
pub(crate) struct Probe {
    shared: Arc<Shared>,
    local: Arc<Local>,
    index: usize,
    epoch: u64,
}

impl Probe {
    // Whether `Member::begin` would leave the member as it is: the same
    // loads, the wake's first.
    #[inline]
    pub(crate) fn current(&self) -> bool {
        !self.shared.wakes[self.index].load(Ordering::Relaxed)
            && self.shared.generation.load(Ordering::Acquire) == self.epoch
    }
    // The member began, loading `epoch`.
    pub(crate) fn began(&mut self, epoch: u64) {
        self.epoch = epoch;
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    // What `Member::housekeep` at `now`, then `Member::woken`, give when
    // the table has nothing due by the member's time: the same loads and
    // the same move of its time, then its wake to settle. None when the
    // table has work due, for the member itself.
    #[inline]
    pub(crate) fn idle(&self, now: Instant) -> Option<bool> {
        let latest = self.local.advance(now);
        (self.shared.deadline.load(Ordering::Acquire) > latest).then(|| self.local.woken())
    }
}

// The member a Network's Host resolves through, when it has one.
pub(crate) fn member(host: &mut Host) -> Option<&mut Member> {
    let table: &mut dyn Any = host.ipv4_neighbor_table_mut()?;
    table.downcast_mut()
}

impl Member {
    // The start of a drive: the one load of the mapping epoch, and this
    // member's wake.
    pub(crate) fn begin(&mut self) {
        self.generation = self.shared.generation.load(Ordering::Acquire);
        let wake = &self.shared.wakes[self.index];
        if wake.load(Ordering::Relaxed) && wake.swap(false, Ordering::Acquire) {
            self.local.set_woken(true);
        }
    }
    pub(crate) fn woken(&self) -> bool {
        self.local.woken()
    }
    // The mapping epoch the member resolves in.
    pub(crate) fn epoch(&self) -> u64 {
        self.generation
    }
    pub(crate) fn probe(&self) -> Probe {
        Probe {
            shared: self.shared.clone(),
            local: self.local.clone(),
            index: self.index,
            epoch: self.generation,
        }
    }
    pub(crate) fn settled(&mut self) {
        self.local.set_woken(false);
    }
    pub(crate) fn set_wake(&mut self, file: Arc<File>) {
        let mut table = self.shared.lock();
        if let Some(record) = &mut table.members[self.index] {
            record.wake = Some(file);
        }
    }
    // The port's timers (when `timers`) and up to `limit` due ARP frames,
    // each passed to `send` with the outcome it returns applied; frames stop
    // at the first that is not Submitted. None when nothing is due or
    // another member holds the table: this drive does not wait for it.
    pub(crate) fn housekeep(
        &mut self,
        now: Instant,
        limit: usize,
        timers: bool,
        mut send: impl FnMut(&ntcp_arp::Control<()>) -> ntcp_arp::ControlOutcome,
    ) -> Option<usize> {
        let latest = self.local.advance(now);
        if self.shared.deadline.load(Ordering::Acquire) > latest {
            return None;
        }
        let mut table = match self.shared.table.try_lock() {
            Ok(table) => table,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return None,
        };
        let now = table.now(latest);
        if timers {
            let Table { cache, members, .. } = &mut *table;
            cache.service(now, &mut |event| {
                let Event::Unreachable { address, .. } = event;
                for record in members.iter_mut().flatten() {
                    if !record.lost.contains(&address) && record.lost.len() < record.lost.capacity()
                    {
                        record.lost.push(address);
                    }
                }
            });
        }
        let mut used = 0;
        while used < limit {
            let Some((control, token)) = table.cache.next_control((), now) else {
                break;
            };
            used += 1;
            let outcome = send(&control);
            table.cache.complete(token, outcome, now);
            if outcome != ntcp_arp::ControlOutcome::Submitted {
                break;
            }
        }
        if timers && table.notify(&self.shared.wakes, self.index) {
            self.local.set_woken(true);
        }
        self.generation = table.cache.mapping_epoch();
        self.shared.publish(&table);
        Some(used)
    }

    fn check(&self, link: LinkId) -> core::result::Result<(), ntcp_host::Error> {
        if self.link == Some(link) {
            Ok(())
        } else {
            Err(ntcp_host::Error::InvalidContext)
        }
    }
    // Run `f` on the table at the clamped time, then wake whom it concerns
    // (when `notify`) and publish its epoch and deadline.
    fn locked<R>(
        &mut self,
        now: Instant,
        notify: bool,
        f: impl FnOnce(&mut Table, Instant, usize) -> R,
    ) -> R {
        let latest = self.local.advance(now);
        let mut table = self.shared.lock();
        let now = table.now(latest);
        let result = f(&mut table, now, self.index);
        if notify && table.notify(&self.shared.wakes, self.index) {
            self.local.set_woken(true);
        }
        self.generation = table.cache.mapping_epoch();
        self.shared.publish(&table);
        result
    }
    // Keep `mapping` of `address` as resolved in the current epoch; a full
    // front cache drops a mapping of an earlier epoch, else the one whose
    // validity ends first.
    fn remember(&mut self, address: Ipv4Addr, mapping: Option<ntcp_arp::Mapping>) {
        let at = self.front.iter().position(|f| f.address == address);
        let Some(mapping) = mapping else {
            if let Some(at) = at {
                self.front.swap_remove(at);
            }
            return;
        };
        let front = Front {
            address,
            mac: mapping.mac,
            state: mapping.state,
            generation: self.generation,
            until: mapping.until,
        };
        match at {
            Some(at) => self.front[at] = front,
            None if self.front.len() < self.front.capacity() => self.front.push(front),
            None => {
                let generation = self.generation;
                if let Some(victim) = self.front.iter_mut().min_by_key(|f| {
                    if f.generation == generation {
                        f.until
                    } else {
                        0
                    }
                }) {
                    *victim = front;
                }
            }
        }
    }
    // The shared table needs this confirmation to change or extend
    // reachability. A current front entry normally settles it locally.
    #[inline(never)]
    fn confirm_shared(
        &mut self,
        address: Ipv4Addr,
        carried_at: Instant,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> HostResult<bool> {
        let (confirmed, mapping) = self.locked(now, false, |table, now, _| {
            let confirmed = table
                .cache
                .confirm((), address, carried_at, now, &mut draw(entropy));
            (confirmed, table.cache.mapping((), address, now))
        });
        if confirmed.is_ok() && self.front.iter().any(|f| f.address == address) {
            self.remember(address, mapping);
        }
        confirmed.map_err(host_error)
    }

    fn usable(&self, address: Ipv4Addr, now: Instant) -> Option<&Front> {
        self.front
            .iter()
            .find(|f| f.address == address)
            .filter(|f| f.generation == self.generation && now < f.until)
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        let mut table = self.shared.lock();
        table.depart(self.index);
        if let Some(record) = table.members[self.index].take() {
            table.reserved -= record.owners;
        }
        table.notify(&self.shared.wakes, self.index);
        self.shared.publish(&table);
        self.shared.wakes[self.index].store(false, Ordering::Relaxed);
    }
}

type HostResult<T> = core::result::Result<T, ntcp_host::Error>;

impl Ipv4NeighborTable for Member {
    fn has_link(&self, link: LinkId) -> bool {
        self.link == Some(link)
    }
    // The member's port is the table's: its requests leave from the port's
    // MAC, whose ReachableTime the table drew.
    fn add_link(&mut self, link: LinkId, mac: [u8; 6], _: Option<&mut Entropy>) -> HostResult<()> {
        if self.link.is_some() {
            return Err(ntcp_host::Error::Path(ntcp_host::path::Error::Duplicate));
        }
        if mac != self.shared.mac {
            return Err(ntcp_host::Error::Unsupported);
        }
        self.link = Some(link);
        Ok(())
    }
    fn remove_link(&mut self, link: LinkId) {
        if self.link != Some(link) {
            return;
        }
        self.link = None;
        self.front.clear();
        self.locked(0, true, |table, _, me| table.depart(me));
    }
    // Members may share an address (their queues then split its flows):
    // the table answers for it while any member has it.
    fn add_local(&mut self, link: LinkId, address: Ipv4Addr) -> HostResult<()> {
        self.check(link)?;
        self.locked(0, false, |table, _, me| {
            let elsewhere = table.answered_elsewhere(me, address);
            let record = table.members[me].as_mut().unwrap();
            if record.addresses.contains(&address) {
                return Err(ntcp_host::Error::Path(ntcp_host::path::Error::Duplicate));
            }
            record
                .addresses
                .try_reserve(1)
                .map_err(|_| ntcp_host::Error::Allocation)?;
            if !elsewhere {
                table
                    .cache
                    .add_address((), address, AddressKind::Local)
                    .map_err(host_error)?;
            }
            table.members[me].as_mut().unwrap().addresses.push(address);
            Ok(())
        })
    }
    fn remove_local(&mut self, link: LinkId, address: Ipv4Addr) {
        if self.check(link).is_err() {
            return;
        }
        self.locked(0, true, |table, _, me| {
            let record = table.members[me].as_mut().unwrap();
            let Some(at) = record.addresses.iter().position(|a| *a == address) else {
                return;
            };
            record.addresses.swap_remove(at);
            if !table.answered_elsewhere(me, address) {
                table.cache.remove_address((), address);
            }
        });
    }
    fn add_permanent(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        mac: [u8; 6],
        now: Instant,
    ) -> HostResult<()> {
        self.check(link)?;
        self.locked(now, true, |table, now, _| {
            table.cache.add_permanent((), address, mac, now)
        })
        .map_err(host_error)
    }
    fn cached_resolution(&self, link: LinkId, address: Ipv4Addr, now: Instant) -> Option<[u8; 6]> {
        self.check(link).ok()?;
        self.usable(address, self.local.advance(now)).map(|f| f.mac)
    }
    fn resolve(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        now: Instant,
        held: NeighborHold,
    ) -> HostResult<Option<[u8; 6]>> {
        self.check(link)?;
        let latest = self.local.advance(now);
        if let Some(front) = self.usable(address, latest) {
            return Ok(Some(front.mac));
        }
        let (resolution, mapping) = self.locked(now, false, |table, now, member| {
            let tag = Tag { member, hold: held };
            let resolution = table.cache.resolve((), address, now, tag);
            (resolution, table.cache.mapping((), address, now))
        });
        self.remember(address, mapping);
        Ok(match resolution.map_err(host_error)? {
            ntcp_arp::Resolution::Ready(mac) => Some(mac),
            ntcp_arp::Resolution::Held => None,
        })
    }
    // Only a woken member has wakes; others take no lock.
    fn next_wake(
        &mut self,
        filter: &dyn Fn(&NeighborHold) -> bool,
    ) -> Option<(NeighborHold, bool)> {
        if !self.local.woken() {
            return None;
        }
        let me = self.index;
        let wake = self
            .shared
            .lock()
            .cache
            .next_wake(|tag| tag.member == me && filter(&tag.hold))?;
        Some(match wake {
            ntcp_arp::Wake::Retry(tag) => (tag.hold, true),
            ntcp_arp::Wake::Unreachable(tag) => (tag.hold, false),
        })
    }
    fn receive(
        &mut self,
        link: LinkId,
        arp: &Arp,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> HostResult<()> {
        self.check(link)?;
        self.locked(now, true, |table, now, _| {
            table.cache.receive((), arp, now, &mut draw(entropy))
        })
        .map_err(host_error)
    }
    // Control output leaves by `housekeep`, under one hold of the table, so
    // that no other member polls a frame before its outcome is applied.
    fn output(
        &mut self,
        _: LinkId,
        _: Instant,
        _: &mut [u8],
    ) -> HostResult<Option<([u8; 6], usize, ntcp_arp::ControlToken)>> {
        Ok(None)
    }
    fn complete(&mut self, _: ntcp_arp::ControlToken, _: ntcp_arp::ControlOutcome, _: Instant) {}
    // The port's timers run in `housekeep`; this reports the neighbors they
    // found unreachable to this member's Host.
    fn service(&mut self, _: Instant, unreachable: &mut dyn FnMut(LinkId, Ipv4Addr)) {
        let Some(link) = self.link.filter(|_| self.local.woken()) else {
            return;
        };
        {
            let mut table = self.shared.lock();
            if let Some(record) = &mut table.members[self.index] {
                self.reported.append(&mut record.lost);
            }
        }
        for address in self.reported.drain(..) {
            unreachable(link, address);
        }
    }
    // The port's next deadline; at once when this member has a wake it has
    // not settled.
    fn next_deadline(&self) -> Option<Instant> {
        let deadline = self.shared.deadline.load(Ordering::Acquire);
        let deadline = (deadline != u64::MAX).then_some(deadline);
        if self.local.woken() || self.shared.wakes[self.index].load(Ordering::Relaxed) {
            let latest = self.local.latest();
            return Some(deadline.map_or(latest, |d| d.min(latest)));
        }
        deadline
    }
    // TCP forward progress through a mapping this member resolved, REACHABLE
    // for longer than DELAY_FIRST_PROBE_TIME, changes nothing the table
    // keeps: the entry stays REACHABLE without it, and a lock per
    // acknowledgment would serialize the members. A confirmation is applied
    // under the lock when the entry is being validated (DELAY or PROBE), or
    // REACHABLE ends within DELAY_FIRST_PROBE_TIME, the window in which
    // validation waits for a confirmation before it probes: a connection
    // that makes progress at least that often keeps its entry REACHABLE,
    // at one lock per ReachableTime, and never probes.
    fn confirm(
        &mut self,
        link: LinkId,
        address: Ipv4Addr,
        carried_at: Instant,
        now: Instant,
        entropy: Option<&mut Entropy>,
    ) -> HostResult<bool> {
        self.check(link)?;
        let latest = self.local.advance(now);
        let near = self.shared.delay_first_probe;
        if let Some(front) = self.usable(address, latest) {
            match front.state {
                ArpState::Permanent => return Ok(false),
                ArpState::Reachable if latest.saturating_add(near) < front.until => {
                    return Ok(true);
                }
                _ => {}
            }
        }
        self.confirm_shared(address, carried_at, now, entropy)
    }
    fn counters(&self) -> ArpCounters {
        self.shared.lock().cache.counters()
    }
    fn entry(&self, _: LinkId, address: Ipv4Addr) -> Option<(ArpState, Option<[u8; 6]>)> {
        self.shared.lock().cache.entry((), address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, SocketAddr};
    use ntcp::{
        ActiveOpenOptions, Endpoint, EndpointConfig, ManagedOpenOptions, OutgoingIpv4Options,
        TransmitAttempt,
    };
    use ntcp_arp::Operation;
    use ntcp_host::{
        AddressState, Ipv4Receive, Ipv6Receive, NdPort, NeighborHop, Owner, ReceiveCapabilities,
        managed_limits,
        path::{ContextId, InterfaceKey, IpPrefix, NextHop, Route, ScopedAddress},
    };

    const SECOND: u64 = 1_000_000;
    const PORT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const PEER_MAC_1: [u8; 6] = [2, 0, 0, 0, 0, 0x11];
    const PEER_MAC_2: [u8; 6] = [2, 0, 0, 0, 0, 0x22];
    const STATIC_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x33];
    const LOCAL_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const LOCAL_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 100);
    const STATIC_PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 101);
    const UNKNOWN: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 200);

    fn arp_reply(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Arp {
        Arp {
            operation: Operation::Reply,
            sender_mac,
            sender_ip,
            target_mac: PORT_MAC,
            target_ip,
        }
    }

    fn receive_caps() -> ReceiveCapabilities {
        ReceiveCapabilities {
            max_ip_packet: 1500,
            ipv4: Ipv4Receive::Enabled {
                interpretation: false,
                source_routes: false,
            },
            ipv6: Ipv6Receive::Disabled,
            gro: false,
        }
    }

    fn build_host(
        context: u64,
        local_ip: Ipv4Addr,
        member: Member,
    ) -> (Host, Endpoint, EndpointConfig, LinkId, LinkId) {
        let mut cfg = EndpointConfig {
            max_connections: 2,
            ..Default::default()
        };
        cfg.connection.timebase.units_per_second = SECOND;
        let (paths, limits) = managed_limits(&cfg, 2, 2, 2, 2, 0).unwrap();
        let mut host = Host::new(
            ContextId::new(context),
            paths,
            limits,
            cfg.connection.timebase,
            [context as u8; 16],
        )
        .unwrap();
        host.set_entropy(crate::entropy());
        host.set_ipv4_neighbor_table(Box::new(member)).unwrap();
        let ctx = host
            .register_neighbor_port(InterfaceKey(1), 1500, receive_caps(), NdPort::new(PORT_MAC))
            .unwrap();
        let link = ctx.link();
        // A second link on the same host (not bound to this member) for wrong-link tests.
        let foreign = host
            .register_link(
                InterfaceKey(2),
                1500,
                receive_caps(),
                ntcp_host::Forwarding::IpNextHop,
            )
            .unwrap()
            .link();
        assert_eq!(
            host.add_neighbor_address(link, local_ip),
            Ok(AddressState::Assigned)
        );
        host.add_route(Route {
            destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop: NextHop::OnLink,
            metric: 10,
        })
        .unwrap();
        let mut endpoint = Endpoint::new(cfg.clone(), [context as u8; 32], 0, |_| true).unwrap();
        host.attach(&mut endpoint).unwrap();
        endpoint
            .enable_output_reservations_with_capacity(2)
            .unwrap();
        (host, endpoint, cfg, link, foreign)
    }

    fn open_options(cfg: &EndpointConfig) -> ManagedOpenOptions {
        ManagedOpenOptions {
            transport: ActiveOpenOptions::from(&cfg.connection),
            dscp: 0,
            ipv4_options: OutgoingIpv4Options::default(),
            registration: None,
            receive_authority: None,
        }
    }

    fn poll_attempt(endpoint: &mut Endpoint, now: Instant) -> TransmitAttempt {
        let mut tcp = [0u8; 2048];
        let (_poll, token) = endpoint.poll_reserved_transmit(now, &mut tcp, 32).unwrap();
        token.expect("pending transmit attempt")
    }

    fn member_mut(host: &mut Host) -> &mut Member {
        let table: &mut dyn Any = host.ipv4_neighbor_table_mut().unwrap();
        table.downcast_mut::<Member>().unwrap()
    }

    #[test]
    fn cached_resolution_matches_resolve_and_respects_expiry_link_and_shared_updates() {
        let shared = SharedNeighbors::new(
            PORT_MAC,
            SECOND,
            SharedNeighborLimits {
                members: 2,
                entries: 8,
                held: 16,
                replies: 4,
            },
        )
        .unwrap();

        let (mut host_a, mut ep_a, cfg_a, link_a, foreign) =
            build_host(77, LOCAL_A, shared.join(4, 4).unwrap());
        let (mut host_b, _ep_b, _cfg_b, link_b, _) =
            build_host(78, LOCAL_B, shared.join(4, 4).unwrap());

        let conn_peer = ep_a
            .connect_with_path_provider(
                0,
                SocketAddr::new(IpAddr::V4(LOCAL_A), 5000),
                SocketAddr::new(IpAddr::V4(PEER), 80),
                open_options(&cfg_a),
                &mut host_a,
            )
            .unwrap();
        let conn_static = ep_a
            .connect_with_path_provider(
                0,
                SocketAddr::new(IpAddr::V4(LOCAL_A), 5001),
                SocketAddr::new(IpAddr::V4(STATIC_PEER), 80),
                open_options(&cfg_a),
                &mut host_a,
            )
            .unwrap();

        // Unknown entry and wrong link both return None.
        assert_eq!(member_mut(&mut host_a).cached_resolution(link_a, UNKNOWN, 0), None);
        assert_eq!(member_mut(&mut host_a).cached_resolution(foreign, PEER, 0), None);

        // Select SYN to PEER and trigger ARP resolution through Host::resolve_neighbor.
        let attempt = poll_attempt(&mut ep_a, 10);
        let egress = host_a.egress_context(&mut ep_a, attempt).unwrap();
        assert_eq!(
            host_a.resolve_neighbor(egress, Owner::Tcp(conn_peer), 10),
            Ok(NeighborHop::Held)
        );
        assert_eq!(member_mut(&mut host_a).cached_resolution(link_a, PEER, 10), None);

        // Deliver ARP reply to member_a so PEER becomes REACHABLE with PEER_MAC_1.
        let reply1 = arp_reply(PEER_MAC_1, PEER, LOCAL_A);
        let mut entropy = crate::entropy();
        member_mut(&mut host_a)
            .receive(link_a, &reply1, 20, Some(&mut entropy))
            .unwrap();

        // Resolve via Host so member_a populates its front cache, then check cached_resolution
        // matches resolve without mutating ARP counters or entry state.
        assert_eq!(
            host_a.resolve_neighbor(egress, Owner::Tcp(conn_peer), 25),
            Ok(NeighborHop::Resolved(PEER_MAC_1))
        );
        let counters_before = member_mut(&mut host_a).counters();
        let entry_before = member_mut(&mut host_a).entry(link_a, PEER);
        assert_eq!(
            member_mut(&mut host_a).cached_resolution(link_a, PEER, 25),
            Some(PEER_MAC_1)
        );
        assert_eq!(member_mut(&mut host_a).counters(), counters_before);
        assert_eq!(member_mut(&mut host_a).entry(link_a, PEER), entry_before);
        assert_eq!(
            host_a.resolve_neighbor(egress, Owner::Tcp(conn_peer), 25),
            Ok(NeighborHop::Resolved(PEER_MAC_1))
        );

        // Wrong link or unknown address returns None even when the front cache is warm.
        assert_eq!(member_mut(&mut host_a).cached_resolution(foreign, PEER, 25), None);
        assert_eq!(member_mut(&mut host_a).cached_resolution(link_b, PEER, 25), None);
        assert_eq!(member_mut(&mut host_a).cached_resolution(link_a, UNKNOWN, 25), None);

        // Shared-table update from member_b changes the MAC and advances the shared epoch.
        let reply2 = arp_reply(PEER_MAC_2, PEER, LOCAL_B);
        member_mut(&mut host_b)
            .receive(link_b, &reply2, 30, Some(&mut entropy))
            .unwrap();
        // Once member_a begins its next drive, its epoch updates and stale PEER_MAC_1 is invalid.
        member_mut(&mut host_a).begin();
        member_mut(&mut host_a).settled();
        assert_eq!(member_mut(&mut host_a).cached_resolution(link_a, PEER, 30), None);
        // Resolving refreshes member_a's front cache with PEER_MAC_2.
        assert_eq!(
            host_a.resolve_neighbor(egress, Owner::Tcp(conn_peer), 35),
            Ok(NeighborHop::Resolved(PEER_MAC_2))
        );
        assert_eq!(
            member_mut(&mut host_a).cached_resolution(link_a, PEER, 35),
            Some(PEER_MAC_2)
        );

        // Expiry: once ReachableTime passes, cached_resolution returns None.
        let expiry = member_mut(&mut host_a)
            .front
            .iter()
            .find(|f| f.address == PEER)
            .expect("front entry present for PEER")
            .until;
        assert!(expiry > 35);
        assert_eq!(
            member_mut(&mut host_a).cached_resolution(link_a, PEER, expiry - 1),
            Some(PEER_MAC_2)
        );
        assert_eq!(member_mut(&mut host_a).cached_resolution(link_a, PEER, expiry), None);
        assert_eq!(
            member_mut(&mut host_a).cached_resolution(link_a, PEER, expiry + SECOND),
            None
        );

        // Reject first attempt so we can select the SYN for STATIC_PEER, then verify permanent
        // entries stay usable across arbitrarily large timestamps.
        assert!(ep_a.reject_unsubmitted(attempt).unwrap());
        host_a
            .add_static_neighbor(link_a, IpAddr::V4(STATIC_PEER), STATIC_MAC, expiry + SECOND)
            .unwrap();
        let attempt_static = poll_attempt(&mut ep_a, expiry + SECOND);
        let egress_static = {
            let e = host_a.egress_context(&mut ep_a, attempt_static).unwrap();
            if e.next_hop
                == ntcp_host::path::ResolvedNextHop::Address(
                    ScopedAddress::new(IpAddr::V4(STATIC_PEER), None).unwrap(),
                )
            {
                e
            } else {
                assert!(ep_a.reject_unsubmitted(attempt_static).unwrap());
                let _ = ep_a.abort(conn_peer);
                let a = poll_attempt(&mut ep_a, expiry + SECOND);
                host_a.egress_context(&mut ep_a, a).unwrap()
            }
        };
        assert_eq!(
            host_a.resolve_neighbor(egress_static, Owner::Tcp(conn_static), expiry + SECOND),
            Ok(NeighborHop::Resolved(STATIC_MAC))
        );
        assert_eq!(
            member_mut(&mut host_a).cached_resolution(
                link_a,
                STATIC_PEER,
                expiry + 10_000 * SECOND
            ),
            Some(STATIC_MAC)
        );
    }
}
