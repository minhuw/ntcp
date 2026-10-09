use core::net::IpAddr;

// Host-owned routing-domain service. Handles must not cross service instances or
// lifetimes. No route lookup, packet authentication, transport state or allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathKey {
    pub local: IpAddr,
    pub remote: IpAddr,
    pub interface: u64,
    pub route_generation: u64,
    pub traffic_class: u8,
}

impl PathKey {
    pub fn new(
        local: IpAddr,
        remote: IpAddr,
        interface: u64,
        route_generation: u64,
        traffic_class: u8,
    ) -> Result<Self, Error> {
        let key = Self {
            local,
            remote,
            interface,
            route_generation,
            traffic_class,
        };
        key.floor()?;
        Ok(key)
    }

    // RFC1191 6.2 keys by TOS; RFC3168 5 assigns low bits to ECN. Retain
    // all eight bits, conservatively isolating ECN rather than assuming the
    // host routes identically. Host supplies the actual transmitted class.
    fn floor(self) -> Result<u32, Error> {
        match (self.local, self.remote) {
            (IpAddr::V4(_), IpAddr::V4(_)) => Ok(68),
            (IpAddr::V6(_), IpAddr::V6(_)) => Ok(1280),
            _ => Err(Error::Family),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4Df {
    Set,
    Clear,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    pub enabled: bool,
    pub mtu: Option<u32>,
    // Caller clock ticks; None means infinity. No built-in wall-clock unit.
    pub aging: Option<u64>,
    // Metadata only: this service does not change codec fragmentation behavior.
    pub ipv4_df: Ipv4Df,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: true,
            mtu: None,
            aging: None,
            ipv4_df: Ipv4Df::Set,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Family,
    InvalidMtu,
    InvalidPolicy,
    Capacity,
    ConfigurationConflict,
    StaleContext,
    PathMismatch,
    ClockWentBackwards,
    TimeOverflow,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathHandle(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathContext {
    handle: PathHandle,
    key: PathKey,
    // Drops survive cache updates, but not explicit configuration replacement.
    epoch: u64,
    // Upward evidence must also postdate every accepted drop/probe.
    revision: u64,
}

impl PathContext {
    pub fn handle(self) -> PathHandle {
        self.handle
    }
    pub fn key(self) -> PathKey {
        self.key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub context: PathContext,
    pub local_mtu: u32,
    pub mtu: u32,
    pub policy: Policy,
    pub revalidation_needed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeReason {
    Decreased,
    Policy,
    FirstHop,
    ProbeConfirmed,
    Revalidation,
    Invalidated,
}

// Neutral path notification; never implies any particular transport packet loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Change {
    pub before: Snapshot,
    pub after: Option<Snapshot>,
    pub reason: ChangeReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketDrop {
    pub context: PathContext,
    // Opaque host departure token, NOT a TCP sequence number.
    pub packet_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropOutcome {
    pub change: Option<Change>,
    pub dropped: PacketDrop,
}

#[derive(Clone, Copy, Debug)]
pub struct HostValidatedDrop {
    context: PathContext,
    quoted_path: PathKey,
    packet_id: u64,
    candidate_mtu: u32,
}

impl HostValidatedDrop {
    // TRUST BOUNDARY: caller attests live departure/drop validation, including
    // quoted size and path. A raw ICMP/UDP quote is NOT sufficient. This is not
    // a cryptographic capability: service checks context, host authenticates.
    // Resolve legacy IPv4 zero-MTU plateaus before calling; no per-flow bounds.
    pub fn new(
        context: PathContext,
        quoted_path: PathKey,
        packet_id: u64,
        candidate_mtu: u32,
    ) -> Self {
        Self {
            context,
            quoted_path,
            packet_id,
            candidate_mtu,
        }
    }
}

#[derive(Clone, Copy)]
struct Entry {
    snapshot: Snapshot,
    deadline: Option<u64>,
}

pub struct PathMtuService<const N: usize> {
    entries: [Option<Entry>; N],
    serial: u64,
    now: u64,
}

impl<const N: usize> Default for PathMtuService<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PathMtuService<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            serial: 0,
            now: 0,
        }
    }

    fn time(&self, now: u64, aging: Option<u64>) -> Result<Option<u64>, Error> {
        if now < self.now {
            return Err(Error::ClockWentBackwards);
        }
        aging
            .map(|duration| now.checked_add(duration).ok_or(Error::TimeOverflow))
            .transpose()
    }

    fn next_serial(&self) -> Result<u64, Error> {
        self.serial.checked_add(1).ok_or(Error::GenerationExhausted)
    }

    fn cap(key: PathKey, local_mtu: u32, policy: Policy) -> Result<u32, Error> {
        let floor = key.floor()?;
        if local_mtu < floor || policy.mtu.is_some_and(|mtu| mtu < floor) {
            return Err(Error::InvalidMtu);
        }
        if key.local.is_ipv4() && policy.enabled && policy.ipv4_df != Ipv4Df::Set {
            return Err(Error::InvalidPolicy);
        }
        let cap = local_mtu.min(policy.mtu.unwrap_or(local_mtu));
        Ok(if key.local.is_ipv6() && !policy.enabled {
            1280
        } else {
            cap
        })
    }

    // ponytail: bounded linear lookup; replace with a fixed-capacity index only
    // if large host-selected capacities make scans measurable.
    fn index(&self, handle: PathHandle) -> Result<usize, Error> {
        self.entries
            .iter()
            .position(|e| e.is_some_and(|e| e.snapshot.context.handle == handle))
            .ok_or(Error::StaleContext)
    }

    fn context_index(&self, context: PathContext) -> Result<usize, Error> {
        let i = self.index(context.handle)?;
        let current = self.entries[i].unwrap().snapshot.context;
        if current.key != context.key || current.epoch != context.epoch {
            return Err(Error::StaleContext);
        }
        Ok(i)
    }

    pub fn register(
        &mut self,
        key: PathKey,
        local_mtu: u32,
        policy: Policy,
        now: u64,
    ) -> Result<PathHandle, Error> {
        let mtu = Self::cap(key, local_mtu, policy)?;
        let deadline = self.time(now, policy.aging)?;
        if let Some(e) = self
            .entries
            .iter()
            .flatten()
            .find(|e| e.snapshot.context.key == key)
        {
            if e.snapshot.local_mtu != local_mtu || e.snapshot.policy != policy {
                return Err(Error::ConfigurationConflict);
            }
            self.now = now;
            return Ok(e.snapshot.context.handle);
        }
        let i = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let serial = self.next_serial()?;
        let handle = PathHandle(serial);
        self.entries[i] = Some(Entry {
            snapshot: Snapshot {
                context: PathContext {
                    handle,
                    key,
                    epoch: serial,
                    revision: serial,
                },
                local_mtu,
                mtu,
                policy,
                revalidation_needed: false,
            },
            deadline,
        });
        self.serial = serial;
        self.now = now;
        Ok(handle)
    }

    pub fn query(&self, handle: PathHandle) -> Result<Snapshot, Error> {
        Ok(self.entries[self.index(handle)?].unwrap().snapshot)
    }

    pub fn iter(&self) -> impl Iterator<Item = Snapshot> + '_ {
        self.entries.iter().flatten().map(|e| e.snapshot)
    }

    pub fn decrease(
        &mut self,
        evidence: HostValidatedDrop,
        now: u64,
    ) -> Result<DropOutcome, Error> {
        let i = self.context_index(evidence.context)?;
        let mut entry = self.entries[i].unwrap();
        let before = entry.snapshot;
        if before.context.key != evidence.quoted_path {
            return Err(Error::PathMismatch);
        }
        // IPv6 reports below 1280 must be discarded, not clamped into evidence.
        if evidence.candidate_mtu < before.context.key.floor()? {
            return Err(Error::InvalidMtu);
        }
        self.time(now, None)?;
        // Even an unchanged report is negative evidence against an older probe.
        let serial = self.next_serial()?;
        entry.snapshot.context.revision = serial;
        let change = if before.policy.enabled && evidence.candidate_mtu < before.mtu {
            entry.deadline = self.time(now, before.policy.aging)?;
            entry.snapshot.mtu = evidence.candidate_mtu;
            entry.snapshot.revalidation_needed = false;
            Some(Change {
                before,
                after: Some(entry.snapshot),
                reason: ChangeReason::Decreased,
            })
        } else {
            None
        };
        self.entries[i] = Some(entry);
        self.serial = serial;
        self.now = now;
        Ok(DropOutcome {
            change,
            dropped: PacketDrop {
                context: evidence.context,
                packet_id: evidence.packet_id,
            },
        })
    }

    // Every explicit policy/first-hop configuration call starts a new evidence
    // epoch, even with equal values or only aging/DF changes. Hosts must retain
    // departure contexts, never relabel old evidence with a freshly queried one.
    pub fn set_policy(
        &mut self,
        handle: PathHandle,
        policy: Policy,
        now: u64,
    ) -> Result<Change, Error> {
        let before = self.query(handle)?;
        self.configure(handle, before.local_mtu, policy, now, ChangeReason::Policy)
    }

    // Same route identity, changed link MTU. Actual route replacement requires
    // invalidate + register with a fresh host route_generation and flow rebinding.
    pub fn first_hop_changed(
        &mut self,
        handle: PathHandle,
        local_mtu: u32,
        now: u64,
    ) -> Result<Change, Error> {
        let before = self.query(handle)?;
        self.configure(
            handle,
            local_mtu,
            before.policy,
            now,
            ChangeReason::FirstHop,
        )
    }

    fn configure(
        &mut self,
        handle: PathHandle,
        local_mtu: u32,
        policy: Policy,
        now: u64,
        reason: ChangeReason,
    ) -> Result<Change, Error> {
        let i = self.index(handle)?;
        let before = self.entries[i].unwrap().snapshot;
        let cap = Self::cap(before.context.key, local_mtu, policy)?;
        let deadline = self.time(now, policy.aging)?;
        let serial = self.next_serial()?;
        let after = Snapshot {
            context: PathContext {
                epoch: serial,
                revision: serial,
                ..before.context
            },
            local_mtu,
            policy,
            mtu: before.mtu.min(cap),
            revalidation_needed: policy.enabled && (before.revalidation_needed || cap > before.mtu),
        };
        self.entries[i] = Some(Entry {
            snapshot: after,
            deadline,
        });
        self.serial = serial;
        self.now = now;
        Ok(Change {
            before,
            after: Some(after),
            reason,
        })
    }

    // Host attests successful same-context probe, with timing/loss/ACK checks
    // performed by the packetization layer. Does not copy its search bounds.
    // Success proves only a lower bound: smaller confirmations are rejected
    // without changing the MTU, deadline or revalidation request.
    pub fn confirm_probe(
        &mut self,
        context: PathContext,
        mtu: u32,
        now: u64,
    ) -> Result<Change, Error> {
        let i = self.context_index(context)?;
        let before = self.entries[i].unwrap().snapshot;
        if before.context != context {
            return Err(Error::StaleContext);
        }
        let cap = Self::cap(context.key, before.local_mtu, before.policy)?;
        if !before.policy.enabled || mtu < before.mtu || mtu > cap {
            return Err(Error::InvalidMtu);
        }
        let deadline = self.time(now, before.policy.aging)?;
        let serial = self.next_serial()?;
        let after = Snapshot {
            context: PathContext {
                revision: serial,
                ..context
            },
            mtu,
            revalidation_needed: false,
            ..before
        };
        self.entries[i] = Some(Entry {
            snapshot: after,
            deadline,
        });
        self.serial = serial;
        self.now = now;
        Ok(Change {
            before,
            after: Some(after),
            reason: ChangeReason::ProbeConfirmed,
        })
    }

    // Caller drives bounded one-handle aging notifications; expiry is not proof
    // of a larger path. Never retransmit solely because of this neutral event.
    pub fn age(&mut self, handle: PathHandle, now: u64) -> Result<Option<Change>, Error> {
        let i = self.index(handle)?;
        self.time(now, None)?;
        let mut entry = self.entries[i].unwrap();
        let before = entry.snapshot;
        let change = if before.policy.enabled
            && entry.deadline.is_some_and(|t| now >= t)
            && !before.revalidation_needed
        {
            entry.snapshot.revalidation_needed = true;
            entry.deadline = None;
            Some(Change {
                before,
                after: Some(entry.snapshot),
                reason: ChangeReason::Revalidation,
            })
        } else {
            None
        };
        self.entries[i] = Some(entry);
        self.now = now;
        Ok(change)
    }

    pub fn invalidate(&mut self, handle: PathHandle) -> Result<Change, Error> {
        let i = self.index(handle)?;
        let before = self.entries[i].take().unwrap().snapshot;
        Ok(Change {
            before,
            after: None,
            reason: ChangeReason::Invalidated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_mutations_preserve_clock_deadline_and_evidence_generations() {
        let mut s = PathMtuService::<1>::new();
        let key = PathKey::new(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 2]),
            0,
            0,
            0,
        )
        .unwrap();
        let policy = Policy {
            aging: Some(10),
            ..Policy::default()
        };
        let h = s.register(key, 1500, policy, 10).unwrap();
        let context = s.query(h).unwrap().context;
        for (now, serial, error) in [
            (9, s.serial, Error::ClockWentBackwards),
            (u64::MAX, s.serial, Error::TimeOverflow),
            (11, u64::MAX, Error::GenerationExhausted),
        ] {
            s.serial = serial;
            let before = (
                s.query(h).unwrap(),
                s.entries[0].unwrap().deadline,
                s.now,
                s.serial,
            );
            let evidence = HostValidatedDrop::new(context, key, 1, 1400);
            assert_eq!(s.decrease(evidence, now), Err(error));
            assert_eq!(s.confirm_probe(context, 1500, now), Err(error));
            assert_eq!(s.set_policy(h, policy, now), Err(error));
            assert_eq!(s.first_hop_changed(h, 1400, now), Err(error));
            assert_eq!(
                (
                    s.query(h).unwrap(),
                    s.entries[0].unwrap().deadline,
                    s.now,
                    s.serial
                ),
                before
            );
        }
        // Unchanged drops also require fresh probe revisions; exhaustion is atomic.
        assert_eq!(
            s.decrease(HostValidatedDrop::new(context, key, 2, 1600), 11),
            Err(Error::GenerationExhausted)
        );
        s.invalidate(h).unwrap();
        assert_eq!(
            s.register(key, 1500, policy, 11),
            Err(Error::GenerationExhausted)
        );
        assert_eq!(s.iter().count(), 0);
        assert_eq!(s.now, 10);
    }
}
