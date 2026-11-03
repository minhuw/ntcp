use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Instant, wire::FastOpenCookie};

/// Authorization for delivering SYN data before the handshake completes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FastOpenEarlyDataPolicy {
    /// Authenticate using the listener's configured cookie algorithm.
    #[default]
    RequireCookie,
    /// Linux-compatible cookie bypass for explicitly protected applications.
    /// The application supplies independent resource/amplification protection
    /// and accepts ordinary Fast Open replay semantics (RFC7413 section7.3).
    ApplicationProtected,
}

/// Client authorization for sending application data in the first SYN.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FastOpenClientPolicy {
    /// Require a learned or explicitly supplied server cookie.
    #[default]
    RequireCookie,
    /// The target service has independently agreed to protected early data.
    /// Omit the FO option; retain conservative cold admission and service cooldown.
    ApplicationProtected,
}

/// Server cookie authentication policy. Selecting a policy does not enable TFO.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum FastOpenCookiePolicy {
    /// Address-bound HMAC with current and previous epoch acceptance.
    #[default]
    HmacSha256,
    /// Linux v5.3+ raw address encoding. Server admission separately enforces leases.
    #[cfg(feature = "tfo-linux-cookie")]
    LinuxSipHash24(LinuxSipHash24Key),
}

/// Raw Linux socket key bytes, not textual sysctl words.
#[cfg(feature = "tfo-linux-cookie")]
#[derive(Clone, PartialEq, Eq)]
pub struct LinuxSipHash24Key([u8; 16]);

#[cfg(feature = "tfo-linux-cookie")]
impl LinuxSipHash24Key {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(bytes.try_into().map_err(|_| Error::InvalidArgument)?))
    }

    fn cookie(&self, local: IpAddr, remote: IpAddr) -> Option<FastOpenCookie> {
        use core::hash::Hasher;
        use siphasher::sip::SipHasher24;

        // new_with_key interprets each raw 8-byte key half as little endian.
        let mut hash = SipHasher24::new_with_key(&self.0);
        match (remote, local) {
            (IpAddr::V4(remote), IpAddr::V4(local)) => {
                hash.write(&remote.octets());
                hash.write(&local.octets());
            }
            (IpAddr::V6(remote), IpAddr::V6(local)) => {
                hash.write(&remote.octets());
                hash.write(&local.octets());
            }
            _ => return None,
        }
        Some(FastOpenCookie::new(&hash.finish().to_le_bytes()).unwrap())
    }
}

#[cfg(feature = "tfo-linux-cookie")]
impl core::fmt::Debug for LinuxSipHash24Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LinuxSipHash24Key([REDACTED])")
    }
}

impl FastOpenCookiePolicy {
    pub(crate) fn refresh_valid_cookie(&self) -> bool {
        matches!(self, Self::HmacSha256)
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //# - GetCookie(IP_Address): returns a (new) cookie.
    pub(crate) fn issue(
        &self,
        secret: &[u8; 32],
        local: IpAddr,
        remote: IpAddr,
        epoch: u64,
    ) -> Option<FastOpenCookie> {
        match self {
            Self::HmacSha256 => Some(issue(secret, local, remote, epoch)),
            #[cfg(feature = "tfo-linux-cookie")]
            Self::LinuxSipHash24(key) => key.cookie(local, remote),
        }
    }

    // Raw codecs authenticate bytes only. ServerCookieContext enforces admission
    // deadlines; accepting a raw vector at u64::MAX does not authorize a SYN.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //= reason=Endpoint admission enforces finite HMAC current/previous epochs and LinuxSipHash24 key leases with absolute issue/accept deadlines, including delayed service, retiring keys and same-key no-renewal through the endpoint-owned identity registry across arbitrary key cycles, policy clearing, listener generations, cross-listener reuse and native pre-listen staging. Raw Linux validation intentionally ignores epoch, including u64::MAX, to preserve wire bytes; that raw codec result is not server acceptance. Timed interfaces require trusted original lease deadlines or fresh keys across restart. T20 must integrate that host restart/time mapping for external raw-key deployment; the whole lifecycle obligation remains TODO pending that integration.
    //# 5. The cookie expires after a certain amount of time. The reason for cookie expiration is detailed
    //# in the "Security Considerations" section (Section 5). This can be done by either periodically
    //# changing the server key used to generate cookies or including a timestamp when generating the cookie.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //# 1. The cookie authenticates the client's (source) IP address of the SYN packet. The IP address may
    //# be an IPv4 or IPv6 address.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //# 2. The cookie can only be generated by the server and cannot be fabricated by any other parties,
    //# including the client.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //# If only one valid cookie is allowed per IP, and the server can regenerate the cookie independently,
    //# the best validation process is to simply regenerate a valid cookie and compare it against the
    //# incoming cookie. In that case, if the incoming cookie fails the check, a valid cookie is readily
    //# available to be sent to the client.
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //# 4. A server may encode other information in the cookie and accept more than one valid cookie per client at any given time. But this is server-implementation dependent and transparent to the client.
    pub(crate) fn valid(
        &self,
        secret: &[u8; 32],
        local: IpAddr,
        remote: IpAddr,
        epoch: u64,
        cookie: FastOpenCookie,
    ) -> bool {
        match self {
            Self::HmacSha256 => valid(secret, local, remote, epoch, cookie),
            #[cfg(feature = "tfo-linux-cookie")]
            Self::LinuxSipHash24(key) => {
                use subtle::ConstantTimeEq;
                if cookie.as_bytes().len() != 8 {
                    return false;
                }
                key.cookie(local, remote).is_some_and(|expected| {
                    bool::from(expected.as_bytes().ct_eq(cookie.as_bytes()))
                })
            }
        }
    }
}

/// Credential duration in microseconds, independent of the caller's tick unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastOpenCookieLifetime(u64);

impl Default for FastOpenCookieLifetime {
    fn default() -> Self {
        Self(LIFETIME_US)
    }
}

impl FastOpenCookieLifetime {
    pub fn from_micros(us: u64) -> Result<Self, Error> {
        // Both supported timebases must represent two HMAC epochs exactly.
        if us == 0 || us.checked_mul(2000).is_none() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(us))
    }

    pub fn as_micros(self) -> u64 {
        self.0
    }

    pub(crate) fn ticks(self, timebase: crate::CallerTimebase) -> Result<u64, Error> {
        if !timebase.valid() {
            return Err(Error::InvalidArgument);
        }
        self.0
            .checked_mul(timebase.units_per_second / 1_000_000)
            .ok_or(Error::InvalidArgument)
    }
}

/// Absolute deadlines in the endpoint's caller timebase. The embedding must
/// preserve these deadlines across reinstall/restart using a trusted clock
/// mapping, or supply fresh key material. Raw cookies carry no installation ID.
/// Issuance is [not_before, issue_until); acceptance is [not_before, accept_until).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastOpenKeyLease {
    pub not_before: Instant,
    pub issue_until: Instant,
    pub accept_until: Instant,
    pub units_per_second: u64,
}

impl FastOpenKeyLease {
    pub fn validate(self, now: Instant, timebase: crate::CallerTimebase) -> Result<(), Error> {
        if !timebase.valid()
            || self.units_per_second != timebase.units_per_second
            || self.not_before > now
            || self.not_before >= self.issue_until
            || self.issue_until > self.accept_until
        {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    pub fn for_lifetime(
        now: Instant,
        lifetime: FastOpenCookieLifetime,
        timebase: crate::CallerTimebase,
        retiring: bool,
    ) -> Result<Self, Error> {
        let ticks = lifetime.ticks(timebase)?;
        let issue_until = now.checked_add(ticks).ok_or(Error::InvalidArgument)?;
        let accept_until = if retiring {
            issue_until
                .checked_add(ticks)
                .ok_or(Error::InvalidArgument)?
        } else {
            issue_until
        };
        Ok(Self {
            not_before: now,
            issue_until,
            accept_until,
            units_per_second: timebase.units_per_second,
        })
    }
}

/// Actual server key material. Linux bytes are never interpreted as a seed.
#[derive(Clone)]
pub enum FastOpenServerKey {
    HmacSha256([u8; 32]),
    #[cfg(feature = "tfo-linux-cookie")]
    LinuxSipHash24(LinuxSipHash24Key),
}

impl core::fmt::Debug for FastOpenServerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FastOpenServerKey([REDACTED])")
    }
}

impl FastOpenServerKey {
    pub(crate) fn policy(&self) -> FastOpenCookiePolicy {
        match self {
            Self::HmacSha256(_) => FastOpenCookiePolicy::HmacSha256,
            #[cfg(feature = "tfo-linux-cookie")]
            Self::LinuxSipHash24(key) => FastOpenCookiePolicy::LinuxSipHash24(key.clone()),
        }
    }

    fn same(&self, other: &Self) -> bool {
        #[cfg(feature = "tfo-linux-cookie")]
        use subtle::ConstantTimeEq;
        match (self, other) {
            (Self::HmacSha256(a), Self::HmacSha256(b)) => {
                use hmac::digest::CtOutput;
                CtOutput::<Sha256>::new((*a).into()) == CtOutput::<Sha256>::new((*b).into())
            }
            #[cfg(feature = "tfo-linux-cookie")]
            (Self::LinuxSipHash24(a), Self::LinuxSipHash24(b)) => bool::from(a.0.ct_eq(&b.0)),
            #[cfg(feature = "tfo-linux-cookie")]
            _ => false,
        }
    }

    fn fingerprint(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hash = Sha256::new();
        hash.update(b"ntcp credential identity\0");
        match self {
            Self::HmacSha256(key) => {
                hash.update(b"hmac-sha256\0");
                hash.update(key);
            }
            #[cfg(feature = "tfo-linux-cookie")]
            Self::LinuxSipHash24(key) => {
                hash.update(b"linux-siphash24\0");
                hash.update(key.0);
            }
        }
        hash.finalize().into()
    }

    fn secret(&self) -> &[u8; 32] {
        match self {
            Self::HmacSha256(secret) => secret,
            #[cfg(feature = "tfo-linux-cookie")]
            Self::LinuxSipHash24(_) => &[0; 32], // Unused by the raw codec.
        }
    }
}

// Only selection contexts retain accepting material. Registry identities rely on
// SHA-256 collision resistance, with codec domain separation; they are not keys.
#[derive(Clone, Copy)]
pub(crate) struct CredentialRecord {
    fingerprint: [u8; 32],
    epoch_ticks: u64,
    registered_at: Instant,
    lease: Option<FastOpenKeyLease>,
}

impl CredentialRecord {
    fn accepts(&self, now: Instant) -> bool {
        now >= self.registered_at
            && self
                .lease
                .is_none_or(|lease| now >= lease.not_before && now < lease.accept_until)
    }

    fn issues(&self, now: Instant) -> bool {
        self.accepts(now) && self.lease.is_none_or(|lease| now < lease.issue_until)
    }

    fn constrain(&mut self, lease: FastOpenKeyLease) {
        self.lease = Some(match self.lease {
            Some(old) => FastOpenKeyLease {
                not_before: old.not_before.max(lease.not_before),
                issue_until: old.issue_until.min(lease.issue_until),
                accept_until: old.accept_until.min(lease.accept_until),
                units_per_second: old.units_per_second,
            },
            None => lease,
        });
    }
}

// Endpoint authority, independent of policy selection and listener generations.
// The constructor credential is inline. Additional records never disappear;
// administrative registration alone grows this storage, charged to buffer_bytes.
pub(crate) struct CredentialRegistry {
    initial: CredentialRecord,
    records: Vec<CredentialRecord>,
}

impl CredentialRegistry {
    pub fn new(key: &FastOpenServerKey, timebase: crate::CallerTimebase, now: Instant) -> Self {
        Self {
            initial: CredentialRecord {
                fingerprint: key.fingerprint(),
                epoch_ticks: FastOpenCookieLifetime::default().ticks(timebase).unwrap(),
                registered_at: now,
                lease: None,
            },
            records: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        1 + self.records.len()
    }

    pub fn allocation_bytes(&self) -> usize {
        self.records.capacity() * core::mem::size_of::<CredentialRecord>()
    }

    #[cfg(test)]
    pub fn constraints(
        &self,
        key: &FastOpenServerKey,
    ) -> Option<(u64, Instant, Option<FastOpenKeyLease>)> {
        let fingerprint = key.fingerprint();
        core::iter::once(&self.initial)
            .chain(self.records.iter())
            .find(|record| record.fingerprint == fingerprint)
            .map(|record| (record.epoch_ticks, record.registered_at, record.lease))
    }

    fn get(&self, id: usize) -> &CredentialRecord {
        if id == 0 {
            &self.initial
        } else {
            &self.records[id - 1]
        }
    }

    fn get_mut(&mut self, id: usize) -> &mut CredentialRecord {
        if id == 0 {
            &mut self.initial
        } else {
            &mut self.records[id - 1]
        }
    }

    pub fn register(
        &mut self,
        key: &FastOpenServerKey,
        lifetime: FastOpenCookieLifetime,
        now: Instant,
        timebase: crate::CallerTimebase,
        lease: Option<FastOpenKeyLease>,
        room: usize,
    ) -> Result<usize, Error> {
        let epoch_ticks = lifetime.ticks(timebase)?;
        if let Some(lease) = lease {
            lease.validate(now, timebase)?;
        }
        let fingerprint = key.fingerprint();
        if let Some(id) = core::iter::once(&self.initial)
            .chain(self.records.iter())
            .position(|record| record.fingerprint == fingerprint)
        {
            if let Some(lease) = lease {
                self.get_mut(id).constrain(lease);
            }
            return Ok(id);
        }
        let lease = match (lease, key) {
            (Some(lease), _) => Some(lease),
            (None, FastOpenServerKey::HmacSha256(_)) => None,
            #[cfg(feature = "tfo-linux-cookie")]
            (None, FastOpenServerKey::LinuxSipHash24(_)) => Some(FastOpenKeyLease::for_lifetime(
                now, lifetime, timebase, false,
            )?),
        };
        if self.records.len() == self.records.capacity() {
            // Stage bounded growth before touching canonical facts. Include both
            // old and new allocations in the peak budget; allocator failure is
            // atomic even when other listeners use the same registry.
            let capacity = self.records.len().checked_add(1).ok_or(Error::NoMemory)?;
            capacity
                .checked_mul(core::mem::size_of::<CredentialRecord>())
                .filter(|bytes| *bytes <= room)
                .ok_or(Error::NoMemory)?;
            let mut staged = Vec::new();
            staged
                .try_reserve_exact(capacity)
                .map_err(|_| Error::NoMemory)?;
            if staged.capacity() * core::mem::size_of::<CredentialRecord>() > room {
                return Err(Error::NoMemory);
            }
            staged.extend_from_slice(&self.records);
            self.records = staged;
        }
        self.records.push(CredentialRecord {
            fingerprint,
            epoch_ticks,
            registered_at: now,
            lease,
        });
        Ok(self.records.len())
    }

    fn retire(&mut self, id: usize, now: Instant, timebase: crate::CallerTimebase) {
        let record = self.get_mut(id);
        if record.lease.is_none() {
            // Last-issued epoch remains valid through its original next epoch.
            let deadline = (now / record.epoch_ticks)
                .checked_add(2)
                .and_then(|epoch| epoch.checked_mul(record.epoch_ticks))
                .unwrap_or(now);
            record.constrain(FastOpenKeyLease {
                not_before: record.registered_at,
                issue_until: now,
                accept_until: deadline,
                units_per_second: timebase.units_per_second,
            });
        }
    }
}

#[derive(Clone)]
struct Credential {
    key: FastOpenServerKey,
    id: usize,
}

impl Credential {
    fn valid(
        &self,
        registry: &CredentialRegistry,
        now: Instant,
        local: IpAddr,
        remote: IpAddr,
        cookie: FastOpenCookie,
    ) -> bool {
        let record = registry.get(self.id);
        record.accepts(now)
            && self.key.policy().valid(
                self.key.secret(),
                local,
                remote,
                now / record.epoch_ticks,
                cookie,
            )
    }
}

// At most current + one retiring accepting credential per selection. Timing is
// always queried from the endpoint authority, never copied with a selection.
#[derive(Clone)]
pub(crate) struct ServerCookieContext {
    current: Credential,
    retiring: Option<Credential>,
    pub lifetime: FastOpenCookieLifetime,
    pub error: Option<Error>,
}

impl ServerCookieContext {
    pub fn new(key: FastOpenServerKey) -> Self {
        Self {
            current: Credential { key, id: 0 },
            retiring: None,
            lifetime: Default::default(),
            error: None,
        }
    }

    pub fn policy(&self) -> FastOpenCookiePolicy {
        self.current.key.policy()
    }

    pub fn replace(&mut self, key: FastOpenServerKey, id: usize) {
        if !self.current.key.same(&key) {
            self.current = Credential { key, id };
            self.retiring = None;
        }
        self.error = None;
    }

    pub fn check_install(&self, key: &FastOpenServerKey) -> Result<(), Error> {
        if self.retiring.as_ref().is_some_and(|old| old.key.same(key)) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
    //# To gradually invalidate cookies over time, the server can implement key rotation to generate and verify cookies using multiple keys. This approach is useful for large-scale servers to retain Fast Open rolling key updates. We do not specify a particular mechanism because the implementation is server specific.
    pub fn install(
        &mut self,
        key: FastOpenServerKey,
        id: usize,
        registry: &mut CredentialRegistry,
        now: Instant,
        timebase: crate::CallerTimebase,
        rotate: bool,
    ) {
        if !self.current.key.same(&key) {
            let old = core::mem::replace(&mut self.current, Credential { key, id });
            if rotate {
                registry.retire(old.id, now, timebase);
            }
            self.retiring = (rotate && registry.get(old.id).accepts(now)).then_some(old);
        }
        self.error = None;
    }

    pub fn replace_hmac(&mut self, key: [u8; 32], id: usize) {
        if matches!(self.current.key, FastOpenServerKey::HmacSha256(_)) {
            self.replace(FastOpenServerKey::HmacSha256(key), id);
        }
        self.revoke_retiring_hmac(key);
    }

    pub fn block_hmac(&mut self, key: [u8; 32], error: Error) {
        if matches!(self.current.key, FastOpenServerKey::HmacSha256(_)) {
            self.error = Some(error);
        }
        self.revoke_retiring_hmac(key);
    }

    fn revoke_retiring_hmac(&mut self, key: [u8; 32]) {
        if self.retiring.as_ref().is_some_and(|old| {
            matches!(old.key, FastOpenServerKey::HmacSha256(_))
                && !old.key.same(&FastOpenServerKey::HmacSha256(key))
        }) {
            self.retiring = None;
        }
    }

    pub fn valid(
        &self,
        registry: &CredentialRegistry,
        now: Instant,
        local: IpAddr,
        remote: IpAddr,
        cookie: FastOpenCookie,
    ) -> bool {
        #[cfg(all(test, feature = "tfo-linux-cookie"))]
        let _scope = crate::endpoint::mac_cost_tests::Scope::new(0);
        self.error.is_none()
            && (self.current.valid(registry, now, local, remote, cookie)
                | self
                    .retiring
                    .as_ref()
                    .is_some_and(|old| old.valid(registry, now, local, remote, cookie)))
    }

    pub fn issue(
        &self,
        registry: &CredentialRegistry,
        now: Instant,
        local: IpAddr,
        remote: IpAddr,
    ) -> Option<FastOpenCookie> {
        #[cfg(all(test, feature = "tfo-linux-cookie"))]
        let _scope = crate::endpoint::mac_cost_tests::Scope::new(1);
        let record = registry.get(self.current.id);
        if self.error.is_some() || !record.issues(now) {
            return None;
        }
        self.current.key.policy().issue(
            self.current.key.secret(),
            local,
            remote,
            now / record.epoch_ticks,
        )
    }
}

const CAPACITY: usize = 64;
pub(crate) const NEGATIVE_LIFETIME_US: u64 = 60_000_000;
pub(crate) const LIFETIME_US: u64 = 3_600_000_000;

#[derive(Clone, Copy)]
pub(crate) struct CachedCookie {
    pub cookie: FastOpenCookie,
    pub mss: Option<u16>,
}

#[derive(Clone, Copy)]
pub(crate) struct CachedPeer {
    credential: Option<(FastOpenCookie, Instant)>,
    mss: Option<(u16, Instant)>,
    local: IpAddr,
    remote: IpAddr,
    learned: Instant,
}

#[derive(Clone, Copy)]
pub(crate) struct NegativeService {
    local: IpAddr,
    remote: SocketAddr,
    failed: Instant,
}

pub(crate) struct FastOpen {
    entries: Vec<CachedPeer>,
    next: usize,
    negative: Vec<NegativeService>,
    negative_next: usize,
}

impl FastOpen {
    pub const fn allocation_bytes() -> usize {
        CAPACITY * (core::mem::size_of::<CachedPeer>() + core::mem::size_of::<NegativeService>())
    }

    pub fn new() -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(CAPACITY)
            .map_err(|_| Error::NoMemory)?;
        let mut negative = Vec::new();
        negative
            .try_reserve_exact(CAPACITY)
            .map_err(|_| Error::NoMemory)?;
        Ok(Self {
            entries,
            next: 0,
            negative,
            negative_next: 0,
        })
    }

    pub fn clear_client_cache(&mut self) {
        self.entries.clear();
        self.next = 0;
        self.negative.clear();
        self.negative_next = 0;
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3.1
    //= reason=Verified erratum 5373 removes the source port from this published path definition. Suppression is keyed by source IP and destination IP/port.
    //# For any negative responses, the client SHOULD disable Fast Open on the specific path (the source and
    //# destination IP addresses and ports) at least temporarily. Since TFO is enabled on a per-service-port
    //# basis, but cookies are independent of service ports, the client's cache should include remote port
    //# numbers, too.
    pub fn suppressed(
        &self,
        now: Instant,
        lifetime: u64,
        local: IpAddr,
        remote: SocketAddr,
    ) -> bool {
        self.negative.iter().any(|e| {
            e.local == local && e.remote == remote && now >= e.failed && now - e.failed < lifetime
        })
    }

    pub fn fail(&mut self, now: Instant, local: IpAddr, remote: SocketAddr) {
        let entry = NegativeService {
            local,
            remote,
            failed: now,
        };
        if let Some(old) = self
            .negative
            .iter_mut()
            .find(|e| e.local == local && e.remote == remote)
        {
            *old = entry;
        } else if self.negative.len() < CAPACITY {
            self.negative.push(entry);
        } else {
            self.negative[self.negative_next] = entry;
            self.negative_next = (self.negative_next + 1) % CAPACITY;
        }
    }

    pub fn get(
        &self,
        now: Instant,
        lifetime: u64,
        local: IpAddr,
        remote: IpAddr,
    ) -> Option<CachedCookie> {
        let peer = self.peer(now, lifetime, local, remote)?;
        let (cookie, learned) = peer.credential?;
        (now >= learned && now - learned < lifetime).then_some(CachedCookie {
            cookie,
            mss: self.peer_mss(now, lifetime, local, remote),
        })
    }

    fn peer(
        &self,
        now: Instant,
        lifetime: u64,
        local: IpAddr,
        remote: IpAddr,
    ) -> Option<&CachedPeer> {
        self.entries.iter().find(|e| {
            e.local == local && e.remote == remote && now >= e.learned && now - e.learned < lifetime
        })
    }

    pub fn peer_mss(
        &self,
        now: Instant,
        lifetime: u64,
        local: IpAddr,
        remote: IpAddr,
    ) -> Option<u16> {
        let (mss, learned) = self.peer(now, lifetime, local, remote)?.mss?;
        (now >= learned && now - learned < lifetime).then_some(mss)
    }

    // Validated MSS observations have their own age. They neither create a
    // credential nor refresh a credential's lifetime.
    pub fn update_mss(&mut self, now: Instant, local: IpAddr, remote: IpAddr, mss: u16) {
        if mss == 0 {
            return;
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.local == local && e.remote == remote)
        {
            if now >= entry.learned {
                entry.mss = Some((mss, now));
                entry.learned = now;
            }
        } else {
            self.insert_peer(CachedPeer {
                credential: None,
                mss: Some((mss, now)),
                local,
                remote,
                learned: now,
            });
        }
    }

    fn insert_peer(&mut self, peer: CachedPeer) {
        if self.entries.len() < CAPACITY {
            self.entries.push(peer);
        } else {
            self.entries[self.next] = peer;
            self.next = (self.next + 1) % CAPACITY;
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3
    //# The client MUST cache cookies from servers for later Fast Open connections. For a multihomed client,
    //# the cookies are dependent on the client and server IP addresses. Hence, the client should cache at
    //# most one (most recently received) cookie per client and server IP address pair.
    pub fn learn(
        &mut self,
        now: Instant,
        local: IpAddr,
        remote: IpAddr,
        cookie: FastOpenCookie,
        mss: Option<u16>,
    ) {
        // Empty wire options do not by themselves establish a server agreement
        // for a zero cookie. That authorization must be supplied explicitly.
        if cookie.as_bytes().is_empty() || mss == Some(0) {
            return;
        }
        let peer = CachedPeer {
            credential: Some((cookie, now)),
            mss: mss.map(|mss| (mss, now)),
            local,
            remote,
            learned: now,
        };
        if let Some(old) = self
            .entries
            .iter_mut()
            .find(|e| e.local == local && e.remote == remote)
        {
            if now >= old.learned {
                // Cookie-only replies must neither invent an MSS nor renew
                // the age of an earlier advertised MSS.
                let mss = peer.mss.or(old.mss);
                *old = CachedPeer { mss, ..peer };
            }
        } else {
            self.insert_peer(peer);
        }
    }
}

fn address_mac(secret: &[u8; 32], local: IpAddr, remote: IpAddr) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts a 32-byte key");
    mac.update(b"ntcp fast open cookie\0");
    for address in [local, remote] {
        match address {
            IpAddr::V4(ip) => {
                mac.update(&[4]);
                mac.update(&ip.octets());
            }
            IpAddr::V6(ip) => {
                mac.update(&[6]);
                mac.update(&ip.octets());
            }
        }
    }
    mac
}

fn mac(secret: &[u8; 32], local: IpAddr, remote: IpAddr, epoch: u64) -> Hmac<Sha256> {
    let mut mac = address_mac(secret, local, remote);
    mac.update(&epoch.to_be_bytes());
    mac
}

pub(crate) fn issue(
    secret: &[u8; 32],
    local: IpAddr,
    remote: IpAddr,
    epoch: u64,
) -> FastOpenCookie {
    FastOpenCookie::new(&mac(secret, local, remote, epoch).finalize().into_bytes()[..8]).unwrap()
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= reason=Release measurements now exist in integration/rfc_host/check_mac_cost.py and the ignored release_mac_cost core test: both policies, IPv4/IPv6, small/64-listener tables, allocating/pooled receive storage, current/previous epochs, current/retiring keys, request/invalid/expired/revoked/length controls, actual admission/issuance multiplicities and encoded committed SYN-ACKs. Raw rounds, source/executable/toolchain provenance, clock/recorder controls and signed disabled/enabled perturbation are retained. Measured repeated HMAC key/address setup justified sharing the prefix within each two-epoch verification without persistent state; cookie bytes and both comparisons are preserved. On the measured Xeon 6230R, pooled small-listener overlap/refresh admission was approximately 6.14/7.99 microseconds for IPv4/IPv6 versus 12.35/13.12 microseconds outside the observed scopes; Linux admission was approximately 0.12-0.26 microseconds. HMAC overlap remains substantial, raw codec drift and paired observer variation limit precise speedup inference, and no arbitrary compliance percentage is asserted. Keep the complete fast-relative property TODO pending independent quantitative review/T23 disposition; any further per-credential preparation experiment must preserve resource accounting and use these same real-path boundaries.
//# 3. The generation and verification are fast relative to the rest of SYN and SYN-ACK processing.
pub(crate) fn valid(
    secret: &[u8; 32],
    local: IpAddr,
    remote: IpAddr,
    epoch: u64,
    cookie: FastOpenCookie,
) -> bool {
    if cookie.as_bytes().len() != 8 {
        return false;
    }
    // Both epochs authenticate the same key/domain/address prefix. Prepare it
    // once per verification to avoid repeated key setup and serialization on
    // every SYN. Only bounded stack state is cloned; no credential/cache state
    // or allocation is added, and each epoch retains a complete MAC comparison.
    let base = address_mac(secret, local, remote);
    let mut current_mac = base.clone();
    current_mac.update(&epoch.to_be_bytes());
    let mut previous_mac = base;
    previous_mac.update(&epoch.saturating_sub(1).to_be_bytes());
    // Both comparisons use the crypto crate's constant-time truncated verifier.
    let current = current_mac.verify_truncated_left(cookie.as_bytes()).is_ok();
    let previous = previous_mac
        .verify_truncated_left(cookie.as_bytes())
        .is_ok();
    current | previous
}

#[cfg(test)]
mod tests {
    use super::*;

    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3
    //= type=test
    //# The client MUST cache cookies from servers for later Fast Open connections. For a multihomed client,
    //# the cookies are dependent on the client and server IP addresses. Hence, the client should cache at
    //# most one (most recently received) cookie per client and server IP address pair.
    #[test]
    fn mss_only_update_preserves_credential_age_and_address_scope() {
        for (local, remote, other) in [
            ("192.0.2.1", "192.0.2.2", "192.0.2.3"),
            ("2001:db8::1", "2001:db8::2", "2001:db8::3"),
        ] {
            let local = local.parse().unwrap();
            let remote = remote.parse().unwrap();
            let other = other.parse().unwrap();
            let cookie = FastOpenCookie::new(&[0; 4]).unwrap();
            let replacement = FastOpenCookie::new(&[2; 16]).unwrap();
            let mut cache = FastOpen::new().unwrap();
            cache.update_mss(9, local, remote, 940);
            assert_eq!(cache.peer_mss(9, 100, local, remote), Some(940));
            assert!(cache.get(9, 100, local, remote).is_none());
            cache.learn(10, local, remote, cookie, Some(1460));
            cache.learn(10, other, remote, cookie, Some(1220));
            cache.learn(10, local, other, cookie, Some(536));
            cache.update_mss(109, local, remote, 940);
            let entry = cache.get(109, 100, local, remote).unwrap();
            assert_eq!(entry.mss, Some(940));
            assert_eq!(entry.cookie, cookie);
            assert!(cache.get(110, 100, local, remote).is_none());
            assert_eq!(cache.peer_mss(110, 100, local, remote), Some(940));
            // Later observations update MSS while the credential stays expired.
            cache.update_mss(111, local, remote, 1000);
            assert!(cache.get(111, 100, local, remote).is_none());
            assert_eq!(cache.peer_mss(111, 100, local, remote), Some(1000));
            assert_eq!(cache.get(109, 100, other, remote).unwrap().mss, Some(1220));
            assert_eq!(cache.get(109, 100, local, other).unwrap().mss, Some(536));
            assert_eq!(cache.next, 0);
            assert_eq!(cache.entries.len(), 3);
            cache.learn(112, local, remote, replacement, Some(1000));
            assert_eq!(
                cache.get(211, 100, local, remote).unwrap().cookie,
                replacement
            );
            assert!(cache.get(212, 100, local, remote).is_none());
            assert_eq!(cache.peer_mss(212, 100, local, remote), None);
            // Older observations and empty wire options cannot install a key.
            cache.update_mss(1, local, remote, 400);
            assert!(cache.get(212, 100, local, remote).is_none());
            cache.learn(213, local, remote, FastOpenCookie::request(), Some(1000));
            assert!(cache.get(213, 100, local, remote).is_none());
            let mut cache = FastOpen::new().unwrap();
            cache.learn(u64::MAX - 10, local, remote, cookie, Some(1460));
            cache.update_mss(u64::MAX, local, remote, 940);
            assert!(cache.get(u64::MAX, 10, local, remote).is_none());
            assert_eq!(cache.peer_mss(u64::MAX, 10, local, remote), Some(940));
        }
    }

    #[test]
    fn cookie_only_learning_preserves_absent_or_aging_advertised_mss() {
        let local = "2001:db8::1".parse().unwrap();
        let remote = "2001:db8::2".parse().unwrap();
        let cookie = FastOpenCookie::new(&[7; 8]).unwrap();
        let replacement = FastOpenCookie::new(&[8; 8]).unwrap();
        let mut cache = FastOpen::new().unwrap();
        cache.learn(1, local, remote, cookie, None);
        assert_eq!(cache.get(1, 100, local, remote).unwrap().cookie, cookie);
        assert_eq!(cache.get(1, 100, local, remote).unwrap().mss, None);
        assert_eq!(cache.peer_mss(1, 100, local, remote), None);
        cache.update_mss(2, local, remote, 940);
        cache.learn(101, local, remote, replacement, None);
        assert_eq!(cache.get(101, 100, local, remote).unwrap().mss, Some(940));
        // A newly learned cookie remains useful after the old MSS expires,
        // without converting its absent MSS into a TCP family default.
        let entry = cache.get(102, 100, local, remote).unwrap();
        assert_eq!(entry.cookie, replacement);
        assert_eq!(entry.mss, None);
        assert_eq!(cache.peer_mss(102, 100, local, remote), None);
        cache.update_mss(103, local, remote, 1000);
        assert_eq!(cache.get(200, 100, local, remote).unwrap().mss, Some(1000));
        assert!(cache.get(201, 100, local, remote).is_none());
        assert_eq!(cache.peer_mss(201, 100, local, remote), Some(1000));
    }

    #[test]
    fn shared_prefix_matches_independent_t5_bytes_and_both_epoch_results() {
        // Deliberately keep the old complete serialization independent of the
        // shared-prefix helper, including family tags and epoch-zero saturation.
        fn old(secret: &[u8; 32], local: IpAddr, remote: IpAddr, epoch: u64) -> FastOpenCookie {
            let mut h = Hmac::<Sha256>::new_from_slice(secret).unwrap();
            h.update(b"ntcp fast open cookie\0");
            for ip in [local, remote] {
                match ip {
                    IpAddr::V4(ip) => {
                        h.update(&[4]);
                        h.update(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        h.update(&[6]);
                        h.update(&ip.octets());
                    }
                }
            }
            h.update(&epoch.to_be_bytes());
            FastOpenCookie::new(&h.finalize().into_bytes()[..8]).unwrap()
        }
        let addresses: [IpAddr; 4] = [
            "192.0.2.1".parse().unwrap(),
            "198.51.100.254".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "2001:db8:ffff::abcd".parse().unwrap(),
        ];
        for byte in [0, 1, 7, 8, 127, 255] {
            let secret = [byte; 32];
            for local in addresses {
                for remote in addresses {
                    for epoch in [0, 1, 2, 1 << 32, u64::MAX - 1, u64::MAX] {
                        let current = old(&secret, local, remote, epoch);
                        let previous = old(&secret, local, remote, epoch.saturating_sub(1));
                        assert_eq!(issue(&secret, local, remote, epoch), current);
                        assert!(valid(&secret, local, remote, epoch, current));
                        assert!(valid(&secret, local, remote, epoch, previous));
                        for offered in [
                            old(&[byte ^ 128; 32], local, remote, epoch),
                            FastOpenCookie::new(&[99; 8]).unwrap(),
                            FastOpenCookie::new(&[99; 4]).unwrap(),
                            FastOpenCookie::request(),
                        ] {
                            let expected = offered.as_bytes().len() == 8
                                && (offered == current || offered == previous);
                            assert_eq!(valid(&secret, local, remote, epoch, offered), expected);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn address_epoch_cache_bounds() {
        for (local, remote, other) in [
            ("192.0.2.1", "192.0.2.2", "192.0.2.3"),
            ("2001:db8::1", "2001:db8::2", "2001:db8::3"),
        ] {
            let local = local.parse().unwrap();
            let remote = remote.parse().unwrap();
            let other = other.parse().unwrap();
            let cookie = issue(&[1; 32], local, remote, 7);
            assert!(valid(&[1; 32], local, remote, 7, cookie));
            assert!(valid(&[1; 32], local, remote, 8, cookie));
            assert!(!valid(&[1; 32], local, remote, 9, cookie));
            assert!(!valid(&[1; 32], other, remote, 7, cookie));
            assert!(!valid(&[1; 32], local, other, 7, cookie));
            assert!(!valid(&[2; 32], local, remote, 7, cookie));
            assert!(!valid(
                &[1; 32],
                local,
                remote,
                7,
                FastOpenCookie::request()
            ));
            let mut cache = FastOpen::new().unwrap();
            cache.learn(10, local, remote, cookie, Some(536));
            assert_eq!(cache.get(10, 100, local, remote).unwrap().mss, Some(536));
            assert!(cache.get(110, 100, local, remote).is_none());
            assert!(cache.get(9, 100, local, remote).is_none());
            assert!(cache.get(10, 100, other, remote).is_none());
            for n in 1..=65 {
                cache.learn(10, local, IpAddr::from([198, 51, 100, n]), cookie, Some(1220));
            }
            assert_eq!(cache.entries.len(), CAPACITY);
            assert!(cache.get(10, 100, local, remote).is_none());
        }
    }
}

#[cfg(test)]
mod negative_tests {
    use super::*;

    #[test]
    fn negative_capacity_lifetime_isolation_and_independent_cookie_age() {
        for units in [1_000_000, 1_000_000_000] {
            let lifetime = crate::CallerTimebase {
                units_per_second: units,
                ..Default::default()
            }
            .ticks_from_us(NEGATIVE_LIFETIME_US);
            let local = "192.0.2.1".parse().unwrap();
            let other = "192.0.2.3".parse().unwrap();
            let remote: SocketAddr = "192.0.2.2:80".parse().unwrap();
            let mut cache = FastOpen::new().unwrap();
            let cookie = FastOpenCookie::new(&[1; 8]).unwrap();
            cache.learn(1, local, remote.ip(), cookie, Some(536));
            cache.fail(10, local, remote);
            for now in [9, 10, 10 + lifetime - 1, 10 + lifetime] {
                assert_eq!(
                    cache.suppressed(now, lifetime, local, remote),
                    (10..10 + lifetime).contains(&now)
                );
            }
            assert!(!cache.suppressed(10, lifetime, other, remote));
            assert!(!cache.suppressed(10, lifetime, local, SocketAddr::new(other, 80)));
            assert!(!cache.suppressed(10, lifetime, local, SocketAddr::new(remote.ip(), 81)));
            assert_eq!(cache.entries[0].credential.unwrap().1, 1);
            assert_eq!(cache.entries[0].mss, Some((536, 1)));
            cache.learn(11, local, remote.ip(), cookie, Some(940));
            assert!(cache.suppressed(11, lifetime, local, remote));
            cache.fail(20, local, remote);
            assert_eq!(cache.negative.len(), 1);
            assert!(cache.suppressed(10 + lifetime, lifetime, local, remote));
            assert!(!cache.suppressed(20 + lifetime, lifetime, local, remote));
            crate::allocation_tests::fail_after(0, || {
                for port in 81..=145 {
                    cache.fail(20, local, SocketAddr::new(remote.ip(), port));
                }
            });
            assert_eq!(cache.negative.len(), CAPACITY);
            assert_eq!(cache.negative.capacity(), CAPACITY);
            assert!(!cache.suppressed(20, lifetime, local, remote));
            assert_eq!(cache.entries[0].credential.unwrap().1, 11);
            assert_eq!(cache.entries[0].mss, Some((940, 11)));
        }
    }
}

#[cfg(test)]
mod cache_management_tests {
    use super::*;

    #[test]
    fn clear_client_cache_reuses_full_storage_and_resets_eviction_cursors() {
        let local = IpAddr::from([192, 0, 2, 1]);
        let cookie = FastOpenCookie::new(&[7; 8]).unwrap();
        let mut cache = FastOpen::new().unwrap();
        for n in 1..=65 {
            let remote = IpAddr::from([198, 51, 100, n]);
            cache.learn(0, local, remote, cookie, Some(536));
            cache.fail(0, local, SocketAddr::new(remote, 80));
        }
        let capacities = (cache.entries.capacity(), cache.negative.capacity());
        assert_eq!((cache.next, cache.negative_next), (1, 1));
        crate::allocation_tests::fail_after(0, || {
            cache.clear_client_cache();
            cache.clear_client_cache();
            assert!(cache.entries.is_empty() && cache.negative.is_empty());
            assert_eq!((cache.next, cache.negative_next), (0, 0));
            assert_eq!(
                (cache.entries.capacity(), cache.negative.capacity()),
                capacities
            );
            let remote = IpAddr::from([203, 0, 113, 1]);
            cache.learn(10, local, remote, cookie, Some(940));
            cache.fail(10, local, SocketAddr::new(remote, 80));
            assert_eq!(cache.get(10, 100, local, remote).unwrap().mss, Some(940));
            assert!(cache.suppressed(10, 100, local, SocketAddr::new(remote, 80)));
            assert!(
                cache
                    .get(10, 100, local, IpAddr::from([198, 51, 100, 65]))
                    .is_none()
            );
        });
    }
}
