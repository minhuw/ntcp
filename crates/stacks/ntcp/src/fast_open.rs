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
    /// Omit the FO option; retain cold peer-MSS and negative-response limits.
    ApplicationProtected,
}

/// Server cookie authentication policy. Selecting a policy does not enable TFO.
#[derive(Clone, Debug, Default)]
pub enum FastOpenCookiePolicy {
    /// Address-bound HMAC with current and previous epoch acceptance.
    #[default]
    HmacSha256,
    /// Linux v5.3+ address cookies: a single key, without epochs or backup keys.
    #[cfg(feature = "tfo-linux-cookie")]
    LinuxSipHash24(LinuxSipHash24Key),
}

/// Raw Linux socket key bytes, not textual sysctl words.
#[cfg(feature = "tfo-linux-cookie")]
#[derive(Clone)]
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

const CAPACITY: usize = 64;
pub(crate) const NEGATIVE_LIFETIME_US: u64 = 60_000_000;
pub(crate) const LIFETIME_US: u64 = 3_600_000_000;

#[derive(Clone, Copy)]
pub(crate) struct CachedCookie {
    pub cookie: FastOpenCookie,
    pub mss: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct CachedPeer {
    credential: Option<(FastOpenCookie, Instant)>,
    mss: u16,
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
            mss: peer.mss,
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
        self.peer(now, lifetime, local, remote).map(|e| e.mss)
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
                entry.mss = mss;
                entry.learned = now;
            }
        } else {
            self.insert_peer(CachedPeer {
                credential: None,
                mss,
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

    pub fn learn(
        &mut self,
        now: Instant,
        local: IpAddr,
        remote: IpAddr,
        cookie: FastOpenCookie,
        mss: u16,
    ) {
        // Empty wire options do not by themselves establish a server agreement
        // for a zero cookie. That authorization must be supplied explicitly.
        if cookie.as_bytes().is_empty() || mss == 0 {
            return;
        }
        let peer = CachedPeer {
            credential: Some((cookie, now)),
            mss,
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
                *old = peer;
            }
        } else {
            self.insert_peer(peer);
        }
    }
}

fn mac(secret: &[u8; 32], local: IpAddr, remote: IpAddr, epoch: u64) -> Hmac<Sha256> {
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
    // Both comparisons use the crypto crate's constant-time truncated verifier.
    let current = mac(secret, local, remote, epoch)
        .verify_truncated_left(cookie.as_bytes())
        .is_ok();
    let previous = mac(secret, local, remote, epoch.saturating_sub(1))
        .verify_truncated_left(cookie.as_bytes())
        .is_ok();
    current | previous
}

#[cfg(test)]
mod tests {
    use super::*;

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
            cache.learn(10, local, remote, cookie, 1460);
            cache.learn(10, other, remote, cookie, 1220);
            cache.learn(10, local, other, cookie, 536);
            cache.update_mss(109, local, remote, 940);
            let entry = cache.get(109, 100, local, remote).unwrap();
            assert_eq!(entry.mss, 940);
            assert_eq!(entry.cookie, cookie);
            assert!(cache.get(110, 100, local, remote).is_none());
            assert_eq!(cache.peer_mss(110, 100, local, remote), Some(940));
            // Later observations update MSS while the credential stays expired.
            cache.update_mss(111, local, remote, 1000);
            assert!(cache.get(111, 100, local, remote).is_none());
            assert_eq!(cache.peer_mss(111, 100, local, remote), Some(1000));
            assert_eq!(cache.get(109, 100, other, remote).unwrap().mss, 1220);
            assert_eq!(cache.get(109, 100, local, other).unwrap().mss, 536);
            assert_eq!(cache.next, 0);
            assert_eq!(cache.entries.len(), 3);
            cache.learn(112, local, remote, replacement, 1000);
            assert_eq!(
                cache.get(211, 100, local, remote).unwrap().cookie,
                replacement
            );
            assert!(cache.get(212, 100, local, remote).is_none());
            assert_eq!(cache.peer_mss(212, 100, local, remote), None);
            // Older observations and empty wire options cannot install a key.
            cache.update_mss(1, local, remote, 400);
            assert!(cache.get(212, 100, local, remote).is_none());
            cache.learn(213, local, remote, FastOpenCookie::request(), 1000);
            assert!(cache.get(213, 100, local, remote).is_none());
            let mut cache = FastOpen::new().unwrap();
            cache.learn(u64::MAX - 10, local, remote, cookie, 1460);
            cache.update_mss(u64::MAX, local, remote, 940);
            assert!(cache.get(u64::MAX, 10, local, remote).is_none());
            assert_eq!(cache.peer_mss(u64::MAX, 10, local, remote), Some(940));
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
            cache.learn(10, local, remote, cookie, 536);
            assert_eq!(cache.get(10, 100, local, remote).unwrap().mss, 536);
            assert!(cache.get(110, 100, local, remote).is_none());
            assert!(cache.get(9, 100, local, remote).is_none());
            assert!(cache.get(10, 100, other, remote).is_none());
            for n in 1..=65 {
                cache.learn(10, local, IpAddr::from([198, 51, 100, n]), cookie, 1220);
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
            cache.learn(1, local, remote.ip(), cookie, 536);
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
            assert_eq!(cache.entries[0].mss, 536);
            cache.learn(11, local, remote.ip(), cookie, 940);
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
            assert_eq!(cache.entries[0].mss, 940);
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
            cache.learn(0, local, remote, cookie, 536);
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
            cache.learn(10, local, remote, cookie, 940);
            cache.fail(10, local, SocketAddr::new(remote, 80));
            assert_eq!(cache.get(10, 100, local, remote).unwrap().mss, 940);
            assert!(cache.suppressed(10, 100, local, SocketAddr::new(remote, 80)));
            assert!(
                cache
                    .get(10, 100, local, IpAddr::from([198, 51, 100, 65]))
                    .is_none()
            );
        });
    }
}
