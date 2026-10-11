use alloc::vec::Vec;
use core::net::IpAddr;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Instant, wire::FastOpenCookie};

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
pub(crate) const LIFETIME_US: u64 = 3_600_000_000;

#[derive(Clone, Copy)]
pub(crate) struct CachedCookie {
    pub cookie: FastOpenCookie,
    pub mss: u16,
    local: IpAddr,
    remote: IpAddr,
    learned: Instant,
}

pub(crate) struct FastOpen {
    entries: Vec<CachedCookie>,
    next: usize,
}

impl FastOpen {
    pub const fn allocation_bytes() -> usize {
        CAPACITY * core::mem::size_of::<CachedCookie>()
    }

    pub fn new() -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(CAPACITY)
            .map_err(|_| Error::NoMemory)?;
        Ok(Self { entries, next: 0 })
    }

    pub fn get(
        &self,
        now: Instant,
        lifetime: u64,
        local: IpAddr,
        remote: IpAddr,
    ) -> Option<CachedCookie> {
        self.entries.iter().copied().find(|e| {
            e.local == local && e.remote == remote && now >= e.learned && now - e.learned < lifetime
        })
    }

    // A validated SYN-ACK can update MSS without supplying a replacement credential.
    // Keep the original cookie age; MSS-only learning cannot create or revive one.
    pub fn update_mss(
        &mut self,
        now: Instant,
        lifetime: u64,
        local: IpAddr,
        remote: IpAddr,
        mss: u16,
    ) {
        if let Some(entry) = self.entries.iter_mut().find(|e| {
            e.local == local && e.remote == remote && now >= e.learned && now - e.learned < lifetime
        }) {
            entry.mss = mss;
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
        if cookie.as_bytes().is_empty() {
            return;
        }
        let entry = CachedCookie {
            cookie,
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
            *old = entry;
        } else if self.entries.len() < CAPACITY {
            self.entries.push(entry);
        } else {
            self.entries[self.next] = entry;
            self.next = (self.next + 1) % CAPACITY;
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
            for now in [9, 10, 109, 110, 111] {
                let mut cache = FastOpen::new().unwrap();
                cache.update_mss(now, 100, local, remote, 940);
                assert!(cache.entries.is_empty());
                cache.learn(10, local, remote, cookie, 1460);
                cache.learn(10, other, remote, cookie, 1220);
                cache.learn(10, local, other, cookie, 536);
                cache.update_mss(now, 100, local, remote, 940);
                let entry = cache.get(109, 100, local, remote).unwrap();
                assert_eq!(entry.mss, if (10..110).contains(&now) { 940 } else { 1460 });
                assert_eq!(entry.cookie, cookie);
                assert_eq!(entry.learned, 10);
                assert!(cache.get(110, 100, local, remote).is_none());
                assert_eq!(cache.get(109, 100, other, remote).unwrap().mss, 1220);
                assert_eq!(cache.get(109, 100, local, other).unwrap().mss, 536);
                assert_eq!(cache.next, 0);
                assert_eq!(cache.entries.len(), 3);
                cache.learn(110, local, remote, replacement, 1000);
                let entry = cache.get(209, 100, local, remote).unwrap();
                assert_eq!(entry.cookie, replacement);
                assert_eq!(entry.mss, 1000);
                assert_eq!(entry.learned, 110);
                assert!(cache.get(210, 100, local, remote).is_none());
            }
            let mut cache = FastOpen::new().unwrap();
            cache.learn(u64::MAX - 10, local, remote, cookie, 1460);
            cache.update_mss(u64::MAX, 10, local, remote, 940);
            assert_eq!(cache.entries[0].mss, 1460);
            cache.update_mss(u64::MAX, 11, local, remote, 940);
            assert_eq!(cache.get(u64::MAX, 11, local, remote).unwrap().mss, 940);
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
