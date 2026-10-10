use alloc::vec::Vec;
use core::net::IpAddr;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Instant, wire::FastOpenCookie};

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
