use crate::Result;
// Payloads registered at once at most: a bound on the registry, not on
// sockets.
const REGISTRATIONS: usize = 512;
use ntcp_io::Payload;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

// Registration holds immutable owning references, never raw foreign-pointer
// borrows. Deregistration cannot revoke already admitted TCP/backend leases.
static REGISTRY: Mutex<BTreeMap<usize, Payload>> = Mutex::new(BTreeMap::new());

pub struct RegisteredPayload {
    payload: Payload,
    address: usize,
    pid: u32,
}
impl RegisteredPayload {
    pub fn register(payload: Payload) -> std::io::Result<Self> {
        if crate::child() {
            return Err(std::io::Error::from_raw_os_error(libc::EOWNERDEAD));
        }
        let pid = std::process::id();
        crate::PID
            .compare_exchange(0, pid as i32, Ordering::AcqRel, Ordering::Acquire)
            .ok();
        let address = payload.as_slice().as_ptr() as usize;
        if payload.is_empty() || address.checked_add(payload.len()).is_none() {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let mut registry = REGISTRY.lock().map_err(|_| std::io::ErrorKind::Other)?;
        if registry.len() >= REGISTRATIONS {
            return Err(std::io::Error::from_raw_os_error(libc::ENOBUFS));
        }
        let end = address + payload.len();
        if registry
            .iter()
            .any(|(&start, p)| start < end && address < start + p.len())
        {
            return Err(std::io::ErrorKind::AlreadyExists.into());
        }
        registry.insert(address, payload.clone());
        Ok(Self {
            payload,
            address,
            pid,
        })
    }
    pub fn as_slice(&self) -> &[u8] {
        self.payload.as_slice()
    }
}
impl Drop for RegisteredPayload {
    fn drop(&mut self) {
        // A fork child cannot acquire a mutex inherited from vanished threads.
        if self.pid != std::process::id() {
            return;
        }
        if let Ok(mut registry) = REGISTRY.lock() {
            registry.remove(&self.address);
        }
    }
}
pub(super) fn lookup(address: usize, length: usize) -> Result<Option<Payload>> {
    let registry = REGISTRY.lock().map_err(|_| libc::EIO)?;
    let Some((&start, payload)) = registry.range(..=address).next_back() else {
        return Ok(None);
    };
    let offset = address - start;
    Ok(offset
        .checked_add(length)
        .filter(|&end| end <= payload.len())
        .and_then(|end| payload.slice(offset..end)))
}

pub(super) struct LeaseState {
    outstanding: AtomicUsize,
    copied: AtomicBool,
}
impl LeaseState {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            outstanding: AtomicUsize::new(1),
            copied: AtomicBool::new(false),
        })
    }
    pub(super) fn borrow(self: &Arc<Self>, payload: Payload) -> Payload {
        self.outstanding.fetch_add(1, Ordering::Relaxed);
        let state = self.clone();
        payload.with_release(move || {
            state.outstanding.fetch_sub(1, Ordering::Release);
        })
    }
    pub(super) fn copied(&self) {
        self.copied.store(true, Ordering::Relaxed);
    }
    pub(super) fn finish(&self) {
        self.outstanding.fetch_sub(1, Ordering::Release);
    }
    pub(super) fn complete(&self) -> Option<bool> {
        (self.outstanding.load(Ordering::Acquire) == 0).then(|| self.copied.load(Ordering::Relaxed))
    }
}
#[derive(Clone)]
pub(super) struct Pending {
    pub(super) id: u32,
    pub(super) state: Arc<LeaseState>,
}
