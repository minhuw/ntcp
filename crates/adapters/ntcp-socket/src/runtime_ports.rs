// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

// Direct syscall avoids libc symbol interposition by the socket adapter. Blocking
// kernel entropy is required: neither startup secrets nor ports have a fallback.
pub(super) fn fill(bytes: &mut [u8]) -> Result<()> {
    fill_with(bytes, |remaining| {
        let n = unsafe { syscall(SYS_getrandom, remaining.as_mut_ptr(), remaining.len(), 0) };
        if n < 0 { Err(errno()) } else { Ok(n as usize) }
    })
}

// The reader seam also exercises interrupted/partial syscalls without replacing
// the completion and error-handling algorithm used in production.
pub(super) fn fill_with(
    mut bytes: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> Result<usize>,
) -> Result<()> {
    while !bytes.is_empty() {
        match read(bytes) {
            Err(EINTR) => continue,
            Err(error) => return Err(error),
            Ok(0) => return Err(EIO),
            Ok(n) if n <= bytes.len() => bytes = &mut bytes[n..],
            Ok(_) => return Err(EIO),
        }
    }
    Ok(())
}

// The local ports an unbound socket's connect, bind(port 0) and listen
// choose from: Linux's default ip_local_port_range, not RFC 6056's
// 1024-65535 (an exception in duvet/rfc6056-todos.toml). Ports below it
// are left to the services an application binds explicitly.
pub(super) const RANGE: std::ops::RangeInclusive<u16> = 32768..=60999;

// How a socket or a connection came by its local port, as Linux's bind
// bucket tells the owners bind() gave a port (fastreuse >= 0) from the
// connections connect() chose it for (fastreuse -1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Binding {
    // bind(), listen, or a connection a listener accepted: no unbound
    // socket's connect takes the port while it is there.
    Bound,
    // The connect of an unbound socket: other connects share the port, to
    // other destinations.
    Ephemeral,
}

// The users of each local port, so that choosing one is a lookup per
// candidate rather than a pass over every socket: per port, the sockets
// whose local address has it and the connections the owner tracks
// (`connection_options`, which outlive their descriptors), each by
// binding, and the tuples of deferred Fast Open connects, which hold their
// port and destination before the endpoint has a connection of them.
// Indexed by the port, allocated whole (512 KiB), as Linux keeps a bind
// bucket per port.
pub(super) struct PortIndex {
    users: Vec<[u16; 4]>,
    deferred: std::collections::HashMap<(SocketAddr, SocketAddr), u32>,
}

impl PortIndex {
    pub(super) fn new() -> Self {
        Self {
            users: vec![[0; 4]; usize::from(u16::MAX) + 1],
            deferred: Default::default(),
        }
    }
    fn count(&mut self, port: u16, at: usize, add: bool) {
        let count = &mut self.users[usize::from(port)][at];
        *count = if add { *count + 1 } else { *count - 1 };
    }
    pub(super) fn socket(&mut self, port: u16, binding: Binding, add: bool) {
        self.count(port, binding as usize, add);
    }
    pub(super) fn connection(&mut self, port: u16, binding: Binding, add: bool) {
        self.count(port, 2 + binding as usize, add);
    }
    pub(super) fn defer(&mut self, tuple: (SocketAddr, SocketAddr), add: bool) {
        if add {
            *self.deferred.entry(tuple).or_default() += 1;
        } else if let Some(count) = self.deferred.get_mut(&tuple) {
            *count -= 1;
            if *count == 0 {
                self.deferred.remove(&tuple);
            }
        }
    }
    // A socket or connection bind() gave `port` holds it.
    pub(super) fn bound(&self, port: u16) -> bool {
        let users = self.users[usize::from(port)];
        users[Binding::Bound as usize] != 0 || users[2 + Binding::Bound as usize] != 0
    }
    // Any socket or connection holds `port`.
    pub(super) fn used(&self, port: u16) -> bool {
        self.users[usize::from(port)] != [0; 4]
    }
    // A deferred connect holds the tuple.
    pub(super) fn deferred(&self, tuple: (SocketAddr, SocketAddr)) -> bool {
        self.deferred.contains_key(&tuple)
    }
    #[cfg(test)]
    pub(super) fn users(&self, port: u16) -> [u16; 4] {
        self.users[usize::from(port)]
    }
    #[cfg(test)]
    pub(super) fn deferred_tuples(&self) -> usize {
        self.deferred.values().map(|&n| n as usize).sum()
    }
}

#[cfg(test)]
#[path = "runtime_port_tests.rs"]
mod tests;
