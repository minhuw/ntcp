//! The clients of each cached path, so that a change to a path reaches its
//! clients without a pass over every client: a list per path slot, in the
//! order the clients joined it. A path slot is reused only once no client
//! pins it, so a slot's list holds the clients of its current incarnation.

use super::index::filled;
use super::*;

// The end of a list.
const NONE: u32 = u32::MAX;

pub(in crate::service) struct PathClients {
    // The first and last client slot of each path slot's list.
    first: Vec<u32>,
    last: Vec<u32>,
    // The neighbours of each client slot on its path's list.
    previous: Vec<u32>,
    next: Vec<u32>,
}

impl PathClients {
    /// What `new` allocates, as (count, element size) pairs for the
    /// service's accounting.
    pub(in crate::service) fn accounting(
        paths: usize,
        clients: usize,
    ) -> Result<[(usize, usize); 2], Error> {
        // Client slot numbers and the list end are u32.
        if clients >= NONE as usize {
            return Err(Error::Capacity);
        }
        Ok([
            (paths, 2 * size_of::<u32>()),
            (clients, 2 * size_of::<u32>()),
        ])
    }

    pub(in crate::service) fn new(paths: usize, clients: usize) -> Result<Self, Error> {
        Self::accounting(paths, clients)?;
        Ok(Self {
            first: filled(paths, NONE)?,
            last: filled(paths, NONE)?,
            previous: filled(clients, NONE)?,
            next: filled(clients, NONE)?,
        })
    }

    /// Append `client` to `path`'s list.
    pub(super) fn join(&mut self, path: usize, client: usize) {
        let last = self.last[path];
        self.previous[client] = last;
        self.next[client] = NONE;
        match last {
            NONE => self.first[path] = client as u32,
            last => self.next[last as usize] = client as u32,
        }
        self.last[path] = client as u32;
    }

    /// Remove `client` from `path`'s list, which holds it.
    pub(super) fn leave(&mut self, path: usize, client: usize) {
        let (previous, next) = (self.previous[client], self.next[client]);
        match previous {
            NONE => self.first[path] = next,
            previous => self.next[previous as usize] = next,
        }
        match next {
            NONE => self.last[path] = previous,
            next => self.previous[next as usize] = previous,
        }
    }

    /// The first client slot on `path`'s list: the clients joined it in
    /// list order.
    pub(super) fn first(&self, path: usize) -> Option<usize> {
        (self.first[path] != NONE).then_some(self.first[path] as usize)
    }

    /// The client slot after `client` on its path's list.
    pub(super) fn after(&self, client: usize) -> Option<usize> {
        (self.next[client] != NONE).then_some(self.next[client] as usize)
    }
}
