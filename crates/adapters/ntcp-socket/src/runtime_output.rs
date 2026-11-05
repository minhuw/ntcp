// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

pub(super) struct MtuRefresh {
    request: SyncSender<()>,
    result: Receiver<std::io::Result<Option<u32>>>,
    outstanding: bool,
}
impl MtuRefresh {
    #[cfg(test)]
    pub(super) fn fixture() -> (Self, Receiver<()>, SyncSender<std::io::Result<Option<u32>>>) {
        let (request, requests) = mpsc::sync_channel(1);
        let (results, result) = mpsc::sync_channel(1);
        (
            Self {
                request,
                result,
                outstanding: false,
            },
            requests,
            results,
        )
    }

    fn spawn(
        mut query: impl FnMut() -> std::io::Result<Option<u32>> + Send + 'static,
    ) -> Result<Self> {
        let (request, requests) = mpsc::sync_channel(1);
        let (results, result) = mpsc::sync_channel(1);
        // Inherits the backend owner's network namespace. One persistent worker,
        // never replaced on timeout: even a kernel-stalled query has bounded cost.
        // Do not join on owner shutdown; kernel control-plane calls may not return.
        std::thread::Builder::new()
            .name("ntcp-mtu".into())
            .spawn(move || {
                set_internal(true);
                while requests.recv().is_ok() {
                    if results.send(query()).is_err() {
                        break;
                    }
                }
            })
            .map_err(|_| EAGAIN)?;
        Ok(Self {
            request,
            result,
            outstanding: false,
        })
    }
    pub(super) fn request(&mut self) {
        if !self.outstanding && self.request.try_send(()).is_ok() {
            self.outstanding = true;
        }
    }
}

impl Owner {
    pub(super) fn enable_reservations(&mut self, config: &crate::IoConfig) -> Result<()> {
        self.enable_egress(config.egress_capacity, config.gso)?;
        // Each kernel port's MTU is queried for that port's own link.
        for port in &mut self.ports {
            let index = port.index;
            port.mtu_refresh = Some(MtuRefresh::spawn(move || {
                ntcp_io::linux::local_ip_mtu(index)
            })?);
        }
        self.reservation_timeout_us = u64::from(config.output_reservation_timeout_ms) * 1000;
        Ok(())
    }

    pub(super) fn poll_mtu_refresh(&mut self) {
        for port in 0..self.ports.len() {
            self.poll_port_mtu_refresh(port);
        }
    }
    // Every port's refresh: the failing port of an EMSGSIZE is not known.
    pub(super) fn request_mtu_refresh(&mut self) {
        for port in &mut self.ports {
            if let Some(refresh) = &mut port.mtu_refresh {
                refresh.request();
            }
        }
    }
    fn poll_port_mtu_refresh(&mut self, port: usize) {
        let Some(refresh) = &mut self.ports[port].mtu_refresh else {
            return;
        };
        let result = match refresh.result.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Disconnected) => {
                refresh.outstanding = false;
                return;
            }
            Err(mpsc::TryRecvError::Empty) => return,
        };
        refresh.outstanding = false;
        // Failed/unchanged queries must neither spin nor kill other connections.
        // Keep the rejected obligation parked until its original deadline.
        if let Ok(Some(mtu)) = result {
            let now = self.now();
            let ingress = self.ports[port].ingress;
            let changed = if let (Some(host), Some(ingress)) = (&mut self.host, ingress) {
                let changed = host
                    .paths()
                    .link(ingress.link())
                    .is_ok_and(|link| link.mtu != mtu);
                if changed && host.set_link_mtu(ingress.link(), mtu).is_ok() {
                    // Canonical physical state first; budget-only application
                    // also visits reserved/released generations. A failed
                    // rebind remains dirty and is retried during service.
                    let _ = host.service_changes(&mut self.endpoint, now);
                    true
                } else {
                    false
                }
            } else if port == 0 {
                // Explicit raw Endpoint embedding used by low-level fixtures.
                self.defaults
                    .connection
                    .pmtud
                    .is_some_and(|p| p.first_hop_mtu != mtu)
                    && self
                        .endpoint
                        .set_endpoint_first_hop_mtu(self.now(), mtu)
                        .is_ok()
            } else {
                false
            };
            if changed {
                // The defaults describe the `io.*` port's link.
                if let Some(policy) = self.defaults.connection.pmtud.as_mut().filter(|_| port == 0) {
                    policy.first_hop_mtu = mtu;
                }
                if let Some(egress) = &mut self.egress {
                    egress.mtu_refreshed();
                }
            }
        }
    }

    pub(super) fn output_wait(&self) -> std::time::Duration {
        let egress = self.egress.as_ref().unwrap();
        egress.wait(self.now(), self.endpoint.next_deadline())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn reserved_refresh_worker_keeps_namespace_and_one_stalled_query() {
        let namespace = std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino();
        let (entered, entries) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let (done, finished) = mpsc::sync_channel(1);
        let mut refresh = MtuRefresh::spawn(move || {
            entered
                .send(std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino())
                .unwrap();
            released.recv().unwrap();
            done.send(()).unwrap();
            Ok(Some(1400))
        })
        .unwrap();
        refresh.request();
        assert_eq!(
            entries
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap(),
            namespace
        );
        for _ in 0..1000 {
            refresh.request();
        }
        assert!(refresh.outstanding);
        assert!(refresh.result.try_recv().is_err());
        assert!(entries.try_recv().is_err());
        // Shutdown does not join a kernel-stalled worker or spawn a replacement.
        drop(refresh);
        release.send(()).unwrap();
        finished
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
    }
}
