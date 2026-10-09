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
    fn request(&mut self) {
        if !self.outstanding && self.request.try_send(()).is_ok() {
            self.outstanding = true;
        }
    }
}

impl Owner {
    pub(super) fn enable_reservations(
        &mut self,
        config: &crate::IoConfig,
        index: u32,
    ) -> Result<()> {
        self.endpoint.enable_output_reservations().map_err(engine)?;
        self.mtu_refresh = Some(MtuRefresh::spawn(move || {
            ntcp_io::linux::local_ip_mtu(index)
        })?);
        self.reservations = true;
        self.reservation_timeout_us = u64::from(config.output_reservation_timeout_ms) * 1000;
        Ok(())
    }

    fn clear_reservation(&mut self) {
        self.reservation = None;
        self.reservation_deadline = None;
        self.waiting_mtu = false;
    }

    // The acceptance result certifies the token, not completion of the whole
    // obligation. A zero-budget timeout is the existing barrier probe; it does
    // no protocol work and advances time only once the reservation is complete.
    fn completed_reservation(&mut self) -> Result<()> {
        match self.endpoint.on_timeout(self.now(), 0) {
            Ok(_) => self.clear_reservation(),
            Err(EndpointError::OutputReserved) => (),
            Err(e) => return Err(engine(e)),
        }
        Ok(())
    }

    fn start_reservation_deadline(&mut self) {
        if self.reservation.is_some() && self.reservation_deadline.is_none() {
            self.reservation_deadline =
                Some(self.now().saturating_add(self.reservation_timeout_us));
        }
    }

    pub(super) fn abandon_reservation(&mut self) -> Result<()> {
        if let Some(attempt) = self.reservation {
            // Only called for bytes certainly not submitted. Accepted prefixes
            // are committed already; the core discards only the remaining owner.
            if !self.endpoint.abandon_transmit(attempt).map_err(engine)? {
                return Err(EIO);
            }
        }
        self.pending_packet = None;
        self.pending_token = None;
        self.clear_reservation();
        self.drain_timestamps(ClockPair::sample(self));
        self.cancel_unused_backend_timestamps();
        Ok(())
    }

    pub(super) fn expire_reservation(&mut self, now: u64) -> Result<()> {
        if self
            .reservation_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            self.abandon_reservation()?;
        }
        Ok(())
    }

    pub(super) fn poll_mtu_refresh(&mut self) {
        let Some(refresh) = &mut self.mtu_refresh else {
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
        if let Ok(Some(mtu)) = result
            && self
                .defaults
                .connection
                .pmtud
                .is_some_and(|p| p.first_hop_mtu != mtu)
            && self
                .endpoint
                .set_endpoint_first_hop_mtu(self.now(), mtu)
                .is_ok()
        {
            self.defaults.connection.pmtud = Some(ntcp::PmtudConfig::new(mtu));
            self.waiting_mtu = false;
        }
    }

    pub(super) fn submit_reserved_packet(&mut self) -> Result<TxOutcome> {
        let result = if let Some(tun) = &mut self.tun {
            submit_packet(tun, &mut self.pending_packet)
        } else {
            self.transmit_ethernet()
        };
        match result {
            Ok(TxOutcome::Submitted) => {
                if let Some(attempt) = self.reservation {
                    if !self
                        .endpoint
                        .accept_transmit(self.now(), attempt)
                        .map_err(engine)?
                    {
                        return Err(EIO);
                    }
                    self.completed_reservation()?;
                }
                if self.tun.is_some() {
                    let token = self.pending_token.take();
                    self.software_transmitted(token, timestamps::realtime());
                }
                self.pending_packet = None;
                self.pending_token = None;
                Ok(TxOutcome::Submitted)
            }
            Ok(TxOutcome::WouldBlock) => {
                self.start_reservation_deadline();
                Ok(TxOutcome::WouldBlock)
            }
            Err(e) if e.raw_os_error() == Some(EMSGSIZE) && self.reservation.is_some() => {
                self.start_reservation_deadline();
                if !self
                    .endpoint
                    .reject_unsubmitted(self.reservation.unwrap())
                    .map_err(engine)?
                {
                    return Err(EIO);
                }
                self.pending_packet = None;
                self.pending_token = None;
                self.waiting_mtu = true;
                if let Some(refresh) = &mut self.mtu_refresh {
                    refresh.request();
                }
                self.completed_reservation()?; // Stateless output is best-effort discard.
                self.drain_timestamps(ClockPair::sample(self));
                self.cancel_unused_backend_timestamps();
                Ok(TxOutcome::WouldBlock)
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(TxOutcome::WouldBlock),
            Err(e) => Err(e.raw_os_error().unwrap_or(EIO)),
        }
    }

    pub(super) fn output_wait(&self) -> std::time::Duration {
        let now = self.now();
        // A parked MTU query has no useful pacing deadline; a pending backend
        // packet must be retried at a bounded cadence, not an overdue TCP timer.
        let core = if self.waiting_mtu || self.pending_packet.is_some() {
            None
        } else {
            self.endpoint.next_deadline()
        };
        core.into_iter()
            .chain(self.reservation_deadline)
            .min()
            .map(|d| std::time::Duration::from_micros(d.saturating_sub(now)))
            .unwrap_or(std::time::Duration::from_millis(1))
            .min(std::time::Duration::from_millis(1))
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
