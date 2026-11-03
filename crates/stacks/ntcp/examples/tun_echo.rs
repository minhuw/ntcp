// Run as: tun_echo TUN_NAME LOCAL_IP TCP_PORT [PEER_SOCKET_ADDR].
// TCP_PORT also names a UDP echo service. Fragmented input is reassembled
// (up to the largest IP datagram). UDP and ICMP Echo replies larger than the
// connectionless effective size are source-fragmented (every IPv4 fragment
// with DF) within the peers' reassembly capacity; TCP is never fragmented.
// Operational settings (deployment knowledge, validated and reported at
// startup):
//   NTCP_UDP_ECHO_MODE=fragment|refuse  UDP echo replies are fragmented when
//     needed (default) or, with refuse, only ever sent whole: a reply beyond
//     the path's unfragmented payload limit is refused.
//   NTCP_PEER_REASSEMBLY_IPV4 / NTCP_PEER_REASSEMBLY_IPV6=OCTETS  the
//     complete reconstructed IP datagram the peers can reassemble, for the
//     local family only; unset keeps the receiver guarantee (576 / 1500).
//   NTCP_SOURCE_QUIET=SECONDS|never  earlier emission from LOCAL_IP ceased
//     at least SECONDS before startup (never: there was none, for example a
//     newly created address). Unset, no IP Identification is issued for one
//     maximum datagram lifetime (120 s) after startup.
//   NTCP_CONTROL_SOCKET=PATH  opt-in local path control socket (absolute
//     pathname in a private 0700 directory owned by this uid) for
//     ntcp-pathctl: route and path query, discovery disable/enable,
//     administrative estimates, plateaus and search aging. Unset, none.
//   NTCP_CONTROL_ALLOW_UIDS=UID[,UID...]  peer uids allowed on the control
//     socket (SO_PEERCRED); unset, only this process's effective uid.
//   NTCP_ORIGINATE_RR=SLOTS,EXPECTED  the active open to PEER_SOCKET_ADDR
//     originates Record Route with SLOTS address slots, for EXPECTED
//     registrations on its path (every recording visit, this host and the
//     destination included). Needs NTCP_IPV4_OPTIONS=1.
//   NTCP_ORIGINATE_TS=times|addresses,SLOTS,EXPECTED  likewise a Timestamp
//     option, flag 0 (times) or 1 (addresses and times). The capacities must
//     hold the expectation and fit the 40-octet option area together; the
//     option area and its expected route are fixed for the connection, which
//     ends if its route changes.
// The caller must configure the TUN interface (MTU 1500) and routes
// beforehand. This adapter exchanges IP packets, not Ethernet frames; it does
// not configure the host or implement ARP, routing, or ICMP services beyond
// Echo and reassembly errors.

#[cfg(target_os = "linux")]
mod linux {
    use ntcp::{
        AddressValidation, ConnectionConfig, ConnectionId, Endpoint, EndpointConfig, EndpointError,
        Error, Event, PmtudConfig, State, Tuple,
    };
    #[cfg(test)]
    use ntcp::{IpMetadata, Ipv4Options};
    use ntcp_host::{
        BackendOutcome, Continuity, DatagramError, DeferredIcmp, EgressContext, Host,
        IcmpDispatch, IngressContext, Processed, ProcessedEnvelope, Received, Submission,
        SubmissionTicket, UdpEvent, UdpFlowId, UdpSend, UdpSendError, UdpSendMode, UdpSent, path,
    };
    use ntcp_io::{PacketIo, TxOutcome};
    use ntcp_io_tun::Tun;
    use std::{
        collections::VecDeque,
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
        os::fd::AsRawFd,
        time::Instant,
    };

    const MTU: usize = 1500;
    const IP_HEADER: usize = 20;
    const MAX_FLOWS: usize = 128;
    const BUDGET: usize = 32;
    const MAX_IP_PACKET: usize = 65575;
    const TICK_US: u64 = 10_000;
    const UDP_HEADER: usize = 8;
    // The largest datagram each family can carry (IPv4 Total Length 65535;
    // IPv6 Payload Length 65535 after the 40-octet header). The echo
    // services accept any datagram a peer may send, so reassembly is sized
    // for these, whatever the peer's fragmentation.
    const IPV4_DATAGRAM: usize = 65535;
    const IPV6_DATAGRAM: usize = 65575;

    fn host_error(error: ntcp_host::Error) -> io::Error {
        io::Error::other(format!("IP host: {error:?}"))
    }

    // How earlier emission from the local address relates to this process.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SourceQuiet {
        // Unknown: an earlier process may have emitted from it until now.
        Unknown,
        // Asserted: it ceased at least this many seconds before startup.
        Seconds(u64),
        // Asserted: there was no earlier emission from it at all.
        Never,
    }

    // Datagram service settings: deployment knowledge the Host cannot learn
    // itself, so the operator states it (see the usage notes above).
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DatagramSettings {
        udp_mode: UdpSendMode,
        // Complete reconstructed IP octets the peers reassemble, for the
        // local family; None keeps RFC 1122 / RFC 8200's guarantee.
        peer_reassembly: Option<u32>,
        quiet: SourceQuiet,
    }

    impl Default for DatagramSettings {
        fn default() -> Self {
            Self {
                udp_mode: UdpSendMode::Fragment,
                peer_reassembly: None,
                quiet: SourceQuiet::Unknown,
            }
        }
    }

    impl DatagramSettings {
        // Each setting is validated before use; an unparsable or
        // inapplicable value is refused at startup, never ignored.
        fn parse(
            local: IpAddr,
            udp_mode: Option<&str>,
            ipv4_capacity: Option<&str>,
            ipv6_capacity: Option<&str>,
            quiet: Option<&str>,
        ) -> io::Result<Self> {
            let udp_mode = match udp_mode {
                None | Some("fragment") => UdpSendMode::Fragment,
                Some("refuse") => UdpSendMode::Refuse,
                Some(_) => return Err(invalid("NTCP_UDP_ECHO_MODE must be fragment or refuse")),
            };
            let (capacity, other, floor, ceiling, name) = if local.is_ipv4() {
                (ipv4_capacity, ipv6_capacity, 576, IPV4_DATAGRAM, "NTCP_PEER_REASSEMBLY_IPV4")
            } else {
                (ipv6_capacity, ipv4_capacity, 1500, IPV6_DATAGRAM, "NTCP_PEER_REASSEMBLY_IPV6")
            };
            if other.is_some() {
                return Err(invalid(
                    "a peer reassembly capacity applies only to the local address family",
                ));
            }
            let peer_reassembly = capacity
                .map(|value| {
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|n| (floor..=ceiling as u32).contains(n))
                        .ok_or_else(|| {
                            invalid(&format!(
                                "{name} must be complete IP octets in {floor}..={ceiling}"
                            ))
                        })
                })
                .transpose()?;
            let quiet = match quiet {
                None => SourceQuiet::Unknown,
                Some("never") => SourceQuiet::Never,
                Some(value) => SourceQuiet::Seconds(value.parse().map_err(|_| {
                    invalid("NTCP_SOURCE_QUIET must be whole seconds or never")
                })?),
            };
            Ok(Self {
                udp_mode,
                peer_reassembly,
                quiet,
            })
        }

        fn from_env(local: IpAddr) -> io::Result<Self> {
            let var = |name: &str| match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(_) => Err(invalid(&format!("invalid {name}"))),
            };
            let (mode, v4, v6, quiet) = (
                var("NTCP_UDP_ECHO_MODE")?,
                var("NTCP_PEER_REASSEMBLY_IPV4")?,
                var("NTCP_PEER_REASSEMBLY_IPV6")?,
                var("NTCP_SOURCE_QUIET")?,
            );
            Self::parse(
                local,
                mode.as_deref(),
                v4.as_deref(),
                v6.as_deref(),
                quiet.as_deref(),
            )
        }

        // The allocator's start: one full MDL after earlier emission from
        // the local address may have ceased (RFC 6864 section 4.3).
        fn continuity(&self, started: u64) -> Continuity {
            match self.quiet {
                SourceQuiet::Unknown => Continuity::QuietSince(started),
                SourceQuiet::Seconds(seconds) => Continuity::QuietFor {
                    at: started,
                    seconds,
                },
                SourceQuiet::Never => Continuity::QuietFor {
                    at: started,
                    seconds: u64::MAX,
                },
            }
        }

        fn report(&self, local: IpAddr) -> String {
            let mode = match self.udp_mode {
                UdpSendMode::Refuse => "refuse (whole replies only)",
                _ => "fragment",
            };
            let capacity = match self.peer_reassembly {
                Some(octets) => format!("{octets} octets (stated)"),
                None => format!(
                    "{} octets (receiver guarantee)",
                    if local.is_ipv4() { 576 } else { 1500 }
                ),
            };
            let lifetime = ntcp_host::DEFAULT_LIFETIME_SECONDS;
            let identifiers = match self.quiet {
                SourceQuiet::Unknown => format!(
                    "none for {lifetime} s (earlier emission from {local} is unknown)"
                ),
                SourceQuiet::Seconds(seconds) => format!(
                    "none for {} s (asserted: emission from {local} ceased {seconds} s before \
                     startup)",
                    u64::from(lifetime).saturating_sub(seconds)
                ),
                SourceQuiet::Never => {
                    format!("immediately (asserted: no earlier emission from {local})")
                }
            };
            format!(
                "datagram settings: UDP echo mode {mode}; peer reassembly capacity {capacity}; \
                 IP identifiers {identifiers}; MDL {lifetime} s"
            )
        }
    }

    // Malformed/unsupported wire input remains a silent discard; bounded
    // factory/provider failures remain observable to run().
    fn silent<T>(result: Result<T, ntcp_host::Error>) -> io::Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(
                ntcp_host::Error::Codec(_)
                | ntcp_host::Error::Unsupported
                | ntcp_host::Error::Path(path::Error::NoRoute),
            ) => Ok(None),
            Err(error) => Err(host_error(error)),
        }
    }

    // Input whose owner's output is reserved. TCP segments are classified by
    // their tuple; ICMP errors only by the Host dispatcher's correlation with
    // its own submission evidence, whose deferred token the replay applies.
    #[derive(Clone, Copy)]
    enum Retained {
        Tcp(ConnectionId),
        Icmp(DeferredIcmp),
    }
    impl Retained {
        fn owner(self) -> ConnectionId {
            match self {
                Self::Tcp(owner) => owner,
                Self::Icmp(deferred) => deferred.owner(),
            }
        }
    }

    // A retained TCP segment is the complete datagram (never a fragment)
    // after destination processing: its processed envelope and bytes. A
    // deferred ICMP report needs only its token.
    struct RetainedIngress {
        owner: Retained,
        envelope: Option<ProcessedEnvelope>,
        bytes: Vec<u8>,
    }

    // IPv4 Timestamp time for destination and origin recording from the
    // characterized Linux UTC source (ntcp-clock): UTC milliseconds since
    // midnight when its sample is standard, otherwise the loop's elapsed
    // milliseconds with the RFC 791 high-order bit set. Recording samples it
    // only for a slot it writes, one kernel acquisition each; the source
    // keeps only its suspend-continuity state across samples.
    struct Utc {
        clock: ntcp_clock::UtcClock,
        start: Instant,
        #[cfg(test)]
        acquisitions: usize,
    }
    impl Utc {
        fn new(start: Instant) -> Self {
            Self {
                clock: ntcp_clock::UtcClock::new(),
                start,
                #[cfg(test)]
                acquisitions: 0,
            }
        }
    }
    impl ntcp::Ipv4TimestampProvider for Utc {
        fn ipv4_timestamp(&mut self) -> Option<ntcp::Ipv4Timestamp> {
            #[cfg(test)]
            {
                self.acquisitions += 1;
            }
            let elapsed = self.start.elapsed().as_millis() as u64;
            // A standard value is below 86 400 000, a nonstandard one marked.
            ntcp::Ipv4Timestamp::from_wire(self.clock.sample(elapsed).value).ok()
        }
    }

    // A test's fixed time, marked nonstandard.
    #[cfg(test)]
    struct Sample(u32);
    #[cfg(test)]
    impl ntcp::Ipv4TimestampProvider for Sample {
        fn ipv4_timestamp(&mut self) -> Option<ntcp::Ipv4Timestamp> {
            Some(ntcp::Ipv4Timestamp::nonstandard(self.0))
        }
    }

    // A test's own read-only adjtimex read of the kernel clock the UTC
    // source samples: its time in nanoseconds since the epoch when the read
    // satisfies that source's per-sample conditions (1) and (2) (no kernel
    // error predicate, neither TIME_ERROR nor TIME_OOP, maximum error within
    // 0..=16 s).
    #[cfg(test)]
    fn utc_read() -> Option<i128> {
        // SAFETY: timex is plain data; all-zero sets modes 0, a read-only call.
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        // SAFETY: `tx` is a valid, writable timex for the call.
        let state = unsafe { libc::adjtimex(&mut tx) };
        let status = tx.status;
        let error = status & (libc::STA_UNSYNC | libc::STA_CLOCKERR) != 0
            || status & (libc::STA_PPSFREQ | libc::STA_PPSTIME) != 0
                && status & libc::STA_PPSSIGNAL == 0
            || status & (libc::STA_PPSTIME | libc::STA_PPSJITTER)
                == libc::STA_PPSTIME | libc::STA_PPSJITTER
            || status & libc::STA_PPSFREQ != 0
                && status & (libc::STA_PPSWANDER | libc::STA_PPSERROR) != 0;
        if state == -1
            || error
            || matches!(state, libc::TIME_ERROR | libc::TIME_OOP)
            || !(0..=16_000_000).contains(&tx.maxerror)
        {
            return None;
        }
        let unit = if status & libc::STA_NANO != 0 {
            1
        } else {
            1000
        };
        Some(i128::from(tx.time.tv_sec) * 1_000_000_000 + i128::from(tx.time.tv_usec) * unit)
    }

    // An IPv4 Timestamp value recorded between the `before` and `after`
    // reads: true for a standard value, which both reads must accept and
    // which must lie within their window in milliseconds since midnight UT
    // (across midnight too); false for a value marked nonstandard by the
    // high-order bit.
    #[cfg(test)]
    fn standard_time(value: u32, before: Option<i128>, after: Option<i128>) -> bool {
        const DAY: i128 = 86_400_000;
        if value & 0x8000_0000 != 0 {
            return false;
        }
        let (Some(before), Some(after)) = (before, after) else {
            panic!("unmarked time {value} without a healthy kernel clock bracket");
        };
        let (first, last) = (before.div_euclid(1_000_000), after.div_euclid(1_000_000));
        let offset = (i128::from(value) - first).rem_euclid(DAY);
        assert!(
            i128::from(value) < DAY && offset <= last - first,
            "unmarked time {value} outside the UTC window {first}..={last}"
        );
        true
    }

    // One actual caller-owned L3 forwarding port. All ingress storage is
    // allocated once, independently of remote traffic or transport buffers.
    struct TunHost {
        host: Host,
        ingress: IngressContext,
        local: IpAddr,
        dscp: u8,
        options_enabled: bool,
        received: VecDeque<RetainedIngress>,
        free: Vec<Vec<u8>>,
        // Destination of each datagram reassembly completes, owned until it
        // is dispatched or copied into retention.
        completed: Vec<u8>,
        // TCP frames waiting for an IPv4 Identification.
        identifier_held: IdentifierHeld,
    }

    impl TunHost {
        #[cfg(test)]
        fn attach(
            endpoint: &mut Endpoint,
            config: &EndpointConfig,
            local: IpAddr,
        ) -> io::Result<Self> {
            Self::attach_with(endpoint, config, local, &DatagramSettings::default(), 0)
        }

        fn attach_with(
            endpoint: &mut Endpoint,
            config: &EndpointConfig,
            local: IpAddr,
            settings: &DatagramSettings,
            started: u64,
        ) -> io::Result<Self> {
            // Independent public lifetime identity, never derived from TCP's
            // confidential ISN/Fast Open key or an interface/address alone.
            let identity = acquire_secret()?;
            // Occupied transport generations + one provisional factory and
            // stateless lease; one serialized rebind gets migration headroom.
            // Peer packets never create forwarding routes.
            let (paths, mut limits) =
                ntcp_host::managed_limits(config, 1, 1, 1, 1, 1).map_err(host_error)?;
            limits.datagrams = tun_datagrams(local.is_ipv4(), settings.peer_reassembly);
            // One UDP echo flow. Its receive and advice queues match the
            // per-iteration read budget, so one loop drains what one read
            // pass can deliver; slots hold the largest reassembled payload.
            // Evicted replies keep exact signatures for a client sustaining
            // one read budget of datagrams per second over the feedback
            // horizon, so its later ICMP stays attributable to the echo.
            let horizon_seconds =
                limits.ledger.feedback_horizon / config.connection.timebase.units_per_second;
            let evicted_signatures = usize::try_from(horizon_seconds)
                .ok()
                .and_then(|seconds| seconds.checked_mul(BUDGET))
                .ok_or_else(|| host_error(ntcp_host::Error::Capacity))?;
            // Reassembly: one read pass's worth of concurrent datagrams, the
            // bytes of one largest datagram buffered at a time (the IPv6
            // first fragment also stores its Fragment header), and enough
            // descriptors for that datagram in 8-octet fragments, the worst
            // conforming fragmentation. The IPv4 timeout is RFC 1122
            // section 3.3.2's lower bound, which loses no conforming
            // datagram and holds incomplete state for the shortest time.
            let reassembly = ntcp_host::ReassemblyLimits {
                assemblies: BUDGET,
                fragments: IPV4_DATAGRAM.div_ceil(8),
                buffered_bytes: IPV6_DATAGRAM + 8,
                ipv4_datagram: IPV4_DATAGRAM,
                ipv6_datagram: IPV6_DATAGRAM,
                ipv4_timeout_seconds: 60,
            };
            let datagram = if local.is_ipv4() {
                IPV4_DATAGRAM - IP_HEADER
            } else {
                IPV6_DATAGRAM - IPV6_HEADER
            };
            // UDP receive slots hold the largest payload reassembly can
            // complete; the flow's ledger attempts cover every fragment of
            // one reply (`limits.datagrams.max_fragments`).
            let (paths, limits) = ntcp_host::managed_udp_limits(
                paths,
                limits,
                ntcp_host::UdpLimits {
                    flows: 1,
                    receive_datagrams: BUDGET,
                    max_payload: datagram - UDP_HEADER,
                    events: BUDGET,
                    evicted_signatures,
                    // The echo flow sends no Probe-mode datagrams; one
                    // receipt is the minimum a flow holds.
                    probe_receipts: 1,
                },
            )
            .map_err(host_error)?;
            // Echo Replies and reassembly errors: one read pass's worth of
            // messages, each as large as a reassembled Echo Request.
            let (paths, mut limits) = ntcp_host::managed_icmp_output_limits(
                paths,
                limits,
                ntcp_host::IcmpOutputLimits {
                    messages: BUDGET,
                    message_bytes: datagram,
                    hop_limit: config.hop_limit,
                },
            )
            .map_err(host_error)?;
            limits.reassembly = reassembly;
            let mut host = Host::new(
                path::ContextId::new(u128::from_ne_bytes(identity[..16].try_into().unwrap())),
                paths,
                limits,
                endpoint.caller_timebase(),
            )
            .map_err(host_error)?;
            // Unpredictable identifiers from the same OS CSPRNG acquisition
            // as the TCP secret; a failure is backpressure, never a weaker
            // source.
            host.set_entropy(Box::new(|bytes: &mut [u8]| {
                os_entropy(bytes).map_err(|_| ntcp_host::EntropyError)
            }));
            host.start_identifiers(settings.continuity(started))
                .map_err(host_error)?;
            let forwarder = path::ForwarderId(1);
            let ingress = host
                .register_link(
                    path::InterfaceKey(1),
                    MTU as u32, // runtime_config checked the actual fixed TUN MTU.
                    ntcp_host::ReceiveCapabilities {
                        max_ip_packet: MAX_IP_PACKET,
                        ipv4: if local.is_ipv4() {
                            ntcp_host::Ipv4Receive::Enabled {
                                interpretation: config.ipv4_options_enabled,
                                source_routes: config.ipv4_options_enabled,
                            }
                        } else {
                            ntcp_host::Ipv4Receive::Disabled
                        },
                        ipv6: if local.is_ipv6() {
                            ntcp_host::Ipv6Receive::BaseHeader
                        } else {
                            ntcp_host::Ipv6Receive::Disabled
                        },
                        gro: false,
                    },
                    ntcp_host::Forwarding::Forwarder(forwarder),
                )
                .map_err(host_error)?;
            host.register_source(
                path::ScopedAddress::new(local, None).map_err(|e| host_error(e.into()))?,
                ingress.link(),
            )
            .map_err(host_error)?;
            host.add_route(path::Route {
                destination: path::IpPrefix::new(
                    if local.is_ipv4() {
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    } else {
                        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                    },
                    0,
                )
                .map_err(|e| host_error(e.into()))?,
                source: None,
                dscp: None,
                link: ingress.link(),
                next_hop: path::NextHop::Forwarder(forwarder),
                metric: 0,
            })
            .map_err(host_error)?;
            let mut free = Vec::new();
            free.try_reserve_exact(BUDGET)
                .map_err(|_| host_error(ntcp_host::Error::Allocation))?;
            for _ in 0..BUDGET {
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(MAX_IP_PACKET)
                    .map_err(|_| host_error(ntcp_host::Error::Allocation))?;
                free.push(bytes);
            }
            let mut received = VecDeque::new();
            received
                .try_reserve_exact(BUDGET)
                .map_err(|_| host_error(ntcp_host::Error::Allocation))?;
            let mut completed = Vec::new();
            completed
                .try_reserve_exact(MAX_IP_PACKET)
                .map_err(|_| host_error(ntcp_host::Error::Allocation))?;
            completed.resize(MAX_IP_PACKET, 0);
            // One output reservation per connection and the stateless lane:
            // an owner whose frame waits for an IPv4 Identification keeps
            // its reservation while every other owner still finds one.
            let owners = config.max_connections.saturating_add(1);
            endpoint
                .enable_output_reservations_with_capacity(owners)
                .map_err(engine)?;
            let identifier_held = IdentifierHeld::new(owners)?;
            host.attach(endpoint).map_err(host_error)?;
            Ok(Self {
                host,
                ingress,
                local,
                dscp: config.dscp,
                options_enabled: config.ipv4_options_enabled,
                received,
                free,
                completed,
                identifier_held,
            })
        }

        // TCP segments only; ICMP ownership is the Host dispatcher's decision.
        fn owner(&self, endpoint: &Endpoint, datagram: Processed) -> Option<ConnectionId> {
            let packet = self.host.decode_datagram(datagram).ok()?;
            if packet.protocol != 6 {
                return None;
            }
            let tcp = ntcp::wire::parse(packet.ip, packet.payload).ok()?;
            endpoint.connection_id(Tuple {
                local: SocketAddr::new(packet.ip.destination, tcp.header.destination_port),
                remote: SocketAddr::new(packet.ip.source, tcp.header.source_port),
            })
        }

        // Retention follows completion: a TCP owner keeps the complete
        // datagram, never a fragment.
        fn retain(&mut self, owner: Retained, datagram: Option<Processed>) -> io::Result<()> {
            let mut bytes = self
                .free
                .pop()
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
            // A deferred ICMP report needs only its token; its buffer still
            // bounds retention.
            if let Some(datagram) = datagram {
                bytes.extend_from_slice(datagram.bytes());
            }
            self.received.push_back(RetainedIngress {
                owner,
                envelope: datagram.map(|d| d.envelope()),
                bytes,
            });
            Ok(())
        }

        fn can_receive(&self) -> bool {
            !self.free.is_empty()
        }

        fn replay(&mut self, endpoint: &mut Endpoint, time: u64) -> io::Result<()> {
            for _ in 0..self.received.len() {
                let mut retained = self.received.pop_front().unwrap();
                if endpoint.is_output_reserved(retained.owner.owner()) {
                    self.received.push_back(retained);
                    continue;
                }
                match retained.owner {
                    // A tuple reused by another generation cannot inherit input.
                    Retained::Tcp(owner) => {
                        if let Some(datagram) = retained
                            .envelope
                            .and_then(|envelope| envelope.datagram(&retained.bytes))
                            && self.owner(endpoint, datagram) == Some(owner)
                        {
                            silent(self.host.input_datagram(
                                endpoint,
                                time,
                                datagram,
                                ntcp::RxPacketMetadata::default(),
                                self.dscp,
                            ))?;
                        }
                    }
                    // The token carries the validated report for this exact
                    // generation; the Host discards it as stale otherwise.
                    Retained::Icmp(deferred) => {
                        if let Some(IcmpDispatch::Deferred(again)) =
                            silent(self.host.replay_icmp(endpoint, deferred, time))?
                        {
                            retained.owner = Retained::Icmp(again);
                            self.received.push_back(retained);
                            continue;
                        }
                    }
                }
                let mut bytes = retained.bytes;
                bytes.clear();
                self.free.push(bytes);
            }
            Ok(())
        }

        // Drain the Host's Echo Replies (source-fragmented when needed) and
        // reassembly errors through the same one-call TUN backend. A blocked
        // TUN before any packet left keeps the message queued.
        fn icmp_output(
            &mut self,
            time: u64,
            output: &mut [u8],
            backend: &mut impl PacketIo,
        ) -> io::Result<bool> {
            let mut progress = false;
            let port = self.ingress.link();
            for _ in 0..BUDGET {
                let mut failure = None;
                match self.host.icmp_output(time, output, |egress, frame| {
                    if !tun_egress(port, egress.link, egress.next_hop) {
                        return BackendOutcome::NotSubmitted;
                    }
                    tun_transmit(backend, frame, &mut failure)
                }) {
                    Ok(None) => break,
                    Ok(Some(BackendOutcome::WouldBlock)) => return Ok(progress),
                    Ok(Some(BackendOutcome::Unknown)) => {
                        return Err(
                            failure.unwrap_or_else(|| io::Error::other("unknown TUN outcome"))
                        );
                    }
                    Ok(Some(_)) => {}
                    // Consumed unsent, counted by the Host: a reply beyond
                    // the path budget that may not be fragmented, or one
                    // with no identifier available.
                    Err(error) => eprintln!("ICMP output not sent: {error:?}"),
                }
                progress = true;
            }
            Ok(progress)
        }
    }

    // Source fragmentation for the replies this Host originates. Enough
    // fragments for the largest reply reassembly can complete, cut to the
    // smallest link each family must support (68 and 1280 octets), so a
    // narrowed path never leaves a reply unsent for want of fragments.
    // Identifier leases live for the whole MDL: IPv4 tuples for every TCP
    // flow's remote plus one read pass of distinct echo peers; IPv6 leases
    // for one read pass of fragmented replies per second over the MDL.
    // Beyond them a reply is sent whole when it fits, otherwise not at all.
    fn tun_datagrams(ipv4: bool, peer_reassembly: Option<u32>) -> ntcp_host::DatagramLimits {
        let (largest, room) = if ipv4 {
            (IPV4_DATAGRAM - IP_HEADER, 68 - IP_HEADER)
        } else {
            (IPV6_DATAGRAM - IPV6_HEADER, 1280 - IPV6_HEADER - 8)
        };
        let lifetime = ntcp_host::DEFAULT_LIFETIME_SECONDS;
        ntcp_host::DatagramLimits {
            max_fragments: largest.div_ceil(room & !7),
            identifiers: ntcp_host::IdentifierLimits {
                lifetime_seconds: lifetime,
                ipv4_tuples: if ipv4 { MAX_FLOWS + BUDGET } else { 0 },
                ipv6_leases: if ipv4 { 0 } else { BUDGET * lifetime as usize },
            },
            connectionless: ntcp_host::ConnectionlessSizing::default(),
            peer_reassembly_ipv4: peer_reassembly.filter(|_| ipv4),
            peer_reassembly_ipv6: peer_reassembly.filter(|_| !ipv4),
            // The Echo adjunct (RFC 4821 section 10.3) confirms larger
            // connectionless sizes for the destinations of fragmented
            // replies: one entry per flow and per read pass of Echo peers.
            adjunct: ntcp_host::AdjunctLimits {
                paths: MAX_FLOWS + BUDGET,
                ..Default::default()
            },
        }
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn engine(error: EndpointError) -> io::Error {
        io::Error::other(format!("TCP engine: {error:?}"))
    }

    fn fill_secret(read: impl FnMut(&mut [u8]) -> io::Result<usize>) -> io::Result<[u8; 32]> {
        let mut secret = [0; 32];
        fill_bytes(&mut secret, read)?;
        Ok(secret)
    }

    fn fill_bytes(
        secret: &mut [u8],
        mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
    ) -> io::Result<()> {
        let mut filled = 0;
        while filled < secret.len() {
            match read(&mut secret[filled..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "getrandom made no progress",
                    ));
                }
                Ok(count) if count <= secret.len() - filled => filled += count,
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "getrandom returned an invalid length",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
    //= type=implementation
    //= reason=Bounded evidence: initialized OS CSPRNG acquisition with error propagation, combined with core HMAC key dependence; tests do not prove entropy or confidentiality.
    //# F() MUST NOT be computable from the outside (MUST-9), or
    //# an attacker could still guess at sequence numbers from the ISN used
    //# for some other connection.

    // The runtime must provide a confidential, unpredictable key. Flags 0 waits
    // for Linux's CSPRNG to initialize; errors abort startup without fallback.
    fn acquire_secret() -> io::Result<[u8; 32]> {
        fill_secret(getrandom)
    }

    // The Host's identifier entropy: the same blocking acquisition.
    fn os_entropy(bytes: &mut [u8]) -> io::Result<()> {
        fill_bytes(bytes, getrandom)
    }

    fn getrandom(buffer: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buffer is exclusively borrowed and writable for exactly
        // buffer.len() bytes throughout the syscall; getrandom retains no pointer.
        let count = unsafe { libc::getrandom(buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }

    #[cfg(test)]
    use ntcp_ip_common::checksum;

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
    //#   A TCP implementation MUST silently discard an incoming SYN segment
    //# |  that is addressed to a broadcast or multicast address [(MUST-57)].

    // This parser rejects address classes; Endpoint additionally validates the
    // configured interface subnet before processing TCP.
    fn unicast(ip: Ipv4Addr) -> bool {
        // Reject unspecified, multicast and reserved IPs.
        ip.octets()[0] != 0 && ip.octets()[0] < 224
    }

    #[cfg(test)]
    fn parse_ipv4(packet: &[u8], local: Ipv4Addr) -> Option<(IpMetadata, &[u8])> {
        parse_ipv4_options(packet, local, false, 0).map(|(ip, tcp, _)| (ip, tcp))
    }

    // The active open's originated Record Route and Timestamp request with
    // the registrations the operator expects on its path
    // (NTCP_ORIGINATE_RR, NTCP_ORIGINATE_TS); the stack never infers hop
    // counts. Both travel on an explicit empty source route, the direct
    // route RR/TS opens require. None when neither is set.
    fn origination(
        record_route: Option<&str>,
        timestamp: Option<&str>,
    ) -> io::Result<
        Option<(
            ntcp::OutgoingIpv4Options,
            ntcp::ExpectedRegistrations<'static>,
        )>,
    > {
        if record_route.is_none() && timestamp.is_none() {
            return Ok(None);
        }
        let counts = |slots: &str, expected: &str| -> Option<(u8, u8)> {
            let number = |value: &str| {
                value
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| value.parse::<u8>().ok())
                    .flatten()
            };
            Some((number(slots)?, number(expected)?))
        };
        let mut options = ntcp::OutgoingIpv4Options {
            source_route: Some(
                ntcp::SourceRoute::new(&[], false).map_err(|_| invalid("empty source route"))?,
            ),
            ..Default::default()
        };
        let mut expected = ntcp::ExpectedRegistrations::default();
        if let Some(value) = record_route {
            let (slots, count) = value
                .split_once(',')
                .and_then(|(slots, expected)| counts(slots, expected))
                .ok_or_else(|| invalid("NTCP_ORIGINATE_RR must be SLOTS,EXPECTED"))?;
            options.record_route_slots = Some(slots);
            expected.record_route = Some(count);
        }
        if let Some(value) = timestamp {
            let mut fields = value.split(',');
            let request = match (fields.next(), fields.next(), fields.next(), fields.next()) {
                (Some(form), Some(slots), Some(count), None) => {
                    counts(slots, count).and_then(|(slots, count)| match form {
                        "times" => Some((ntcp::TimestampRequest::Times(slots), count)),
                        "addresses" => Some((ntcp::TimestampRequest::AddressTimes(slots), count)),
                        _ => None,
                    })
                }
                _ => None,
            };
            let (request, count) = request.ok_or_else(|| {
                invalid("NTCP_ORIGINATE_TS must be times|addresses,SLOTS,EXPECTED")
            })?;
            options.timestamp = Some(request);
            expected.timestamp = Some(ntcp::ExpectedTimestamps::Count(count));
        }
        Ok(Some((options, expected)))
    }

    fn options_enabled(value: Option<&str>) -> io::Result<bool> {
        match value {
            None => Ok(false),
            Some("1") => Ok(true),
            _ => Err(invalid("NTCP_IPV4_OPTIONS must be exactly 1 or unset")),
        }
    }

    #[cfg(test)]
    fn parse_ipv4_options(
        packet: &[u8],
        local: Ipv4Addr,
        enabled: bool,
        timestamp: u32,
    ) -> Option<(IpMetadata, &[u8], Ipv4Options)> {
        // Preserve the example's historical IPv4 padding allowance, while the
        // reusable complete-frame codec requires exact bounds.
        let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
        let parsed = ntcp_ip::parse(packet.get(..total)?, enabled).ok()?;
        let (IpAddr::V4(source), IpAddr::V4(destination)) =
            (parsed.ip.source, parsed.ip.destination)
        else {
            return None;
        };
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //# |  An incoming SYN with an invalid source address MUST be ignored
        //# |  either by TCP or by the IP layer [(MUST-63)] (see
        //# |  Section 3.2.1.3).
        // Endpoint additionally checks directed broadcasts in this TUN subnet.
        if parsed.protocol != 6 || destination != local || !unicast(source) || !unicast(destination)
        {
            return None;
        }
        // Like Host destination processing, disabled interpretation keeps
        // every option as received.
        let options = if enabled {
            parsed.ipv4_options.record(local, timestamp).ok()?
        } else {
            parsed.ipv4_options
        };
        Some((parsed.ip, parsed.payload, options))
    }

    #[cfg(test)]
    fn build_ipv4(
        packet: &mut [u8],
        ip: IpMetadata,
        tcp_len: usize,
        hop_limit: u8,
        dscp: u8,
        ecn: u8,
    ) -> io::Result<usize> {
        build_ipv4_options(
            packet,
            ntcp::Transmit {
                connection: None,
                tx_timestamp: None,
                ip,
                len: tcp_len,
                hop_limit,
                dscp,
                ecn,
                ipv4_options: ntcp::OutgoingIpv4Options::default(),
            },
            0,
        )
    }

    fn build_ipv4_options(
        packet: &mut [u8],
        transmit: ntcp::Transmit,
        timestamp: u32,
    ) -> io::Result<usize> {
        let (IpAddr::V4(source), IpAddr::V4(destination)) =
            (transmit.ip.source, transmit.ip.destination)
        else {
            return Err(invalid("expected IPv4 transmit addresses"));
        };
        if !unicast(source) || !unicast(destination) {
            return Err(invalid("invalid outgoing IPv4 address"));
        }
        let capacity = packet.len().min(MTU);
        ntcp_ip::encode(&mut packet[..capacity], transmit, timestamp)
            .map_err(|_| invalid("invalid outgoing IPv4 packet or MTU exceeded"))
    }

    const IPV6_HEADER: usize = 40;

    fn unicast_v6(ip: Ipv6Addr) -> bool {
        // No zone handling: reject link/site-local, mapped IPv4 and loopback addresses.
        !ip.is_unspecified()
            && !ip.is_multicast()
            && !ip.is_loopback()
            && !ip.is_unicast_link_local()
            && ip.segments()[0] & 0xffc0 != 0xfec0
            && ip.to_ipv4_mapped().is_none()
    }

    #[cfg(test)]
    fn parse_ipv6(packet: &[u8], local: Ipv6Addr) -> Option<(IpMetadata, u8, &[u8])> {
        let parsed = ntcp_ip6::parse(packet).ok()?;
        let (IpAddr::V6(source), IpAddr::V6(destination)) =
            (parsed.ip.source, parsed.ip.destination)
        else {
            return None;
        };
        if parsed.protocol != 6
            || destination != local
            || !unicast_v6(source)
            || !unicast_v6(destination)
        {
            return None;
        }
        Some((parsed.ip, parsed.traffic_class, parsed.payload))
    }

    fn build_ipv6(packet: &mut [u8], transmit: ntcp::Transmit) -> io::Result<usize> {
        let (IpAddr::V6(source), IpAddr::V6(destination)) =
            (transmit.ip.source, transmit.ip.destination)
        else {
            return Err(invalid("expected IPv6 transmit addresses"));
        };
        if !unicast_v6(source) || !unicast_v6(destination) {
            return Err(invalid("invalid outgoing IPv6 address"));
        }
        let capacity = packet.len().min(MTU);
        ntcp_ip6::encode(&mut packet[..capacity], transmit)
            .map_err(|_| invalid("invalid outgoing IPv6 base-header packet"))
    }

    fn checked_peer(value: &str, local: IpAddr) -> io::Result<SocketAddr> {
        let peer: SocketAddr = value
            .parse()
            .map_err(|_| invalid("invalid peer socket address"))?;
        if peer.is_ipv4() != local.is_ipv4()
            || peer.port() == 0
            || matches!(peer, SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
            || !match peer.ip() {
                IpAddr::V4(ip) => unicast(ip),
                IpAddr::V6(ip) => unicast_v6(ip),
            }
        {
            return Err(invalid(
                "peer must be unscoped unicast and match local address family",
            ));
        }
        Ok(peer)
    }

    //= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
    //= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
    //# Setting the DF bit implies the use of Path MTU Discovery as described
    //# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
    //# that implements PAWS MUST also implement Path MTU Discovery.
    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# The destination host MUST (if possible) add the current timestamp to
    //# a Timestamp option before passing the option to the transport layer
    //# or to ICMP for processing.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-5
    //= type=implementation
    //= reason=Direct-TCP IPv6 base-header adapter extracts the identical ECN field from Traffic Class of each complete datagram (received fragments are first reassembled by the Host); extension headers other than Fragment, source fragmentation and jumbograms are scoped adapter limits.
    //# Bits 6 and 7 in the IPv4 TOS octet are designated as the ECN field. The IPv4 TOS octet corresponds to the Traffic Class octet in IPv6, and the ECN field is defined identically in both cases.
    fn input_frame(
        network: &mut TunHost,
        endpoint: &mut Endpoint,
        time: u64,
        packet: &[u8],
        local: IpAddr,
        options_enabled: bool,
        timestamps: &mut dyn ntcp::Ipv4TimestampProvider,
    ) -> io::Result<()> {
        if local != network.local || options_enabled != network.options_enabled {
            return Ok(());
        }
        // Preserve IPv4 trailing-padding acceptance, passing only the complete
        // IP frame to canonical authority and the exact-bounds codec.
        let packet = if packet.first().is_some_and(|b| b >> 4 == 4) {
            let Some(total) = packet.get(2..4) else {
                return Ok(());
            };
            let total = usize::from(u16::from_be_bytes([total[0], total[1]]));
            let Some(frame) = packet.get(..total) else {
                return Ok(());
            };
            frame
        } else {
            packet
        };
        // Reassembly precedes classification; the completed datagram's
        // buffer is restored whatever the outcome.
        let mut completed = std::mem::take(&mut network.completed);
        let result = input_datagram(network, endpoint, time, packet, &mut completed, timestamps);
        network.completed = completed;
        result
    }

    fn input_datagram(
        network: &mut TunHost,
        endpoint: &mut Endpoint,
        time: u64,
        packet: &[u8],
        completed: &mut [u8],
        timestamps: &mut dyn ntcp::Ipv4TimestampProvider,
    ) -> io::Result<()> {
        // A TUN carries IP packets only: no link-layer multicast arrival.
        let Ok(Received::Datagram(datagram)) =
            network
                .host
                .receive(network.ingress, time, packet, false, completed)
        else {
            return Ok(());
        };
        // Destination processing happens once, here; retention and replay
        // keep its result.
        let Ok(datagram) = network.host.process(datagram, Some(timestamps)) else {
            return Ok(());
        };
        let Ok(decoded) = network.host.decode_datagram(datagram) else {
            return Ok(());
        };
        if decoded.protocol == if decoded.ip.source.is_ipv4() { 1 } else { 58 } {
            // The single Host dispatcher classifies, correlates and applies
            // ICMP and answers Echo Requests; a reserved owner's report comes
            // back unapplied to retain.
            if let Some(IcmpDispatch::Deferred(deferred)) =
                silent(network.host.input_icmp_datagram(endpoint, time, datagram))?
            {
                network.retain(Retained::Icmp(deferred), None)?;
            }
            return Ok(());
        }
        if let Some(owner) = network.owner(endpoint, datagram)
            && endpoint.is_output_reserved(owner)
        {
            return network.retain(Retained::Tcp(owner), Some(datagram));
        }
        silent(network.host.input_datagram(
            endpoint,
            time,
            datagram,
            ntcp::RxPacketMetadata::default(),
            network.dscp,
        ))?;
        Ok(())
    }

    fn build_frame(
        packet: &mut [u8],
        transmit: ntcp::Transmit,
        timestamp: u32,
    ) -> io::Result<usize> {
        match transmit.ip.source {
            IpAddr::V4(_) => build_ipv4_options(packet, transmit, timestamp),
            IpAddr::V6(_) => build_ipv6(packet, transmit),
        }
    }

    fn tun_v6_policy(local: Ipv6Addr) -> impl Fn(AddressValidation) -> bool {
        let valid = |ip| matches!(ip, IpAddr::V6(ip) if unicast_v6(ip));
        move |request| match request {
            AddressValidation::Bind { local: bind } => bind == IpAddr::V6(local) && valid(bind),
            AddressValidation::Open {
                local: source,
                remote: destination,
            } => source == IpAddr::V6(local) && valid(source) && valid(destination),
            AddressValidation::Route {
                source,
                destination,
                hop,
            } => source == IpAddr::V6(local) && valid(source) && valid(destination) && valid(hop),
            AddressValidation::Incoming {
                source,
                destination,
            } => destination == IpAddr::V6(local) && valid(source) && valid(destination),
        }
    }

    fn checked_interface_ipv6(
        local: Ipv6Addr,
        address: Ipv6Addr,
        mask: u128,
        scope_id: u32,
    ) -> io::Result<()> {
        let prefix = mask.leading_ones();
        if mask != u128::MAX.checked_shl(128 - prefix).unwrap_or(0) {
            return Err(invalid("noncontiguous IPv6 interface netmask"));
        }
        if !unicast_v6(local)
            || local.segments()[0] & 0xe000 != 0x2000
            || !unicast_v6(address)
            || address.segments()[0] & 0xe000 != 0x2000
            || scope_id != 0
            || local == address
            || u128::from(local) & mask != u128::from(address) & mask
        {
            return Err(invalid(
                "local IPv6 address must be a distinct global-unicast address in the TUN interface subnet",
            ));
        }
        Ok(())
    }

    fn interface_ipv6(tun: &Tun, local: Ipv6Addr) -> io::Result<()> {
        // SAFETY: zero initializes ifreq; the live TUN fd writes its actual name.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addresses = std::ptr::null_mut();
        // SAFETY: getifaddrs initializes the list pointer on success.
        if unsafe { libc::getifaddrs(&mut addresses) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut found = false;
        let mut kernel_owned = false;
        let mut cursor = addresses;
        // SAFETY: traverse the live getifaddrs list, checking nullable addresses
        // and family before casting; names are NUL-terminated by the kernel.
        unsafe {
            let name = std::ffi::CStr::from_ptr(request.ifr_name.as_ptr());
            while let Some(entry) = cursor.as_ref() {
                if !entry.ifa_addr.is_null() && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET6
                {
                    let address = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                    let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
                    // Any kernel-owned duplicate has a local route that bypasses TUN,
                    // including addresses assigned to another interface.
                    kernel_owned |= ip == local;
                    if std::ffi::CStr::from_ptr(entry.ifa_name) == name
                        && !entry.ifa_netmask.is_null()
                        && (*entry.ifa_netmask).sa_family as i32 == libc::AF_INET6
                    {
                        let mask = &*entry.ifa_netmask.cast::<libc::sockaddr_in6>();
                        found |= checked_interface_ipv6(
                            local,
                            ip,
                            u128::from_be_bytes(mask.sin6_addr.s6_addr),
                            address.sin6_scope_id,
                        )
                        .is_ok();
                    }
                }
                cursor = entry.ifa_next;
            }
            libc::freeifaddrs(addresses);
        }
        if kernel_owned {
            Err(invalid("local IPv6 address is already owned by the kernel"))
        } else if found {
            Ok(())
        } else {
            Err(invalid(
                "local IPv6 address must be a distinct global-unicast address in the TUN interface subnet",
            ))
        }
    }

    fn open_tun(name: &str) -> io::Result<Tun> {
        Tun::open(name)
    }

    fn prefix_length(mask: u32) -> io::Result<u8> {
        let prefix = mask.leading_ones();
        if mask != u32::MAX.checked_shl(32 - prefix).unwrap_or(0) {
            return Err(invalid("noncontiguous interface netmask"));
        }
        Ok(prefix as u8)
    }

    fn checked_interface_subnet(
        local: Ipv4Addr,
        address: Ipv4Addr,
        mask: u32,
    ) -> io::Result<(Ipv4Addr, u8)> {
        let prefix = prefix_length(mask)?;
        if u32::from(local) & mask != u32::from(address) & mask {
            return Err(invalid(
                "local IPv4 address must lie in the TUN interface subnet; unrelated routed endpoint addresses are unsupported",
            ));
        }
        Ok((address, prefix))
    }

    fn tun_address_policy(
        local: Ipv4Addr,
        subnet: (Ipv4Addr, u8),
    ) -> impl Fn(AddressValidation) -> bool {
        // The subnet is queried from this TUN, not a union of unrelated interfaces.
        // checked_interface_subnet validates the prefix and local/subnet relationship.
        let (address, prefix) = subnet;
        let valid = move |ip: IpAddr| match ip {
            IpAddr::V4(ip) => {
                unicast(ip)
                    && (prefix > 30 || u32::from(ip) != (u32::from(address) | (u32::MAX >> prefix)))
            }
            IpAddr::V6(_) => false,
        };
        move |request| match request {
            AddressValidation::Bind { local: bind } => bind == IpAddr::V4(local) && valid(bind),
            AddressValidation::Open {
                local: source,
                remote: destination,
            } => source == IpAddr::V4(local) && valid(source) && valid(destination),
            AddressValidation::Route {
                source,
                destination,
                hop,
            } => source == IpAddr::V4(local) && valid(source) && valid(destination) && valid(hop),
            AddressValidation::Incoming {
                source,
                destination,
            } => destination == IpAddr::V4(local) && valid(source) && valid(destination),
        }
    }

    fn interface_subnet(tun: &Tun, local: Ipv4Addr) -> io::Result<(Ipv4Addr, u8)> {
        // SAFETY: zero initializes every ifreq union member and the name buffer.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        // SAFETY: live TUN fd and writable, correctly sized ifreq. Querying the
        // actual name also handles kernel-expanded names such as tun%d.
        if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        // SAFETY: the socket is live and request contains the kernel's interface name.
        if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFNETMASK, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful SIOCGIFNETMASK initialized this union member.
        let mask = unsafe { request.ifr_ifru.ifru_netmask };
        if i32::from(mask.sa_family) != libc::AF_INET {
            return Err(invalid("expected an IPv4 interface netmask"));
        }
        // sockaddr_in's network-order address follows its two-byte port.
        let mask = u32::from_be_bytes([
            mask.sa_data[2] as u8,
            mask.sa_data[3] as u8,
            mask.sa_data[4] as u8,
            mask.sa_data[5] as u8,
        ]);
        // SAFETY: the live socket and kernel-returned interface name remain valid.
        if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFADDR, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful SIOCGIFADDR initialized this union member.
        let address = unsafe { request.ifr_ifru.ifru_addr };
        if i32::from(address.sa_family) != libc::AF_INET {
            return Err(invalid("expected an IPv4 interface address"));
        }
        let address = Ipv4Addr::new(
            address.sa_data[2] as u8,
            address.sa_data[3] as u8,
            address.sa_data[4] as u8,
            address.sa_data[5] as u8,
        );
        checked_interface_subnet(local, address, mask)
    }

    struct Flow {
        id: ConnectionId,
        pending: [u8; 4096],
        start: usize,
        end: usize,
        shutdown: bool,
    }

    impl Flow {
        fn new(id: ConnectionId) -> Self {
            Self {
                id,
                pending: [0; 4096],
                start: 0,
                end: 0,
                shutdown: false,
            }
        }

        // One bounded chunk per flow. Never read again until all pending bytes
        // have been accepted by TCP, even when peer FIN has already arrived.
        fn drive(&mut self, endpoint: &mut Endpoint) -> io::Result<bool> {
            if self.shutdown || endpoint.is_output_reserved(self.id) {
                return Ok(false);
            }
            let mut progress = false;
            if self.start == self.end {
                match endpoint.read(self.id, &mut self.pending) {
                    Ok(0) => {
                        endpoint.shutdown(self.id).map_err(engine)?;
                        self.shutdown = true;
                        return Ok(true);
                    }
                    Ok(count) => {
                        self.start = 0;
                        self.end = count;
                        progress = true;
                    }
                    Err(EndpointError::Connection(Error::WouldBlock)) => return Ok(false),
                    Err(error) => return Err(engine(error)),
                }
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
            //# As a result of implementation differences and middlebox interactions,
            //# new applications SHOULD NOT employ the TCP urgent mechanism (SHLD-13).
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
            //# New applications SHOULD NOT set the URGENT flag [39] due to
            //# implementation differences and middlebox issues (SHLD-13).
            match endpoint.write(self.id, &self.pending[self.start..self.end]) {
                Ok(count) => {
                    self.start += count;
                    progress |= count != 0;
                }
                Err(EndpointError::Connection(Error::WouldBlock)) => {}
                Err(error) => return Err(engine(error)),
            }
            Ok(progress)
        }
    }

    fn now(start: Instant) -> u64 {
        start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }

    // The time an originated Timestamp option records at this origin,
    // sampled only when origin recording writes a slot: one whose addresses
    // are not prespecified, or whose first prespecified address is the
    // source (RFC 1122 section 3.2.1.8). Without one the value is never
    // written; it is the loop's elapsed time at `time` marked nonstandard.
    fn origin_timestamp(
        transmit: &ntcp::Transmit,
        time: u64,
        timestamps: &mut dyn ntcp::Ipv4TimestampProvider,
    ) -> u32 {
        let writes = match transmit.ipv4_options.timestamp {
            None => false,
            Some(ntcp::TimestampRequest::Prespecified { addresses, len }) => {
                len != 0 && transmit.ip.source == IpAddr::V4(addresses[0])
            }
            Some(_) => true,
        };
        writes
            .then(|| timestamps.ipv4_timestamp())
            .flatten()
            .unwrap_or(ntcp::Ipv4Timestamp::nonstandard((time / 1000) as u32))
            .wire_value()
    }

    // TCP frames on a discovery-disabled IPv4 route or path that wait for an
    // Identification (the allocator's start quiet period, or the RFC 6864
    // ceiling of their tuple). Only such a frame waits: it keeps its owner's
    // reservation, evidence ticket and bytes and is retried at its own time
    // while other owners' output continues, as the native runtime's
    // scheduler retries only the affected entry. An owner has at most one
    // reserved frame, so the connections plus the stateless lane bound the
    // set; its storage precedes selection.
    struct IdentifierHeld {
        frames: Vec<HeldFrame>,
        free: Vec<Vec<u8>>,
    }

    struct HeldFrame {
        frame: PendingFrame,
        bytes: Vec<u8>,
        retry_at: u64,
    }

    impl IdentifierHeld {
        fn new(owners: usize) -> io::Result<Self> {
            let allocation = |_| host_error(ntcp_host::Error::Allocation);
            let mut frames = Vec::new();
            frames.try_reserve_exact(owners).map_err(allocation)?;
            let mut free = Vec::new();
            free.try_reserve_exact(owners).map_err(allocation)?;
            for _ in 0..owners {
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(MTU).map_err(allocation)?;
                free.push(bytes);
            }
            Ok(Self { frames, free })
        }

        // When an identifier is withheld: at the allocator's stated time,
        // otherwise (none stated) at the loop's next tick.
        fn retry_at(time: u64, backpressure: ntcp_host::IdentifierBackpressure) -> u64 {
            match backpressure {
                ntcp_host::IdentifierBackpressure::Exhausted { retry_at }
                | ntcp_host::IdentifierBackpressure::Unavailable {
                    until: Some(retry_at),
                } => retry_at.max(time.saturating_add(1)),
                _ => time.saturating_add(TICK_US),
            }
        }

        // Set `frame` (its bytes in `bytes`) aside; returned when no storage
        // is left.
        fn hold(
            &mut self,
            frame: PendingFrame,
            bytes: &[u8],
            retry_at: u64,
        ) -> Result<(), PendingFrame> {
            let Some(mut storage) = self.free.pop() else {
                return Err(frame);
            };
            if bytes.len() > storage.capacity() {
                self.free.push(storage);
                return Err(frame);
            }
            storage.clear();
            storage.extend_from_slice(bytes);
            self.frames.push(HeldFrame {
                frame,
                bytes: storage,
                retry_at,
            });
            Ok(())
        }

        // The oldest frame due at `time`, its bytes copied back to `output`.
        fn due(&mut self, time: u64, output: &mut [u8]) -> Option<PendingFrame> {
            let index = self.frames.iter().position(|held| held.retry_at <= time)?;
            let held = self.frames.remove(index);
            output[..held.bytes.len()].copy_from_slice(&held.bytes);
            self.free.push(held.bytes);
            Some(held.frame)
        }

        fn is_empty(&self) -> bool {
            self.frames.is_empty()
        }

        fn next_retry(&self) -> Option<u64> {
            self.frames.iter().map(|held| held.retry_at).min()
        }
    }

    struct PendingFrame {
        attempt: ntcp::TransmitAttempt,
        context: Option<EgressContext>,
        ticket: Option<SubmissionTicket>,
        len: usize,
        blocked: bool,
    }

    // The one physical TUN call, as the Host transaction's backend outcome.
    // This embedding retries the identical attempt after a refusal or EINTR;
    // any other error is an unknown outcome, kept for the caller.
    fn tun_transmit(
        backend: &mut impl PacketIo,
        frame: &[u8],
        failure: &mut Option<io::Error>,
    ) -> BackendOutcome {
        match backend.transmit(frame) {
            Ok(TxOutcome::Submitted) => BackendOutcome::Submitted,
            Ok(TxOutcome::WouldBlock | TxOutcome::Rejected) => BackendOutcome::WouldBlock,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => BackendOutcome::WouldBlock,
            Err(error) => {
                *failure = Some(error);
                BackendOutcome::Unknown
            }
        }
    }

    // This one physical backend implements only its assigned opaque L3
    // forwarder, never arbitrary neighbor mappings.
    fn tun_egress(port: path::LinkId, link: path::LinkId, next_hop: path::ResolvedNextHop) -> bool {
        link == port && next_hop == path::ResolvedNextHop::Forwarder(path::ForwarderId(1))
    }

    fn transmit_frames(
        network: &mut TunHost,
        endpoint: &mut Endpoint,
        time: u64,
        output: &mut [u8],
        pending: &mut Option<PendingFrame>,
        header_len: usize,
        timestamps: &mut dyn ntcp::Ipv4TimestampProvider,
        backend: &mut impl PacketIo,
    ) -> io::Result<bool> {
        // The change service publishes connection results and serves every
        // dirty client; one that cannot rebind stays dirty for the next pass.
        // A blocked selected packet below exposes that failure and pauses output.
        if let Ok(report) = network.host.service_changes(endpoint, time)
            && let Some(error) = report.first_error
        {
            eprintln!(
                "path change service left {} client(s) pending: {error:?}",
                report.failed
            );
        }
        // True when the budget ended the pass with output possibly left.
        for _ in 0..BUDGET {
            if let Some(frame) = pending
                .is_none()
                .then(|| network.identifier_held.due(time, output))
                .flatten()
            {
                // A frame waiting for an identifier is tried again first.
                *pending = Some(frame);
            } else if pending.is_none() {
                let (polled, attempt) =
                    match endpoint.poll_reserved_transmit(time, &mut output[header_len..], 1) {
                        Ok(polled) => polled,
                        // Every reservation is held by a frame waiting for an
                        // identifier: nothing else can be selected now.
                        Err(EndpointError::OutputReserved)
                            if !network.identifier_held.is_empty() =>
                        {
                            return Ok(false);
                        }
                        Err(error) => return Err(engine(error)),
                    };
                let Some(packet) = polled.packet else {
                    // Held frames keep their owners' reservations, which
                    // count as pending output: only their retry time wakes
                    // the loop for them.
                    if !polled.more_work || !network.identifier_held.is_empty() {
                        return Ok(false);
                    }
                    continue;
                };
                let attempt =
                    attempt.ok_or_else(|| io::Error::other("missing transmit attempt"))?;
                // A frame held for retry keeps these bytes and its time.
                let timestamp = origin_timestamp(&packet, time, timestamps);
                let len = match build_frame(output, packet, timestamp) {
                    Ok(len) => len,
                    Err(error) => {
                        // Encoding failed before any backend call. Keep core's
                        // selected bytes/accounting for safe suffix reselection.
                        endpoint.reject_unsubmitted(attempt).map_err(engine)?;
                        return Err(error);
                    }
                };
                *pending = Some(PendingFrame {
                    attempt,
                    context: None,
                    ticket: None,
                    len,
                    blocked: false,
                });
            }
            let held = pending.as_mut().unwrap();
            // Authority and the attempt's single evidence reservation precede
            // any backend call; a held frame keeps both across retries.
            let prepared = match (held.context, held.ticket.take()) {
                (Some(context), Some(ticket)) => Ok((context, ticket)),
                (context, _) => context
                    .map_or_else(|| network.host.egress_context(endpoint, held.attempt), Ok)
                    .and_then(|context| {
                        Ok((context, network.host.submission_ticket(endpoint, context)?))
                    }),
            };
            let refused: Result<(), _> = match prepared {
                Ok((context, ticket)) => {
                    // RFC 1191 section 6.6: on an IPv4 route or path whose
                    // owner disabled discovery the packet leaves without DF,
                    // with an Identification leased for this physical
                    // attempt. Without one only this frame is held, never
                    // sent with a reused value; other owners' output goes on.
                    if network.host.clears_dont_fragment(context)
                        && let Err(backpressure) =
                            network.host.lease_df_clear(time, &mut output[..held.len])
                    {
                        held.context = Some(context);
                        held.ticket = Some(ticket);
                        if !held.blocked {
                            eprintln!("TUN output held for an IPv4 Identification: {backpressure:?}");
                        }
                        held.blocked = true;
                        let len = held.len;
                        let frame = pending.take().unwrap();
                        let retry_at = IdentifierHeld::retry_at(time, backpressure);
                        match network.identifier_held.hold(frame, &output[..len], retry_at) {
                            Ok(()) => continue,
                            // No storage left (not expected: one frame per
                            // owner): the frame stays selected.
                            Err(frame) => {
                                *pending = Some(frame);
                                return Ok(false);
                            }
                        }
                    }
                    // A frame rewritten DF clear for an attempt that did not
                    // leave (the backend would block) goes back to the
                    // atomic header (DF set, Identification 0) when the
                    // owner re-enabled discovery before this retry.
                    if !network.host.clears_dont_fragment(context) {
                        ntcp_host::Host::restore_atomic_header(&mut output[..held.len]);
                    }
                    let mut live = None;
                    let mut unusable = false;
                    let mut failure = None;
                    let frame = &output[..held.len];
                    let port = network.ingress.link();
                    let result =
                        network
                            .host
                            .submit(endpoint, time, ticket, context, frame, 0, |context| {
                                live = Some(context);
                                if !tun_egress(port, context.link, context.next_hop) {
                                    unusable = true;
                                    return BackendOutcome::WouldBlock;
                                }
                                tun_transmit(backend, frame, &mut failure)
                            });
                    match result {
                        Ok(Submission::Submitted) => {
                            *pending = None;
                            network.host.collect(endpoint).map_err(host_error)?;
                            // Yield to retained ingress before selecting more
                            // work for an owner whose reservation just completed.
                            network.replay(endpoint, time)?;
                            continue;
                        }
                        Ok(Submission::Blocked(ticket)) => {
                            held.context = live.or(Some(context));
                            held.ticket = Some(ticket);
                            if !unusable {
                                held.blocked = false;
                                return Ok(false);
                            }
                            Err(ntcp_host::Error::Unsupported)
                        }
                        // Unknown outcome: terminate with the attempt pinned and
                        // its evidence sealed as possibly submitted. Never issue
                        // a not-sent certificate or retry it.
                        Ok(Submission::PossiblySubmitted) => {
                            return Err(
                                failure.unwrap_or_else(|| io::Error::other("unknown TUN outcome"))
                            );
                        }
                        Ok(Submission::Rejected(_) | Submission::Cancelled) => {
                            unreachable!("this backend reports neither outcome")
                        }
                        Err(refused) => {
                            held.context = Some(context);
                            if refused.error == ntcp_host::Error::Obsolete {
                                // Certified unsent: no backend call happened.
                                network.host.cancel_submission(refused.ticket);
                            } else {
                                held.ticket = Some(refused.ticket);
                            }
                            Err(refused.error)
                        }
                    }
                }
                Err(error) => Err(error),
            };
            match refused {
                Err(ntcp_host::Error::Obsolete) => {
                    if !endpoint.reject_unsubmitted(held.attempt).map_err(engine)? {
                        return Err(io::Error::other("stale rejected transmit attempt"));
                    }
                    *pending = None;
                    network.host.collect(endpoint).map_err(host_error)?;
                }
                // The route its owner stated the expected registrations for
                // changed or is gone (RFC 791 section 3.1). This example has
                // no topology knowledge to state them for another route
                // (`Host::revalidate_registration`), so the flow ends: the
                // certainly unsent attempt fails its connection without a
                // reset, and other owners' output goes on.
                Err(ntcp_host::Error::StaleRoute) => {
                    let held = pending.take().unwrap();
                    if let Some(ticket) = held.ticket {
                        network.host.cancel_submission(ticket);
                    }
                    if !endpoint.abandon_transmit(held.attempt).map_err(engine)? {
                        return Err(io::Error::other("stale abandoned transmit attempt"));
                    }
                    eprintln!("TUN flow terminated: its IPv4 registration plan's route changed");
                    network.host.collect(endpoint).map_err(host_error)?;
                }
                result => {
                    if !held.blocked {
                        eprintln!(
                            "TUN output paused: {:?}",
                            result.err().unwrap_or(ntcp_host::Error::Unsupported)
                        );
                    }
                    held.blocked = true;
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    // Bounded UDP echo beside the TCP echo. Requests wait in the Host's
    // bounded flow queue; at most one reply is held here, so a blocked TUN
    // stops reading requests instead of growing storage. Every reply is a
    // real application datagram through the Host's submission transaction,
    // and the flow's correlated ICMP advice is consumed on every pass. In
    // Fragment mode (the default) a reply larger than the connectionless
    // effective size is source-fragmented within the peers' stated
    // reassembly capacity; Refuse mode sends replies whole or not at all.
    struct UdpEcho {
        flow: UdpFlowId,
        send: UdpSend,
        // Holds the largest request the Host can reassemble.
        reply: Vec<u8>,
        // The largest reply, plus room for one fragment when it is split.
        packet: Vec<u8>,
        held: Option<(SocketAddr, usize)>,
        blocked: bool,
        #[cfg(test)]
        notes: Vec<String>,
    }

    impl UdpEcho {
        // Operational reports go to stderr; tests also read them back.
        fn note(&mut self, line: std::fmt::Arguments) {
            eprintln!("{line}");
            #[cfg(test)]
            self.notes.push(line.to_string());
        }

        fn open(
            network: &mut TunHost,
            endpoint: &Endpoint,
            local: SocketAddr,
            config: &EndpointConfig,
            settings: &DatagramSettings,
        ) -> io::Result<Self> {
            let flow = network
                .host
                .udp_open(
                    endpoint,
                    local,
                    None,
                    ntcp_host::UdpOptions {
                        dscp: config.dscp,
                        hop_limit: config.hop_limit,
                    },
                )
                .map_err(host_error)?;
            let datagram = if local.is_ipv4() {
                IPV4_DATAGRAM - IP_HEADER
            } else {
                IPV6_DATAGRAM - IPV6_HEADER
            };
            // The flow's default: the operator's mode and stated capacity.
            let send = UdpSend {
                mode: settings.udp_mode,
                peer_capability: settings.peer_reassembly,
            };
            network
                .host
                .udp_set_send(flow, send)
                .map_err(host_error)?;
            Ok(Self {
                flow,
                send,
                reply: vec![0; datagram - UDP_HEADER],
                packet: vec![0; datagram + MTU],
                held: None,
                blocked: false,
                #[cfg(test)]
                notes: Vec::new(),
            })
        }

        fn drive(
            &mut self,
            network: &mut TunHost,
            endpoint: &Endpoint,
            time: u64,
            backend: &mut impl PacketIo,
        ) -> io::Result<bool> {
            let mut progress = false;
            // Advice concerns replies already sent; any shared decrease it
            // caused is already the budget every later reply is held to.
            for _ in 0..BUDGET {
                match network.host.udp_event(self.flow).map_err(host_error)? {
                    Some(UdpEvent::PacketTooBig {
                        remote,
                        mtu,
                        dropped_len,
                    }) => self.note(format_args!(
                        "UDP echo reply to {remote} ({dropped_len} octets) dropped by the \
                         path (next-hop MTU {mtu:?}); later replies use the reduced budget"
                    )),
                    Some(UdpEvent::NetworkError { remote, error }) => {
                        self.note(format_args!("UDP echo reply to {remote} failed: {error:?}"))
                    }
                    None => break,
                }
                progress = true;
            }
            // A shared change to the pinned path: report the new limit and
            // reconsider a held reply against it. Echoes are never
            // truncated: one that no longer fits what the mode can send (in
            // Refuse mode the unfragmented limit) is refused.
            if let Some(change) = network
                .host
                .udp_path_change(self.flow)
                .map_err(host_error)?
            {
                self.note(format_args!(
                    "UDP echo path to {} changed: MMS_S {}, payload limit {}",
                    change.destination, change.mms_s, change.max_payload
                ));
                if let Some((peer, len)) = self.held
                    && peer.ip() == change.destination
                {
                    if self.send.mode == UdpSendMode::Refuse {
                        if len > change.max_payload {
                            self.note(format_args!(
                                "UDP echo of {len} octets to {peer} refused: exceeds the \
                                 changed path payload limit of {}",
                                change.max_payload
                            ));
                            self.held = None;
                            self.blocked = false;
                        }
                    } else if let Ok(limits) = network.host.udp_datagram_limits(
                        endpoint,
                        self.flow,
                        Some(peer.ip()),
                        None,
                    ) && len > limits.max_payload
                    {
                        self.note(format_args!(
                            "UDP echo of {len} octets to {peer} refused: exceeds the changed \
                             datagram limit of {} (peer reassembly capacity {})",
                            limits.max_payload, limits.guarantee
                        ));
                        self.held = None;
                        self.blocked = false;
                    }
                }
                progress = true;
            }
            for _ in 0..BUDGET {
                let Some((peer, len)) = self.held else {
                    match network
                        .host
                        .udp_receive(self.flow, &mut self.reply)
                        .map_err(host_error)?
                    {
                        Some(request) => self.held = Some(request),
                        None => break,
                    }
                    progress = true;
                    continue;
                };
                let sent = if self.send.mode == UdpSendMode::Refuse {
                    self.send_whole(network, endpoint, time, backend, peer, len)?
                } else {
                    self.send_datagram(network, endpoint, time, backend, peer, len)?
                };
                match sent {
                    Sent::Done => {}
                    Sent::Blocked => {
                        self.blocked = true;
                        break;
                    }
                }
                self.held = None;
                self.blocked = false;
                progress = true;
            }
            Ok(progress)
        }

        // Refuse mode: one unfragmented datagram through `udp_send`, refused
        // with the path's unfragmented payload limit.
        fn send_whole(
            &mut self,
            network: &mut TunHost,
            endpoint: &Endpoint,
            time: u64,
            backend: &mut impl PacketIo,
            peer: SocketAddr,
            len: usize,
        ) -> io::Result<Sent> {
            // Size the reply against the current path before building it.
            match network
                .host
                .udp_path_limits(endpoint, self.flow, Some(peer.ip()))
            {
                Ok(limits) if len > limits.max_payload => {
                    self.note(format_args!(
                        "UDP echo of {len} octets to {peer} refused: exceeds the path \
                         payload limit of {}; replies are never fragmented",
                        limits.max_payload
                    ));
                    return Ok(Sent::Done);
                }
                // The send below reports any failure of this authority.
                _ => {}
            }
            let mut unusable = false;
            let mut failure = None;
            let port = network.ingress.link();
            let result = network.host.udp_send(
                endpoint,
                time,
                self.flow,
                Some(peer),
                &self.reply[..len],
                &mut self.packet,
                |egress, frame| {
                    if !tun_egress(port, egress.link, egress.next_hop) {
                        unusable = true;
                        return BackendOutcome::NotSubmitted;
                    }
                    tun_transmit(backend, frame, &mut failure)
                },
            );
            match result {
                Ok(UdpSent::Submitted(_)) => {}
                // Same contract as TCP output: an unknown outcome ends
                // the runtime rather than claiming or repeating it.
                Ok(UdpSent::PossiblySubmitted(_)) => {
                    return Err(failure.unwrap_or_else(|| io::Error::other("unknown TUN outcome")));
                }
                // Nothing runs between the query above and this send, so
                // the query already refused whatever this would; this is
                // the send's own enforcement of the same limit.
                Err(UdpSendError::TooBig { max_payload }) => self.note(format_args!(
                    "UDP echo of {len} octets to {peer} refused at send: exceeds the path \
                     payload limit of {max_payload}; replies are never fragmented"
                )),
                // A DF-clear reply on a discovery-disabled IPv4 route found
                // no Identification; it ends, as in Fragment mode.
                Err(UdpSendError::Backpressure(why)) => self.note(format_args!(
                    "UDP echo of {len} octets to {peer} not sent: no IP identifier \
                     available ({why:?})"
                )),
                // Retry the same reply once the TUN or evidence storage frees.
                Err(
                    UdpSendError::NotSubmitted(_) | UdpSendError::Host(ntcp_host::Error::Capacity),
                ) if !unusable => return Ok(Sent::Blocked),
                Err(error) => {
                    self.note(format_args!("UDP echo reply to {peer} not sent: {error:?}"))
                }
            }
            Ok(Sent::Done)
        }

        // Fragment mode: the Host's datagram transaction. A reply within the
        // connectionless effective size goes whole; a larger one is cut into
        // fragments of that size (each IPv4 fragment with DF) within the
        // peers' reassembly capacity; a reply that may not be fragmented
        // still goes whole within the path budget.
        fn send_datagram(
            &mut self,
            network: &mut TunHost,
            endpoint: &Endpoint,
            time: u64,
            backend: &mut impl PacketIo,
            peer: SocketAddr,
            len: usize,
        ) -> io::Result<Sent> {
            let limits = match network.host.udp_datagram_limits(
                endpoint,
                self.flow,
                Some(peer.ip()),
                None,
            ) {
                Ok(limits) if len > limits.max_payload => {
                    self.note(format_args!(
                        "UDP echo of {len} octets to {peer} refused: exceeds the datagram \
                         limit of {} (peer reassembly capacity {})",
                        limits.max_payload, limits.guarantee
                    ));
                    return Ok(Sent::Done);
                }
                Ok(limits) => limits,
                Err(error) => {
                    self.note(format_args!("UDP echo reply to {peer} not sent: {error:?}"));
                    return Ok(Sent::Done);
                }
            };
            let mut send = self.send;
            for _ in 0..2 {
                let mut unusable = false;
                let mut failure = None;
                let port = network.ingress.link();
                let buffer = limits.buffer_len(len).min(self.packet.len());
                let result = network.host.udp_send_datagram(
                    endpoint,
                    time,
                    self.flow,
                    Some(peer),
                    Some(send),
                    &self.reply[..len],
                    &mut self.packet[..buffer],
                    |egress, frame| {
                        if !tun_egress(port, egress.link, egress.next_hop) {
                            unusable = true;
                            return BackendOutcome::NotSubmitted;
                        }
                        tun_transmit(backend, frame, &mut failure)
                    },
                );
                match result {
                    Ok(report) => match report.terminal {
                        None => {}
                        // An unknown outcome ends the runtime, as for TCP.
                        Some(BackendOutcome::Unknown) => {
                            return Err(failure
                                .unwrap_or_else(|| io::Error::other("unknown TUN outcome")));
                        }
                        // A submitted prefix is never reported unsent, and
                        // a retry would be a new datagram: the reply ends.
                        Some(outcome) => self.note(format_args!(
                            "UDP echo reply to {peer}: {} of {} fragments submitted before \
                             {outcome:?}; not repeated",
                            report.submitted, report.fragments
                        )),
                    },
                    Err(DatagramError::TooBig { max_payload })
                    | Err(DatagramError::PeerLimit { max_payload, .. }) => {
                        self.note(format_args!(
                            "UDP echo of {len} octets to {peer} refused at send: exceeds the \
                             datagram limit of {max_payload}"
                        ))
                    }
                    // No identifier (quiet period, MDL ceiling, entropy):
                    // a reply the path carries whole still goes whole.
                    Err(DatagramError::Backpressure(_))
                        if send.mode == UdpSendMode::Fragment
                            && len <= limits.unfragmented_payload =>
                    {
                        send.mode = UdpSendMode::Refuse;
                        continue;
                    }
                    Err(DatagramError::Backpressure(why)) => self.note(format_args!(
                        "UDP echo of {len} octets to {peer} not sent: no IP identifier \
                         available ({why:?})"
                    )),
                    // Retry the same reply once the TUN or storage frees.
                    Err(
                        DatagramError::NotSubmitted(_)
                        | DatagramError::Host(ntcp_host::Error::Capacity),
                    ) if !unusable => return Ok(Sent::Blocked),
                    Err(error) => {
                        self.note(format_args!("UDP echo reply to {peer} not sent: {error:?}"))
                    }
                }
                break;
            }
            Ok(Sent::Done)
        }
    }

    // Whether a reply left (or was finally refused) or waits for the TUN.
    enum Sent {
        Done,
        Blocked,
    }

    fn wait(tun: &Tun, timeout_ms: i32, pending: bool, readable: bool) -> io::Result<()> {
        let mut fd = libc::pollfd {
            fd: tun.as_raw_fd(),
            events: (if readable { libc::POLLIN } else { 0 })
                | if pending { libc::POLLOUT } else { 0 },
            revents: 0,
        };
        // SAFETY: fd points to one initialized pollfd for the duration of poll.
        if unsafe { libc::poll(&mut fd, 1, timeout_ms) } < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(error)
            };
        }
        if fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("TUN poll reported device failure"));
        }
        Ok(())
    }

    //= https://www.rfc-editor.org/rfc/rfc7323#section-5.7
    //= reason=The supplied fixed-1500 TUN embedding queries and validates the real backend MTU, enables PMTUD with or without PAWS, and dispatches checksummed ICMP PTB through live tuple/sequence/exact-packet validation. Runtime-constructor and framed peer tests prove timestamp negotiation, IPv4 DF, bounded IPv4/IPv6 repairs, receiver/ACK byte progress, rejected feedback, committed-output retention, and ICMP-blackhole R1 fallback with ordinary congestion response and subsequent ACK-confirmed probing. This evidence covers the supplied embedding and existing core discovery, not arbitrary external embeddings, native IPv6 sockets or a full host ICMP service.
    //# Setting the DF bit implies the use of Path MTU Discovery as described
    //# in [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation
    //# that implements PAWS MUST also implement Path MTU Discovery.
    fn runtime_config(
        backend: &impl PacketIo,
        local: IpAddr,
        timestamps: bool,
        sack: bool,
        ipv4_options_enabled: bool,
    ) -> io::Result<EndpointConfig> {
        // Fixed builders and output storage require exactly this link MTU. Do
        // not substitute an invented first hop when the backend cannot query it.
        let first_hop_mtu = backend
            .local_ip_mtu()?
            .ok_or_else(|| invalid("TUN MTU is unavailable; expected 1500"))?;
        if first_hop_mtu != MTU as u32 {
            return Err(invalid("TUN MTU must be exactly 1500"));
        }
        let header_len = if local.is_ipv4() {
            IP_HEADER
        } else {
            IPV6_HEADER
        };
        Ok(EndpointConfig {
            max_connections: MAX_FLOWS,
            preallocate_connections: 0,
            max_listeners: 1,
            max_control_packets: BUDGET,
            max_setup_cache_entries: 64,
            max_route_policies: 64,
            max_buffer_bytes: MAX_FLOWS * (5 * 65536 + 1460),
            hop_limit: 64,
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
            //# Generally, an application SHOULD NOT change the Diffserv field value
            //# during the course of a connection (SHLD-23).
            dscp: 0,
            ipv4_options_enabled,
            error_reports: true,
            reuse_time_wait: false,
            connection: ConnectionConfig {
                timestamps,
                sack,
                // IPv4 always emits DF, including without TCP timestamps.
                pmtud: Some(PmtudConfig::new(first_hop_mtu)),
                send_capacity: 65536,
                receive_capacity: 65536,
                mss: (MTU - header_len - 20) as u16,
                receive_ip_payload_limit: (MTU - header_len) as u16,
                send_ip_payload_limit: (MTU - header_len) as u16,
                ..ConnectionConfig::default()
            },
        })
    }

    pub fn run() -> io::Result<()> {
        let args: Vec<_> = std::env::args().collect();
        if !matches!(args.len(), 4 | 5) {
            return Err(invalid(
                "usage: tun_echo TUN_NAME LOCAL_IP TCP_PORT [PEER_SOCKET_ADDR]",
            ));
        }
        let local: IpAddr = args[2]
            .parse()
            .map_err(|_| invalid("invalid local IP address"))?;
        let port: u16 = args[3].parse().map_err(|_| invalid("invalid TCP port"))?;
        if !match local {
            IpAddr::V4(ip) => unicast(ip),
            IpAddr::V6(ip) => unicast_v6(ip),
        } || port == 0
        {
            return Err(invalid(
                "expected an unscoped unicast IP address and nonzero port",
            ));
        }
        let ipv4_options_enabled = match std::env::var("NTCP_IPV4_OPTIONS") {
            Ok(value) => options_enabled(Some(&value))?,
            Err(std::env::VarError::NotPresent) => options_enabled(None)?,
            Err(_) => return Err(invalid("invalid NTCP_IPV4_OPTIONS")),
        };
        if local.is_ipv6() && ipv4_options_enabled {
            return Err(invalid("IPv4 option configuration is unsupported for IPv6"));
        }
        let peer = args
            .get(4)
            .map(|value| checked_peer(value, local))
            .transpose()?;
        let var = |name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(invalid("invalid IPv4 origination setting")),
        };
        let (record_route, timestamp) = (var("NTCP_ORIGINATE_RR")?, var("NTCP_ORIGINATE_TS")?);
        let (ipv4_options, registration) = match origination(
            record_route.as_deref(),
            timestamp.as_deref(),
        )? {
            None => (ntcp::OutgoingIpv4Options::default(), None),
            Some((options, expected)) => {
                let Some(peer) = peer.filter(|_| ipv4_options_enabled) else {
                    return Err(invalid(
                        "IPv4 option origination needs NTCP_IPV4_OPTIONS=1 and a peer",
                    ));
                };
                // Refused before any connection or path is allocated.
                let plan = ntcp::Ipv4RegistrationPlan::new(local, peer.ip(), options, &expected)
                    .map_err(|error| {
                        invalid(&format!("IPv4 registration plan refused: {error:?}"))
                    })?;
                eprintln!(
                    "IPv4 origination toward {peer}: {options:?} for {expected:?}, {} option octets",
                    plan.option_octets()
                );
                (options, Some(plan))
            }
        };
        let header_len = if local.is_ipv4() {
            IP_HEADER
        } else {
            IPV6_HEADER
        };
        let timestamps = match std::env::var("NTCP_TIMESTAMPS") {
            Ok(value) if value == "1" => true,
            Err(std::env::VarError::NotPresent) => false,
            _ => return Err(invalid("NTCP_TIMESTAMPS must be exactly 1 or unset")),
        };
        let sack = match std::env::var("NTCP_SACK") {
            Ok(value) if value == "1" => true,
            Err(std::env::VarError::NotPresent) => false,
            _ => return Err(invalid("NTCP_SACK must be exactly 1 or unset")),
        };
        let settings = DatagramSettings::from_env(local)?;
        let secret = acquire_secret()?;
        let mut tun = open_tun(&args[1])?;
        let start = Instant::now();
        let mut utc = Utc::new(start);
        let address_policy: Box<dyn Fn(AddressValidation) -> bool> = match local {
            IpAddr::V4(ip) => Box::new(tun_address_policy(ip, interface_subnet(&tun, ip)?)),
            IpAddr::V6(ip) => {
                interface_ipv6(&tun, ip)?;
                Box::new(tun_v6_policy(ip))
            }
        };
        let config = runtime_config(&tun, local, timestamps, sack, ipv4_options_enabled)?;
        let open_options = ntcp::ManagedOpenOptions {
            transport: ntcp::ActiveOpenOptions::from(&config.connection),
            dscp: config.dscp,
            ipv4_options,
            registration,
            receive_authority: None,
        };
        let mut endpoint =
            Endpoint::new(config.clone(), secret, now(start), address_policy).map_err(engine)?;
        let mut network =
            TunHost::attach_with(&mut endpoint, &config, local, &settings, now(start))?;
        let mut control = control_server(
            &mut network.host,
            &endpoint,
            std::env::var_os("NTCP_CONTROL_SOCKET"),
            std::env::var_os("NTCP_CONTROL_ALLOW_UIDS"),
        )?;
        let listener = endpoint
            .listen(SocketAddr::new(local, port), MAX_FLOWS)
            .map_err(engine)?;
        let mut udp = UdpEcho::open(
            &mut network,
            &endpoint,
            SocketAddr::new(local, port),
            &config,
            &settings,
        )?;
        let mut flows = Vec::with_capacity(MAX_FLOWS);
        if let Some(peer) = peer {
            let id = endpoint
                .connect_with_path_provider(
                    now(start),
                    SocketAddr::new(local, port),
                    peer,
                    open_options,
                    &mut network.host,
                )
                .map_err(|error| host_error(error.into()))?;
            flows.push(Flow::new(id));
        }
        // One byte beyond the largest non-jumbo IPv6 datagram: a truncated
        // oversized frame cannot masquerade as an exact-length base-header packet.
        // IPv4 total-length handling remains unchanged.
        let mut input = [0u8; 65576];
        // Storage precedes selection; only actual Submitted accepts a reservation.
        let mut output = [0u8; MTU];
        // Separate from `output`, which keeps a held TCP frame across passes.
        // A queued message is built whole here; a fragmented one keeps the
        // complete message beside the fragment being cut: the largest
        // message, an IP header and one link-sized packet.
        let mut icmp_output = vec![
            0u8;
            if local.is_ipv4() {
                IPV4_DATAGRAM
            } else {
                IPV6_DATAGRAM
            } + MTU
        ];
        let mut pending = None;
        let mut accepting = false;
        eprintln!(
            "echo listening on {local}:{port} via {} (caller-configured TUN)",
            args[1]
        );
        eprintln!("{}", settings.report(local));
        loop {
            let mut immediate = false;
            network.replay(&mut endpoint, now(start))?;
            for _ in 0..BUDGET {
                if !network.can_receive() {
                    break;
                }
                match tun.receive(&mut input) {
                    Ok(Some(0)) => {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN closed"));
                    }
                    Ok(Some(len)) => {
                        input_frame(
                            &mut network,
                            &mut endpoint,
                            now(start),
                            &input[..len],
                            local,
                            ipv4_options_enabled,
                            &mut utc,
                        )?;
                    }
                    Ok(None) => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            immediate |= endpoint.on_timeout(now(start), BUDGET).map_err(engine)?;
            for _ in 0..=MAX_FLOWS {
                match endpoint.next_event() {
                    Some(Event::Acceptable(id)) if id == listener => accepting = true,
                    Some(Event::RouteAdvice(tuple)) => {
                        // This adapter has one caller-configured, fixed TUN route.
                        // A routing adapter would invalidate/reselect its path here.
                        eprintln!("negative route advice for {tuple:?}; no alternate TUN route");
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            if accepting {
                for _ in 0..BUDGET {
                    match endpoint.accept(listener) {
                        Ok(id) => {
                            if flows.len() == MAX_FLOWS {
                                return Err(io::Error::other("application flow limit exceeded"));
                            }
                            flows.push(Flow::new(id));
                        }
                        Err(EndpointError::Connection(Error::WouldBlock)) => {
                            accepting = false;
                            break;
                        }
                        Err(error) => return Err(engine(error)),
                    }
                }
                immediate |= accepting;
            }
            // ponytail: bounded application scan of at most 128 accepted flows;
            // use an application ready queue if increasing that cap substantially.
            // Buffered writes are retried independently of edge-like TCP events.
            let mut index = 0;
            while index < flows.len() {
                let id = flows[index].id;
                if endpoint.is_output_reserved(id) {
                    index += 1;
                    continue;
                }
                if matches!(
                    endpoint.state(id).map_err(engine)?,
                    State::Closed | State::TimeWait
                ) {
                    endpoint.release(id).map_err(engine)?; // Engine still owns TIME-WAIT.
                    flows.swap_remove(index);
                } else {
                    immediate |= flows[index].drive(&mut endpoint)?;
                    index += 1;
                }
            }
            immediate |= transmit_frames(
                &mut network,
                &mut endpoint,
                now(start),
                &mut output,
                &mut pending,
                header_len,
                &mut utc,
                &mut tun,
            )?;
            immediate |= udp.drive(&mut network, &endpoint, now(start), &mut tun)?;
            immediate |= network.icmp_output(now(start), &mut icmp_output, &mut tun)?;
            network.host.collect(&endpoint).map_err(host_error)?;
            // Bounded control pass; the wait below is at most TICK_US, so
            // an administrator is served within one tick even when idle.
            if let Some(server) = &mut control {
                server.service(&mut network.host, &mut endpoint, now(start));
            }
            // Frames waiting for an identifier keep their reservations
            // (pending output) and wake the loop at their retry time.
            immediate |= pending.is_none()
                && network.identifier_held.is_empty()
                && endpoint.has_pending_output();
            let current = now(start);
            // Reassembly expiry runs in the change service even without
            // traffic; adjunct probes and their reply deadlines in the ICMP
            // output drain.
            let delay = endpoint
                .next_deadline()
                .into_iter()
                .chain(network.host.next_reassembly_deadline())
                .chain(network.host.next_adjunct_deadline())
                .chain(network.identifier_held.next_retry())
                .min()
                .map_or(TICK_US, |deadline| {
                    deadline.saturating_sub(current).min(TICK_US)
                });
            let timeout_ms = if immediate {
                0
            } else {
                delay.div_ceil(1000) as i32
            };
            // Held-owner deadlines cannot be serviced until submission; avoid
            // spinning on an already expired transport deadline while blocked.
            let timeout_ms = if pending.is_some() || !network.identifier_held.is_empty() {
                timeout_ms.max(1)
            } else {
                timeout_ms
            };
            wait(
                &tun,
                timeout_ms,
                pending.as_ref().is_some_and(|held| !held.blocked) || udp.blocked,
                network.can_receive(),
            )?;
        }
    }

    // The opt-in control server (NTCP_CONTROL_SOCKET), bound with this
    // Host's administration capability. An allow-list without a socket is
    // refused rather than ignored.
    fn control_server(
        host: &mut Host,
        endpoint: &Endpoint,
        socket: Option<std::ffi::OsString>,
        allow_uids: Option<std::ffi::OsString>,
    ) -> io::Result<Option<ntcp_path_control::Server>> {
        let allow_uids = match allow_uids {
            None => Vec::new(),
            Some(text) => ntcp_path_control::ControlConfig::parse_uids(
                text.to_str()
                    .ok_or_else(|| invalid("invalid NTCP_CONTROL_ALLOW_UIDS"))?,
            )?,
        };
        let Some(socket) = socket else {
            if !allow_uids.is_empty() {
                return Err(invalid("NTCP_CONTROL_ALLOW_UIDS needs NTCP_CONTROL_SOCKET"));
            }
            return Ok(None);
        };
        let server = ntcp_path_control::Server::bind(
            &ntcp_path_control::ControlConfig {
                socket: socket.into(),
                allow_uids,
            },
            host.administration(),
            endpoint.caller_timebase(),
        )?;
        eprintln!("path control socket at {}", server.path().display());
        Ok(Some(server))
    }

    #[cfg(test)]
    mod control_tests {
        include!("support/tun_echo_control_tests.rs");
    }

    #[cfg(test)]
    mod pmtu_tests {
        include!("support/tun_echo_pmtu_tests.rs");
        mod ingress {
            include!("support/tun_echo_ingress_tests.rs");
        }
        mod udp {
            include!("support/tun_echo_udp_tests.rs");
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
        //= type=test
        //= reason=Bounded evidence: full/partial fills, EINTR, zero progress, error propagation and live initialized OS CSPRNG acquisition complement core isn_depends_on_secret_and_each_tuple_component HMAC key-dependence coverage; tests do not prove entropy or confidentiality.
        //# F() MUST NOT be computable from the outside (MUST-9), or
        //# an attacker could still guess at sequence numbers from the ISN used
        //# for some other connection.
        #[test]
        fn secret_acquisition() {
            let secret = fill_secret(|buffer| {
                assert_eq!(buffer.len(), 32);
                buffer.fill(0xa5);
                Ok(buffer.len())
            })
            .unwrap();
            assert_eq!(secret, [0xa5; 32]);

            let mut calls = 0;
            let secret = fill_secret(|buffer| {
                calls += 1;
                match calls {
                    1 => {
                        assert_eq!(buffer.len(), 32);
                        buffer[..7].fill(0x11);
                        Ok(7)
                    }
                    2 => {
                        assert_eq!(buffer.len(), 25);
                        Err(io::Error::from_raw_os_error(libc::EINTR))
                    }
                    3 => {
                        assert_eq!(buffer.len(), 25);
                        buffer.fill(0x22);
                        Ok(buffer.len())
                    }
                    _ => panic!("read after full fill"),
                }
            })
            .unwrap();
            assert_eq!(calls, 3);
            assert_eq!(&secret[..7], &[0x11; 7]);
            assert_eq!(&secret[7..], &[0x22; 25]);

            for errno in [libc::EIO, libc::ENOSYS, libc::EAGAIN] {
                let mut calls = 0;
                let error = fill_secret(|buffer| {
                    calls += 1;
                    match calls {
                        1 => {
                            buffer[..1].fill(0x33);
                            Ok(1)
                        }
                        2 => Err(io::Error::from_raw_os_error(errno)),
                        _ => panic!("retried hard error"),
                    }
                })
                .unwrap_err();
                assert_eq!(error.raw_os_error(), Some(errno));
                assert_eq!(calls, 2);
            }
            for (count, kind) in [
                (0, io::ErrorKind::UnexpectedEof),
                (33, io::ErrorKind::InvalidData),
            ] {
                let mut calls = 0;
                let error = fill_secret(|_| {
                    calls += 1;
                    assert_eq!(calls, 1, "retried invalid progress");
                    Ok(count)
                })
                .unwrap_err();
                assert_eq!(error.kind(), kind);
            }

            // Exercise the real OS path, not a statistical entropy test.
            let _secret = acquire_secret().unwrap();
        }

        // Identifier backpressure holds only the frame that needs one.
        // Inside the allocator's start quiet period (the default: earlier
        // emission from the address is unknown), the SYN of a connection
        // whose exact path the owner made discovery-disabled must leave DF
        // clear with a leased Identification, so it waits with its own
        // reservation, while a connection to a neighbor destination still
        // sends its SYN with DF. Once identifiers can be issued, the held SYN
        // leaves DF clear with a nonzero leased Identification.
        #[test]
        fn identifier_backpressure_holds_only_the_df_clear_frame() {
            use ntcp_io::{PacketIo, PacketLayer};
            const MDL_US: u64 = 120_000_000;
            struct Mock {
                submitted: Vec<Vec<u8>>,
            }
            impl PacketIo for Mock {
                fn layer(&self) -> PacketLayer {
                    PacketLayer::Ip
                }
                fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
                    Ok(None)
                }
                fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
                    self.submitted.push(packet.to_vec());
                    Ok(TxOutcome::Submitted)
                }
            }
            let (_, _, local) = packet();
            let mut output = [0; MTU];
            let mut pending = None;
            let mut backend = Mock {
                submitted: Vec::new(),
            };
            let config = EndpointConfig::default();
            let mut endpoint =
                Endpoint::new(config.clone(), [1; 32], 0, test_policy(local)).unwrap();
            let mut network = TunHost::attach(&mut endpoint, &config, local.into()).unwrap();
            let options = || ntcp::ManagedOpenOptions {
                transport: ntcp::ActiveOpenOptions::from(&config.connection),
                dscp: config.dscp,
                ipv4_options: Default::default(),
                registration: None,
                receive_authority: None,
            };
            let disabled: SocketAddr = "10.0.0.1:8080".parse().unwrap();
            let neighbor: SocketAddr = "10.0.0.3:8080".parse().unwrap();
            let held = endpoint
                .connect_with_path_provider(
                    0,
                    SocketAddr::new(local.into(), 1234),
                    disabled,
                    options(),
                    &mut network.host,
                )
                .unwrap();
            let capability = network.host.administration();
            let target = network
                .host
                .admin_paths(&capability)
                .unwrap()
                .find(|p| p.snapshot.key().destination().address() == disabled.ip())
                .unwrap();
            let candidate = network
                .host
                .admin_validate(
                    &capability,
                    0,
                    path::AdminChange {
                        target: path::AdminTarget::Path(target.snapshot.path()),
                        expected: target.generation,
                        policy: path::AdminPolicy {
                            discovery_disabled: true,
                            estimate: None,
                        },
                    },
                )
                .unwrap();
            network
                .host
                .admin_apply(&capability, &mut endpoint, candidate)
                .unwrap();
            let other = endpoint
                .connect_with_path_provider(
                    0,
                    SocketAddr::new(local.into(), 1235),
                    neighbor,
                    options(),
                    &mut network.host,
                )
                .unwrap();
            let to = |packet: &Vec<u8>, peer: SocketAddr| {
                IpAddr::from([packet[16], packet[17], packet[18], packet[19]]) == peer.ip()
            };
            for time in [1, MDL_US - 1] {
                transmit_frames(
                    &mut network,
                    &mut endpoint,
                    time,
                    &mut output,
                    &mut pending,
                    IP_HEADER,
                    &mut Sample(0),
                    &mut backend,
                )
                .unwrap();
                assert!(pending.is_none(), "no frame blocks selection");
                assert!(endpoint.is_output_reserved(held), "the held SYN keeps its reservation");
                assert!(!endpoint.is_output_reserved(other));
                assert!(!backend.submitted.iter().any(|p| to(p, disabled)));
            }
            let neighbor_syn = backend.submitted.first().unwrap();
            assert!(to(neighbor_syn, neighbor));
            assert_ne!(neighbor_syn[6] & 0x40, 0, "DF on the enabled path");
            let sent = backend.submitted.len();
            transmit_frames(
                &mut network,
                &mut endpoint,
                MDL_US,
                &mut output,
                &mut pending,
                IP_HEADER,
                &mut Sample(0),
                &mut backend,
            )
            .unwrap();
            assert!(!endpoint.is_output_reserved(held));
            let syn: Vec<_> = backend.submitted[sent..]
                .iter()
                .filter(|p| to(p, disabled))
                .collect();
            assert_eq!(syn.len(), 1, "the held SYN, once");
            assert_eq!(syn[0][6] & 0x40, 0, "DF clear on the disabled path");
            assert_ne!(u16::from_be_bytes([syn[0][4], syn[0][5]]), 0);
            assert_eq!(checksum(&syn[0][..20]), 0);
        }

        // RFC 6864 uniqueness holds at the final destination: a source-routed
        // SYN on a discovery-disabled path leaves DF clear through this
        // embedding's `lease_df_clear` with an Identification of the
        // (source, final destination, TCP) tuple, so an option-free packet
        // to that destination leases the next value, not its first hop's.
        #[test]
        fn source_routed_df_clear_frames_lease_for_the_final_destination() {
            use ntcp_io::{PacketIo, PacketLayer};
            const MDL_US: u64 = 120_000_000;
            struct Mock {
                submitted: Vec<Vec<u8>>,
            }
            impl PacketIo for Mock {
                fn layer(&self) -> PacketLayer {
                    PacketLayer::Ip
                }
                fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
                    Ok(None)
                }
                fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
                    self.submitted.push(packet.to_vec());
                    Ok(TxOutcome::Submitted)
                }
            }
            let (_, _, local) = packet();
            let mut output = [0; MTU];
            let mut pending = None;
            let mut backend = Mock {
                submitted: Vec::new(),
            };
            let config = EndpointConfig {
                ipv4_options_enabled: true,
                ..Default::default()
            };
            let mut endpoint =
                Endpoint::new(config.clone(), [1; 32], 0, test_policy(local)).unwrap();
            let mut network = TunHost::attach(&mut endpoint, &config, local.into()).unwrap();
            let destination: SocketAddr = "10.0.0.1:8080".parse().unwrap();
            let hop = Ipv4Addr::new(10, 0, 0, 9);
            endpoint
                .connect_with_path_provider(
                    0,
                    SocketAddr::new(local.into(), 1234),
                    destination,
                    ntcp::ManagedOpenOptions {
                        transport: ntcp::ActiveOpenOptions::from(&config.connection),
                        dscp: config.dscp,
                        ipv4_options: ntcp::OutgoingIpv4Options {
                            source_route: Some(ntcp::SourceRoute::new(&[hop], false).unwrap()),
                            ..Default::default()
                        },
                        registration: None,
                        receive_authority: None,
                    },
                    &mut network.host,
                )
                .unwrap();
            let capability = network.host.administration();
            let target = network
                .host
                .admin_paths(&capability)
                .unwrap()
                .find(|p| p.snapshot.key().destination().address() == destination.ip())
                .unwrap();
            let candidate = network
                .host
                .admin_validate(
                    &capability,
                    0,
                    path::AdminChange {
                        target: path::AdminTarget::Path(target.snapshot.path()),
                        expected: target.generation,
                        policy: path::AdminPolicy {
                            discovery_disabled: true,
                            estimate: None,
                        },
                    },
                )
                .unwrap();
            network
                .host
                .admin_apply(&capability, &mut endpoint, candidate)
                .unwrap();
            transmit_frames(
                &mut network,
                &mut endpoint,
                MDL_US,
                &mut output,
                &mut pending,
                IP_HEADER,
                &mut Sample(0),
                &mut backend,
            )
            .unwrap();
            let syn = &backend.submitted[0];
            let header = usize::from(syn[0] & 15) * 4;
            assert!(header > 20, "the source route is in the header");
            assert_eq!(&syn[16..20], &hop.octets(), "sent to the route's first hop");
            assert_eq!(syn[6] & 0x40, 0, "DF clear on the disabled path");
            assert_eq!(checksum(&syn[..header]), 0);
            let first = u16::from_be_bytes([syn[4], syn[5]]);
            assert_ne!(first, 0);
            // An option-free TCP header to the final destination.
            let mut direct = [0; 40];
            direct[..12].copy_from_slice(&[0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0]);
            direct[12..16].copy_from_slice(&local.octets());
            if let IpAddr::V4(final_destination) = destination.ip() {
                direct[16..20].copy_from_slice(&final_destination.octets());
            }
            let sum = checksum(&direct[..20]);
            direct[10..12].copy_from_slice(&sum.to_be_bytes());
            network.host.lease_df_clear(MDL_US, &mut direct).unwrap();
            assert_eq!(direct[6] & 0x40, 0);
            assert_eq!(
                u16::from_be_bytes([direct[4], direct[5]]),
                first.wrapping_add(1)
            );
        }

        // The final bytes follow the decision current at each submission:
        // a SYN rewritten DF clear with a leased Identification on a
        // discovery-disabled path, whose submission the backend refuses
        // with WouldBlock, leaves after the owner re-enables discovery with
        // the atomic header (DF set, Identification 0, valid checksum).
        #[test]
        fn blocked_df_clear_frame_follows_a_reenable() {
            use ntcp_io::{PacketIo, PacketLayer};
            const MDL_US: u64 = 120_000_000;
            struct Mock {
                offered: Vec<Vec<u8>>,
                submitted: Vec<Vec<u8>>,
            }
            impl PacketIo for Mock {
                fn layer(&self) -> PacketLayer {
                    PacketLayer::Ip
                }
                fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
                    Ok(None)
                }
                fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
                    self.offered.push(packet.to_vec());
                    if self.offered.len() == 1 {
                        return Ok(TxOutcome::WouldBlock);
                    }
                    self.submitted.push(packet.to_vec());
                    Ok(TxOutcome::Submitted)
                }
            }
            let (_, _, local) = packet();
            let mut output = [0; MTU];
            let mut pending = None;
            let mut backend = Mock {
                offered: Vec::new(),
                submitted: Vec::new(),
            };
            let config = EndpointConfig::default();
            let mut endpoint =
                Endpoint::new(config.clone(), [1; 32], 0, test_policy(local)).unwrap();
            let mut network = TunHost::attach(&mut endpoint, &config, local.into()).unwrap();
            let remote: SocketAddr = "10.0.0.1:8080".parse().unwrap();
            let id = endpoint
                .connect_with_path_provider(
                    0,
                    SocketAddr::new(local.into(), 1234),
                    remote,
                    ntcp::ManagedOpenOptions {
                        transport: ntcp::ActiveOpenOptions::from(&config.connection),
                        dscp: config.dscp,
                        ipv4_options: Default::default(),
                        registration: None,
                        receive_authority: None,
                    },
                    &mut network.host,
                )
                .unwrap();
            let capability = network.host.administration();
            let set = |network: &mut TunHost, endpoint: &mut Endpoint, disabled: bool| {
                let target = network
                    .host
                    .admin_paths(&capability)
                    .unwrap()
                    .find(|p| p.snapshot.key().destination().address() == remote.ip())
                    .unwrap();
                let candidate = network
                    .host
                    .admin_validate(
                        &capability,
                        0,
                        path::AdminChange {
                            target: path::AdminTarget::Path(target.snapshot.path()),
                            expected: target.generation,
                            policy: path::AdminPolicy {
                                discovery_disabled: disabled,
                                estimate: None,
                            },
                        },
                    )
                    .unwrap();
                network
                    .host
                    .admin_apply(&capability, endpoint, candidate)
                    .unwrap();
            };
            set(&mut network, &mut endpoint, true);
            // After the start quiet period the DF-clear lease succeeds.
            transmit_frames(
                &mut network,
                &mut endpoint,
                MDL_US,
                &mut output,
                &mut pending,
                IP_HEADER,
                &mut Sample(0),
                &mut backend,
            )
            .unwrap();
            assert!(backend.submitted.is_empty());
            let blocked = backend.offered[0].clone();
            assert_eq!(blocked[6] & 0x40, 0, "offered DF clear while disabled");
            assert_ne!(u16::from_be_bytes([blocked[4], blocked[5]]), 0);
            assert!(pending.is_some() && endpoint.is_output_reserved(id));
            set(&mut network, &mut endpoint, false);
            transmit_frames(
                &mut network,
                &mut endpoint,
                MDL_US + 1,
                &mut output,
                &mut pending,
                IP_HEADER,
                &mut Sample(0),
                &mut backend,
            )
            .unwrap();
            assert!(!endpoint.is_output_reserved(id));
            let syn = &backend.submitted[0];
            assert_eq!(&syn[20..], &blocked[20..], "the same held segment");
            assert_ne!(syn[6] & 0x40, 0, "DF set on the enabled path");
            assert_eq!(u16::from_be_bytes([syn[4], syn[5]]), 0, "atomic Identification");
            assert_eq!(checksum(&syn[..20]), 0);
        }

        #[test]
        fn pending_packet_survives_backpressure() {
            use ntcp_io::{PacketIo, PacketLayer};
            struct Mock {
                attempts: usize,
                submitted: Vec<Vec<u8>>,
            }
            impl PacketIo for Mock {
                fn layer(&self) -> PacketLayer {
                    PacketLayer::Ip
                }
                fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
                    Ok(None)
                }
                fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
                    self.attempts += 1;
                    if self.attempts <= 2 {
                        return Ok(TxOutcome::WouldBlock);
                    }
                    self.submitted.push(packet.to_vec());
                    Ok(TxOutcome::Submitted)
                }
            }
            let (_, _, local) = packet();
            let mut output = [0; MTU];
            let mut pending = None;
            let mut backend = Mock {
                attempts: 0,
                submitted: Vec::new(),
            };
            let config = EndpointConfig::default();
            let mut endpoint =
                Endpoint::new(config.clone(), [1; 32], 0, test_policy(local)).unwrap();
            let mut network = TunHost::attach(&mut endpoint, &config, local.into()).unwrap();
            let id = endpoint
                .connect_with_path_provider(
                    0,
                    SocketAddr::new(local.into(), 1234),
                    "10.0.0.1:8080".parse().unwrap(),
                    ntcp::ManagedOpenOptions {
                        transport: ntcp::ActiveOpenOptions::from(&config.connection),
                        dscp: config.dscp,
                        ipv4_options: Default::default(),
                        registration: None,
                        receive_authority: None,
                    },
                    &mut network.host,
                )
                .unwrap();
            let mut staged = Vec::new();
            let mut attempt = None;
            for _ in 0..2 {
                transmit_frames(
                    &mut network,
                    &mut endpoint,
                    0,
                    &mut output,
                    &mut pending,
                    IP_HEADER,
                    &mut Sample(0),
                    &mut backend,
                )
                .unwrap();
                let held = pending.as_ref().unwrap();
                if staged.is_empty() {
                    staged.extend_from_slice(&output[..held.len]);
                    attempt = Some(held.attempt);
                }
                assert_eq!(&output[..held.len], staged);
                assert_eq!(Some(held.attempt), attempt);
                assert!(endpoint.is_output_reserved(id));
                assert!(backend.submitted.is_empty());
                assert_eq!(backend.receive(&mut [0; 1]).unwrap(), None);
            }
            transmit_frames(
                &mut network,
                &mut endpoint,
                0,
                &mut output,
                &mut pending,
                IP_HEADER,
                &mut Sample(0),
                &mut backend,
            )
            .unwrap();
            assert!(pending.is_none());
            assert!(!endpoint.is_output_reserved(id));
            assert_eq!(backend.submitted, vec![staged]);
            assert!(endpoint.transmit_attempt_packet(attempt.unwrap()).is_none());
            transmit_frames(
                &mut network,
                &mut endpoint,
                0,
                &mut output,
                &mut pending,
                IP_HEADER,
                &mut Sample(0),
                &mut backend,
            )
            .unwrap();
            assert_eq!(backend.submitted.len(), 1, "duplicate send");
        }

        fn v6_transmit(len: usize) -> ntcp::Transmit {
            ntcp::Transmit {
                connection: None,
                tx_timestamp: None,
                ip: IpMetadata {
                    source: "2001:db8::1".parse().unwrap(),
                    destination: "2001:db8::2".parse().unwrap(),
                },
                len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: ntcp::OutgoingIpv4Options::default(),
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc3168#section-5
        //= type=test
        //= reason=All 64 DSCP values and four ECN values are packed/extracted across both IPv6 Traffic Class nibbles; flow-label high nibble is independent. Bounds, address and direct-TCP scope rejection are asserted.
        //# Bits 6 and 7 in the IPv4 TOS octet are designated as the ECN field. The IPv4 TOS octet corresponds to the Traffic Class octet in IPv6, and the ECN field is defined identically in both cases.
        #[test]
        fn ipv6_base_header_matrix_and_rejections() {
            let local = "2001:db8::2".parse().unwrap();
            let mut bytes = [0xa5; MTU];
            for dscp in 0..64 {
                for ecn in 0..4 {
                    for hop_limit in [1, 64, 255] {
                        let mut transmit = v6_transmit(20);
                        transmit.dscp = dscp;
                        transmit.ecn = ecn;
                        transmit.hop_limit = hop_limit;
                        let len = build_frame(&mut bytes, transmit, 0).unwrap();
                        assert_eq!(len, 60);
                        assert_eq!(bytes[0], 0x60 | (dscp >> 2));
                        assert_eq!(bytes[1], ((dscp << 2) | ecn) << 4);
                        assert_eq!(&bytes[4..8], &[0, 20, 6, hop_limit]);
                        assert_eq!(&bytes[40..60], &[0xa5; 20]);
                        for flow_nibble in 0..16 {
                            bytes[1] = (bytes[1] & 0xf0) | flow_nibble;
                            let (ip, class, tcp) = parse_ipv6(&bytes[..len], local).unwrap();
                            assert_eq!(ip, transmit.ip);
                            assert_eq!(class, (dscp << 2) | ecn);
                            assert_eq!(tcp, &[0xa5; 20]);
                        }
                    }
                }
            }
            let len = build_frame(&mut bytes, v6_transmit(20), 0).unwrap();
            for truncated in 0..len {
                assert!(parse_ipv6(&bytes[..truncated], local).is_none());
            }
            assert!(parse_ipv6(&bytes[..len + 1], local).is_none());
            assert!(parse_ipv6(&bytes[..len], "2001:db8::3".parse().unwrap()).is_none());
            for (offset, value) in [(0, 0x40), (4, 1), (5, 19), (5, 21)] {
                let mut bad = bytes;
                bad[offset] = value;
                assert!(parse_ipv6(&bad[..len], local).is_none());
            }
            // Hop-by-hop (including jumbo), routing, fragment, ESP, AH,
            // destination options, no-next-header, UDP and unknown protocols.
            for next in [0, 43, 44, 50, 51, 60, 59, 17, 255] {
                let mut bad = bytes;
                bad[6] = next;
                assert!(parse_ipv6(&bad[..len], local).is_none());
            }
            // Destination input accepts Hop Limit zero; originating policy is
            // checked separately below when building frames.
            let mut expired = bytes;
            expired[7] = 0;
            let (ip, class, tcp) = parse_ipv6(&expired[..len], local).unwrap();
            assert_eq!(ip, v6_transmit(20).ip);
            assert_eq!(class, 0);
            assert_eq!(tcp, &bytes[IPV6_HEADER..len]);

            // A zero Payload Length is a legal empty base packet. A Jumbo
            // Payload option requires the unsupported Hop-by-Hop header.
            let mut empty = bytes;
            empty[4..6].fill(0);
            assert!(
                parse_ipv6(&empty[..IPV6_HEADER], local)
                    .unwrap()
                    .2
                    .is_empty()
            );
            assert!(parse_ipv6(&empty[..len], local).is_none());
            let mut jumbo = empty;
            jumbo[6] = 0;
            assert!(parse_ipv6(&jumbo[..IPV6_HEADER], local).is_none());
            for address in [
                "::",
                "ff02::1",
                "fe80::1",
                "fec0::1",
                "::1",
                "::ffff:192.0.2.1",
            ] {
                let address: Ipv6Addr = address.parse().unwrap();
                for offset in [8, 24] {
                    let mut bad = bytes;
                    bad[offset..offset + 16].copy_from_slice(&address.octets());
                    assert!(
                        parse_ipv6(&bad[..len], if offset == 24 { address } else { local })
                            .is_none()
                    );
                    let mut transmit = v6_transmit(20);
                    if offset == 8 {
                        transmit.ip.source = address.into();
                    } else {
                        transmit.ip.destination = address.into();
                    }
                    assert!(build_frame(&mut bad, transmit, 0).is_err());
                }
            }
            let local_ip = IpAddr::V6(local);
            assert!(checked_peer("[2001:db8::1]:8080", local_ip).is_ok());
            for peer in [
                "192.0.2.1:8080",
                "[2001:db8::1]:0",
                "[2001:db8::1%2]:8080",
                "[fe80::1]:8080",
                "[ff02::1]:8080",
                "invalid",
            ] {
                assert!(checked_peer(peer, local_ip).is_err());
            }
            assert!(checked_peer("[2001:db8::1]:8080", "192.0.2.2".parse().unwrap()).is_err());
            let policy = tun_v6_policy(local);
            assert!(policy(AddressValidation::Bind {
                local: local.into()
            }));
            assert!(!policy(AddressValidation::Bind {
                local: "2001:db8::3".parse().unwrap()
            }));
            assert!(!policy(AddressValidation::Incoming {
                source: "192.0.2.1".parse().unwrap(),
                destination: local.into()
            }));
            for payload in [1, 20, MTU - IPV6_HEADER] {
                let len = build_frame(&mut bytes, v6_transmit(payload), 0).unwrap();
                assert_eq!(len, IPV6_HEADER + payload);
                assert_eq!(parse_ipv6(&bytes[..len], local).unwrap().2.len(), payload);
            }
            let before = bytes;
            for payload in [0, MTU - IPV6_HEADER + 1, usize::MAX] {
                assert!(build_frame(&mut bytes, v6_transmit(payload), 0).is_err());
                assert_eq!(bytes, before);
            }
            assert!(build_frame(&mut bytes[..59], v6_transmit(20), 0).is_err());
            for (dscp, ecn, hop) in [(64, 0, 64), (0, 4, 64), (0, 0, 0)] {
                let mut transmit = v6_transmit(20);
                transmit.dscp = dscp;
                transmit.ecn = ecn;
                transmit.hop_limit = hop;
                assert!(build_frame(&mut bytes, transmit, 0).is_err());
            }
            let mut transmit = v6_transmit(20);
            transmit.ip.destination = "192.0.2.2".parse().unwrap();
            assert!(build_frame(&mut bytes, transmit, 0).is_err());
            transmit = v6_transmit(20);
            transmit.ipv4_options.record_route_slots = Some(1);
            assert!(build_frame(&mut bytes, transmit, 0).is_err());
            let (v4, len, _) = packet();
            assert!(parse_ipv6(&v4[..len], local).is_none());
            assert!(parse_ipv4(&bytes[..60], Ipv4Addr::new(192, 0, 2, 2)).is_none());
        }

        //= https://www.rfc-editor.org/rfc/rfc3168#section-5
        //= type=test
        //= reason=Two actual IPv6 Endpoints negotiate ECN through the runtime base-header encoder/input dispatch, transmit ECT data, receive CE Traffic Class, emit ECE feedback and then CWR data. This is privilege-free adapter evidence, not a live kernel TUN/routing test.
        //# Bits 6 and 7 in the IPv4 TOS octet are designated as the ECN field. The IPv4 TOS octet corresponds to the Traffic Class octet in IPv6, and the ECN field is defined identically in both cases.
        #[test]
        fn ipv6_framed_handshake_and_ecn_feedback() {
            fn transfer(
                from_host: &mut TunHost,
                from: &mut Endpoint,
                to_host: &mut TunHost,
                to: &mut Endpoint,
                local: IpAddr,
                time: u64,
                mark_ce: bool,
            ) -> Vec<(u8, u8, usize)> {
                let mut observed = Vec::new();
                for mut bytes in super::pmtu_tests::emit(from_host, from, time, local) {
                    let IpAddr::V6(local_v6) = local else {
                        panic!("wrong family")
                    };
                    let (ip, class, tcp) = parse_ipv6(&bytes, local_v6).unwrap();
                    let segment = ntcp::wire::parse(ip, tcp).unwrap();
                    assert_eq!(class >> 2, 37);
                    assert_eq!(bytes[7], 64);
                    observed.push((segment.header.flags, class & 3, segment.payload.len()));
                    if mark_ce && !segment.payload.is_empty() {
                        assert_eq!(class & 3, 2, "negotiated data must be ECT(0)");
                        bytes[1] = (bytes[1] & 0xcf) | 0x30;
                    }
                    input_frame(to_host, to, time, &bytes, local, false, &mut Sample(0)).unwrap();
                }
                observed
            }
            let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
            let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
            let mut cfg = EndpointConfig {
                dscp: 37,
                ..EndpointConfig::default()
            };
            cfg.connection.nagle = false;
            cfg.connection.mss = (MTU - IPV6_HEADER - 20) as u16;
            cfg.connection.receive_ip_payload_limit = (MTU - IPV6_HEADER) as u16;
            cfg.connection.send_ip_payload_limit = (MTU - IPV6_HEADER) as u16;
            let mut client = Endpoint::new(cfg.clone(), [1; 32], 0, tun_v6_policy(a)).unwrap();
            let mut server = Endpoint::new(cfg.clone(), [2; 32], 0, tun_v6_policy(b)).unwrap();
            let mut client_host = TunHost::attach(&mut client, &cfg, a.into()).unwrap();
            let mut server_host = TunHost::attach(&mut server, &cfg, b.into()).unwrap();
            let local = SocketAddr::new(a.into(), 1234);
            let remote = SocketAddr::new(b.into(), 8080);
            let listener = server.listen(remote, 1).unwrap();
            let id = client
                .connect_with_path_provider(
                    0,
                    local,
                    remote,
                    ntcp::ManagedOpenOptions {
                        transport: ntcp::ActiveOpenOptions::from(&cfg.connection),
                        dscp: cfg.dscp,
                        ipv4_options: Default::default(),
                        registration: None,
                        receive_authority: None,
                    },
                    &mut client_host.host,
                )
                .unwrap();
            let syn = transfer(
                &mut client_host,
                &mut client,
                &mut server_host,
                &mut server,
                b.into(),
                0,
                false,
            );
            assert_eq!(syn.len(), 1);
            assert_eq!(
                syn[0],
                (ntcp::wire::SYN | ntcp::wire::ECE | ntcp::wire::CWR, 0, 0)
            );
            let synack = transfer(
                &mut server_host,
                &mut server,
                &mut client_host,
                &mut client,
                a.into(),
                0,
                false,
            );
            assert_eq!(synack.len(), 1);
            assert_eq!(
                synack[0],
                (ntcp::wire::SYN | ntcp::wire::ACK | ntcp::wire::ECE, 0, 0)
            );
            transfer(
                &mut client_host,
                &mut client,
                &mut server_host,
                &mut server,
                b.into(),
                0,
                false,
            );
            let accepted = server.accept(listener).unwrap();
            assert_eq!(client.state(id).unwrap(), State::Established);
            assert_eq!(server.state(accepted).unwrap(), State::Established);
            client.write(id, b"CE-marked data").unwrap();
            let data = transfer(
                &mut client_host,
                &mut client,
                &mut server_host,
                &mut server,
                b.into(),
                1,
                true,
            );
            assert!(data.iter().any(|&(_, ecn, len)| ecn == 2 && len == 14));
            server.on_timeout(300_000, BUDGET).unwrap();
            let feedback = transfer(
                &mut server_host,
                &mut server,
                &mut client_host,
                &mut client,
                a.into(),
                300_000,
                false,
            );
            assert!(
                feedback
                    .iter()
                    .any(|&(flags, ecn, len)| flags & ntcp::wire::ECE != 0 && ecn == 0 && len == 0)
            );
            let mut received = [0; 32];
            let count = server.read(accepted, &mut received).unwrap();
            assert_eq!(&received[..count], b"CE-marked data");
            client.write(id, b"after feedback").unwrap();
            let cwr = transfer(
                &mut client_host,
                &mut client,
                &mut server_host,
                &mut server,
                b.into(),
                300_001,
                false,
            );
            assert!(
                cwr.iter()
                    .any(|&(flags, ecn, len)| flags & ntcp::wire::CWR != 0 && ecn == 2 && len > 0)
            );
        }

        fn test_policy(local: Ipv4Addr) -> impl Fn(AddressValidation) -> bool {
            tun_address_policy(
                local,
                checked_interface_subnet(local, local, 0xffff_ff00).unwrap(),
            )
        }

        #[test]
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //= type=test
        //= reason=The actual TUN policy rejects a checksummed broadcast-source SYN after IP parsing in an explicit /24 context; no kernel filtering is assumed.
        //# |  An incoming SYN with an invalid source address MUST be ignored
        //# |  either by TCP or by the IP layer [(MUST-63)] (see
        //# |  Section 3.2.1.3).
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //= type=test
        //= reason=The adapter rejects the broadcast destination before TCP under its configured-local-address restriction.
        //#   A TCP implementation MUST silently discard an incoming SYN segment
        //# |  that is addressed to a broadcast or multicast address [(MUST-57)].
        fn tun_policy_rejects_broadcast_syn_without_kernel_filtering() {
            let local = Ipv4Addr::new(192, 0, 2, 2);
            let broadcast = Ipv4Addr::new(192, 0, 2, 255);
            let host = Ipv4Addr::new(192, 0, 2, 1);
            let mut endpoint =
                Endpoint::new(EndpointConfig::default(), [1; 32], 0, test_policy(local)).unwrap();
            endpoint
                .listen(SocketAddr::new(local.into(), 8080), 1)
                .unwrap();
            for (source, destination) in [(broadcast, local), (host, broadcast), (host, local)] {
                let ip = IpMetadata {
                    source: source.into(),
                    destination: destination.into(),
                };
                let mut packet = [0; MTU];
                let tcp_len = ntcp::wire::encode(
                    ip,
                    ntcp::wire::Header {
                        source_port: 40000,
                        destination_port: 8080,
                        sequence: 1,
                        acknowledgment: 0,
                        flags: ntcp::wire::SYN,
                        window: 1024,
                        urgent_pointer: 0,
                    },
                    &[],
                    &[],
                    &mut packet[IP_HEADER..],
                )
                .unwrap();
                let len = build_ipv4(&mut packet, ip, tcp_len, 64, 0, 0).unwrap();
                let parsed = parse_ipv4_options(&packet[..len], local, false, 0);
                if destination == broadcast {
                    assert!(parsed.is_none());
                } else {
                    let (ip, tcp, options) = parsed.unwrap();
                    assert!(ntcp::wire::parse(ip, tcp).is_ok());
                    let result = endpoint
                        .input_with_ipv4_options(0, ip, 0, options, tcp)
                        .unwrap();
                    assert_eq!(
                        result,
                        if source == broadcast {
                            ntcp::InputDisposition::Dropped
                        } else {
                            ntcp::InputDisposition::Processed
                        }
                    );
                }
                let output = endpoint.poll_transmit(0, &mut [0; MTU], BUDGET).unwrap();
                if source == broadcast || destination == broadcast {
                    assert_eq!(endpoint.buffer_bytes(), 0);
                    assert!(output.packet.is_none());
                    assert!(!output.more_work);
                } else {
                    assert!(endpoint.buffer_bytes() > 0);
                    assert!(output.packet.is_some());
                }
            }
        }

        // Rejected-source SYNs through the real TunHost ingress must stay
        // silent discards: they neither terminate run() nor disturb a stream.
        #[test]
        fn framed_rejected_source_syns_keep_tun_loop_and_stream_alive() {
            let a = Ipv4Addr::new(192, 0, 2, 1);
            let b = Ipv4Addr::new(192, 0, 2, 2);
            let mut cfg = EndpointConfig::default();
            cfg.connection.nagle = false;
            let mut client = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy(a)).unwrap();
            let mut server = Endpoint::new(cfg.clone(), [2; 32], 0, test_policy(b)).unwrap();
            let mut client_host = TunHost::attach(&mut client, &cfg, a.into()).unwrap();
            let mut server_host = TunHost::attach(&mut server, &cfg, b.into()).unwrap();
            let remote = SocketAddr::new(b.into(), 8080);
            let listener = server.listen(remote, 4).unwrap();
            let id = client
                .connect_with_path_provider(
                    0,
                    SocketAddr::new(a.into(), 1234),
                    remote,
                    ntcp::ManagedOpenOptions {
                        transport: ntcp::ActiveOpenOptions::from(&cfg.connection),
                        dscp: cfg.dscp,
                        ipv4_options: Default::default(),
                        registration: None,
                        receive_authority: None,
                    },
                    &mut client_host.host,
                )
                .unwrap();
            let exchange = |client: &mut Endpoint,
                                client_host: &mut TunHost,
                                server: &mut Endpoint,
                                server_host: &mut TunHost,
                                time: u64| {
                for _ in 0..16 {
                    let to_server = super::pmtu_tests::emit(client_host, client, time, b.into());
                    for frame in &to_server {
                        input_frame(server_host, server, time, frame, b.into(), false, &mut Sample(0)).unwrap();
                    }
                    let to_client = super::pmtu_tests::emit(server_host, server, time, a.into());
                    for frame in &to_client {
                        input_frame(client_host, client, time, frame, a.into(), false, &mut Sample(0)).unwrap();
                    }
                    if to_server.is_empty() && to_client.is_empty() {
                        return;
                    }
                }
                panic!("framed exchange did not quiesce");
            };
            exchange(&mut client, &mut client_host, &mut server, &mut server_host, 0);
            let accepted = server.accept(listener).unwrap();
            assert_eq!(client.state(id).unwrap(), State::Established);
            let bindings = server_host.host.binding_count();
            for (index, source) in [
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::new(224, 0, 0, 1),
                Ipv4Addr::new(192, 0, 2, 255),
            ]
            .into_iter()
            .enumerate()
            {
                let ip = IpMetadata {
                    source: source.into(),
                    destination: b.into(),
                };
                let mut packet = [0; MTU];
                let tcp_len = ntcp::wire::encode(
                    ip,
                    ntcp::wire::Header {
                        source_port: 40000 + index as u16,
                        destination_port: 8080,
                        sequence: 1,
                        acknowledgment: 0,
                        flags: ntcp::wire::SYN,
                        window: 1024,
                        urgent_pointer: 0,
                    },
                    &[],
                    &[],
                    &mut packet[IP_HEADER..],
                )
                .unwrap();
                // Build with a unicast placeholder, then install the real source.
                let placeholder = IpMetadata {
                    source: Ipv4Addr::new(198, 51, 100, 7).into(),
                    destination: b.into(),
                };
                let len = build_ipv4(&mut packet, placeholder, tcp_len, 64, 0, 0).unwrap();
                packet[12..16].copy_from_slice(&source.octets());
                reseal(&mut packet);
                let result =
                    input_frame(&mut server_host, &mut server, 1, &packet[..len], b.into(), false, &mut Sample(0));
                println!("framed TUN SYN from {source}: {result:?}");
                assert!(result.is_ok());
                assert_eq!(server_host.host.binding_count(), bindings);
                assert!(super::pmtu_tests::emit(&mut server_host, &mut server, 1, a.into()).is_empty());
            }
            for (time, payload) in [(2, &b"after rejected"[..]), (3, &b"second round"[..])] {
                client.write(id, payload).unwrap();
                exchange(&mut client, &mut client_host, &mut server, &mut server_host, time);
                let mut received = [0; 32];
                let count = server.read(accepted, &mut received).unwrap();
                assert_eq!(&received[..count], payload);
                server.write(accepted, &received[..count]).unwrap();
                exchange(&mut client, &mut client_host, &mut server, &mut server_host, time);
                let count = client.read(id, &mut received).unwrap();
                assert_eq!(&received[..count], payload);
            }
        }

        // The real active open's originated options state the expected
        // registrations; the plan, not the stack, sizes nothing.
        //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
        //= type=test
        //# A recorded route is composed of a series of internet addresses. Each
        //# internet address is 32 bits or 4 octets. If the pointer is greater than
        //# the length, the recorded route data area is full. The originating host
        //# must compose this option with a large enough route data area to hold all
        //# the address expected. The size of the option does not change due to
        //# adding addresses. The intitial contents of the route data area must be
        //# zero.

        //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
        //= type=test
        //# The originating host must compose this option with a large enough
        //# timestamp data area to hold all the timestamp information expected. The
        //# size of the option does not change due to adding timestamps. The
        //# intitial contents of the timestamp data area must be zero or internet
        //# address/zero pairs.
        #[test]
        fn originated_option_configuration_states_expected_registrations() {
            use ntcp::{
                ExpectedTimestamps, Ipv4RegistrationError, Ipv4RegistrationPlan, RegisteredOption,
                TimestampRequest,
            };
            let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
            let peer = IpAddr::V4(Ipv4Addr::new(198, 18, 2, 2));
            assert!(origination(None, None).unwrap().is_none());
            let (options, expected) = origination(Some("3,3"), Some("times,3,3"))
                .unwrap()
                .unwrap();
            assert!(options.source_route.unwrap().hops().is_empty());
            assert_eq!(options.record_route_slots, Some(3));
            assert_eq!(options.timestamp, Some(TimestampRequest::Times(3)));
            assert_eq!(expected.record_route, Some(3));
            assert_eq!(expected.timestamp, Some(ExpectedTimestamps::Count(3)));
            // Three records each: 15 + 16 octets, padded to 32.
            let plan = Ipv4RegistrationPlan::new(local, peer, options, &expected).unwrap();
            assert_eq!(plan.option_octets(), 32);
            let (options, expected) = origination(None, Some("addresses,4,3")).unwrap().unwrap();
            assert_eq!(options.record_route_slots, None);
            assert_eq!(options.timestamp, Some(TimestampRequest::AddressTimes(4)));
            assert_eq!(
                Ipv4RegistrationPlan::new(local, peer, options, &expected)
                    .unwrap()
                    .option_octets(),
                36
            );
            // Addressed Timestamp beside three Record Route records needs 43.
            let (options, expected) = origination(Some("3,3"), Some("addresses,3,3"))
                .unwrap()
                .unwrap();
            assert_eq!(
                Ipv4RegistrationPlan::new(local, peer, options, &expected).err(),
                Some(Ipv4RegistrationError::CombinedCapacity {
                    required_octets: 44,
                    maximum: 40
                })
            );
            let (options, expected) = origination(Some("2,3"), None).unwrap().unwrap();
            assert_eq!(
                Ipv4RegistrationPlan::new(local, peer, options, &expected).err(),
                Some(Ipv4RegistrationError::InsufficientRecords {
                    option: RegisteredOption::RecordRoute,
                    expected: 3,
                    available: 2
                })
            );
            for bad in ["3", "3,", ",3", "3,3,3", "+3,3", "256,3", " 3,3", "3,3 "] {
                assert!(origination(Some(bad), None).is_err(), "{bad:?}");
            }
            for bad in [
                "times,3",
                "flags,3,3",
                "times,3,3,3",
                "addresses,-1,3",
                "Times,3,3",
            ] {
                assert!(origination(None, Some(bad)).is_err(), "{bad:?}");
            }
        }

        #[test]
        fn enabled_option_profile_header_mtu_and_timestamp_roundtrip() {
            use ntcp::{OutgoingIpv4Options, SourceRoute, TimestampRequest};
            assert!(!options_enabled(None).unwrap());
            assert!(options_enabled(Some("1")).unwrap());
            for value in ["", "0", "true", "01", " 1", "1 "] {
                assert!(options_enabled(Some(value)).is_err());
            }
            let source = Ipv4Addr::new(192, 0, 2, 1);
            let local = Ipv4Addr::new(192, 0, 2, 2);
            let hop = Ipv4Addr::new(192, 0, 2, 9);
            let ip = IpMetadata {
                source: source.into(),
                destination: local.into(),
            };
            let mut bytes = [0xa5; MTU];
            let mut transmit = ntcp::Transmit {
                connection: None,
                tx_timestamp: None,
                ip,
                len: 1440,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: OutgoingIpv4Options {
                    source_route: Some(SourceRoute::new(&[hop], false).unwrap()),
                    record_route_slots: Some(2),
                    timestamp: Some(TimestampRequest::Times(4)),
                },
            };
            let len = build_ipv4_options(&mut bytes, transmit, 0x8000_0001).unwrap();
            assert_eq!(len, MTU);
            assert_eq!(bytes[0], 0x4f);
            assert_eq!(checksum(&bytes[..60]), 0);
            assert_eq!(&bytes[16..20], &hop.octets());
            assert_eq!(&bytes[23..27], &local.octets());
            assert_eq!(&bytes[60..], &[0xa5; 1440]);
            // Simulate RFC 791's router swap, not a live kernel source-route path.
            bytes[16..20].copy_from_slice(&local.octets());
            bytes[23..27].copy_from_slice(&hop.octets());
            bytes[22] = 8;
            reseal(&mut bytes);
            assert!(parse_ipv4_options(&bytes, local, false, 0).is_none());
            let (received_ip, tcp, options) =
                parse_ipv4_options(&bytes, local, true, 0x8000_0002).unwrap();
            assert_eq!(received_ip, ip);
            assert_eq!(tcp, &[0xa5; 1440]);
            assert_eq!(options.return_route(source).unwrap().hops(), &[hop]);
            let recorded = options.as_bytes();
            assert_eq!(&recorded[14..18], &local.octets()); // RR's second slot.
            assert_eq!(&recorded[26..30], &0x8000_0002u32.to_be_bytes());
            let before = bytes;
            transmit.len = 1441;
            assert!(build_ipv4_options(&mut bytes, transmit, 0).is_err());
            assert_eq!(bytes, before);
            transmit.len = 1440;
            assert!(build_ipv4_options(&mut bytes[..MTU - 1], transmit, 0).is_err());
            assert_eq!(bytes, before);
        }

        //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
        //= type=test
        //# The destination host MUST (if possible) add the current timestamp to
        //# a Timestamp option before passing the option to the transport layer
        //# or to ICMP for processing.

        //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
        //= type=test
        //# The Timestamp is a right-justified, 32-bit timestamp in milliseconds
        //# since midnight UT. If the time is not available in milliseconds or
        //# cannot be provided with respect to midnight UT then any time may be
        //# inserted as a timestamp provided the high order bit of the timestamp
        //# field is set to one to indicate the use of a non-standard value.
        //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
        //= type=test
        //# A timestamp value MUST follow the rules given in Section 3.2.2.8 for
        //# the ICMP Timestamp message.
        #[test]
        fn option_frames_record_once_before_real_tcp_handoff() {
            use ntcp::{Ipv4Timestamp, OutgoingIpv4Options, TimestampRequest};
            let source = Ipv4Addr::new(192, 0, 2, 1);
            let destination = Ipv4Addr::new(192, 0, 2, 2);
            let source_time = Ipv4Timestamp::nonstandard(123).wire_value();
            let destination_time = Ipv4Timestamp::nonstandard(456).wire_value();
            // The example's provider: one acquisition per sample, a
            // standard value only within this test's own healthy kernel
            // clock bracket, otherwise the elapsed time marked nonstandard.
            let clock = Instant::now();
            let mut utc = Utc::new(clock);
            let (utc_before, before) = (utc_read(), clock.elapsed().as_millis() as u32);
            let sample = ntcp::Ipv4TimestampProvider::ipv4_timestamp(&mut utc)
                .unwrap()
                .wire_value();
            let (after, utc_after) = (clock.elapsed().as_millis() as u32, utc_read());
            assert_eq!(utc.acquisitions, 1);
            if !standard_time(sample, utc_before, utc_after) {
                assert!((before..=after).contains(&(sample & 0x7fff_ffff)));
            }
            for request in [
                None,
                Some(TimestampRequest::Times(2)),
                Some(TimestampRequest::AddressTimes(2)),
                Some(TimestampRequest::Prespecified {
                    addresses: [source, destination, source, destination],
                    len: 2,
                }),
            ] {
                let enabled = request.is_some();
                let cfg = EndpointConfig {
                    ipv4_options_enabled: enabled,
                    ..Default::default()
                };
                let mut client =
                    Endpoint::new(cfg.clone(), [1; 32], 0, test_policy(source)).unwrap();
                let mut server =
                    Endpoint::new(cfg.clone(), [2; 32], 0, test_policy(destination)).unwrap();
                let mut client_host = TunHost::attach(&mut client, &cfg, source.into()).unwrap();
                let mut server_host =
                    TunHost::attach(&mut server, &cfg, destination.into()).unwrap();
                let local = SocketAddr::new(source.into(), 1234);
                let remote = SocketAddr::new(destination.into(), 8080);
                let listener = server.listen(remote, 1).unwrap();
                let outgoing = OutgoingIpv4Options {
                    source_route: enabled.then(|| ntcp::SourceRoute::new(&[], false).unwrap()),
                    record_route_slots: enabled.then_some(2),
                    timestamp: request,
                    ..Default::default()
                };
                // The direct path registers the origin and the destination.
                let visits = [source, destination];
                let expected = ntcp::ExpectedRegistrations {
                    record_route: Some(2),
                    timestamp: request.map(|request| match request {
                        TimestampRequest::Prespecified { .. } => {
                            ntcp::ExpectedTimestamps::Prespecified(&visits)
                        }
                        _ => ntcp::ExpectedTimestamps::Count(2),
                    }),
                };
                let registration = enabled.then(|| {
                    ntcp::Ipv4RegistrationPlan::new(local.ip(), remote.ip(), outgoing, &expected)
                        .unwrap()
                });
                let id = client
                    .connect_with_path_provider(
                        0,
                        local,
                        remote,
                        ntcp::ManagedOpenOptions {
                            transport: ntcp::ActiveOpenOptions::from(&cfg.connection),
                            dscp: cfg.dscp,
                            ipv4_options: outgoing,
                            registration,
                            receive_authority: None,
                        },
                        &mut client_host.host,
                    )
                    .unwrap();
                let transfer = |from_host: &mut TunHost,
                                from: &mut Endpoint,
                                to_host: &mut TunHost,
                                to: &mut Endpoint,
                                local: Ipv4Addr,
                                opaque: bool| {
                    let mut bytes = [0; MTU];
                    let (poll, attempt) = from
                        .poll_reserved_transmit(0, &mut bytes[20..], BUDGET)
                        .unwrap();
                    let tx = poll.packet.unwrap();
                    let attempt = attempt.unwrap();
                    let mut len = build_ipv4_options(&mut bytes, tx, source_time).unwrap();
                    let context = from_host.host.egress_context(from, attempt).unwrap();
                    let ticket = from_host.host.submission_ticket(from, context).unwrap();
                    let submitted = from_host
                        .host
                        .submit(from, 0, ticket, context, &bytes[..len], 0, |_| {
                            BackendOutcome::Submitted
                        })
                        .unwrap();
                    assert!(submitted == Submission::Submitted);
                    assert!(from.transmit_attempt_packet(attempt).is_none());
                    if opaque {
                        let raw: &[u8] = if enabled {
                            &[30, 2, 158, 2]
                        } else {
                            // Disabled interpretation still retains RR and TS.
                            &[30, 2, 158, 2, 7, 3, 4, 1, 68, 4, 5, 0]
                        };
                        bytes.copy_within(20..len, 20 + raw.len());
                        bytes[20..20 + raw.len()].copy_from_slice(raw);
                        bytes[0] += (raw.len() / 4) as u8;
                        len += raw.len();
                        bytes[2..4].copy_from_slice(&(len as u16).to_be_bytes());
                        reseal(&mut bytes);
                    } else {
                        assert_eq!(bytes[0], 0x45, "received options are not echoed");
                    }
                    let parsed = ntcp_ip::parse(&bytes[..len], false).unwrap();
                    assert!(ntcp::wire::parse(parsed.ip, parsed.payload).is_ok());
                    // Disabled interpretation delivers every option unrecorded.
                    let expected = if enabled {
                        parsed.ipv4_options.record(local, destination_time).unwrap()
                    } else {
                        parsed.ipv4_options
                    };
                    input_frame(
                        to_host,
                        to,
                        0,
                        &bytes[..len],
                        local.into(),
                        enabled,
                        &mut Sample(destination_time),
                    )
                    .unwrap();
                    expected
                };
                transfer(
                    &mut client_host,
                    &mut client,
                    &mut server_host,
                    &mut server,
                    destination,
                    true,
                );
                transfer(
                    &mut server_host,
                    &mut server,
                    &mut client_host,
                    &mut client,
                    source,
                    false,
                );
                let expected = transfer(
                    &mut client_host,
                    &mut client,
                    &mut server_host,
                    &mut server,
                    destination,
                    true,
                );
                let accepted = server.accept(listener).unwrap();
                assert_eq!(client.state(id).unwrap(), State::Established);
                assert_eq!(server.state(accepted).unwrap(), State::Established);
                let received = server.received_ipv4_options(accepted).unwrap().unwrap();
                assert_eq!(received, expected);
                assert_eq!(received.unrecognized().as_bytes(), &[30, 2, 158, 2]);
                if let Some(request) = request {
                    let bytes = received.as_bytes();
                    assert_eq!(&bytes[4..7], &[7, 11, 12]);
                    assert_eq!(&bytes[7..15], &[192, 0, 2, 1, 192, 0, 2, 2]);
                    let ts = &bytes[15..];
                    let stride = if matches!(request, TimestampRequest::Times(_)) {
                        4
                    } else {
                        8
                    };
                    assert_eq!(ts.len(), 4 + 2 * stride);
                    assert_eq!(usize::from(ts[2]), ts.len() + 1);
                    assert_eq!(ts[3] >> 4, 0, "no duplicate destination recording/overflow");
                    assert_eq!(&ts[stride..stride + 4], &source_time.to_be_bytes());
                    assert_eq!(
                        &ts[2 * stride..2 * stride + 4],
                        &destination_time.to_be_bytes()
                    );
                    if stride == 8 {
                        assert_eq!(&ts[4..8], &source.octets());
                        assert_eq!(&ts[12..16], &destination.octets());
                    }
                }
                client.write(id, b"destination before TCP").unwrap();
                let expected = transfer(
                    &mut client_host,
                    &mut client,
                    &mut server_host,
                    &mut server,
                    destination,
                    true,
                );
                assert_eq!(
                    server.received_ipv4_options(accepted).unwrap(),
                    Some(expected)
                );
                let mut payload = [0; 32];
                let n = server.read(accepted, &mut payload).unwrap();
                assert_eq!(&payload[..n], b"destination before TCP");
            }
        }

        fn packet() -> ([u8; MTU], usize, Ipv4Addr) {
            let local = Ipv4Addr::new(10, 0, 0, 2);
            let mut bytes = [0; MTU];
            bytes[20..40].fill(0x5a);
            let len = build_ipv4(
                &mut bytes,
                IpMetadata {
                    source: Ipv4Addr::new(10, 0, 0, 1).into(),
                    destination: local.into(),
                },
                20,
                64,
                0,
                0,
            )
            .unwrap();
            (bytes, len, local)
        }

        fn reseal(bytes: &mut [u8]) {
            bytes[10..12].fill(0);
            let len = usize::from(bytes[0] & 15) * 4;
            let sum = checksum(&bytes[..len]);
            bytes[10..12].copy_from_slice(&sum.to_be_bytes());
        }

        #[test]
        fn source_routing_and_malformed_ip_options_are_rejected() {
            for option in [[131, 4, 0, 0], [137, 4, 0, 0], [7, 0, 0, 0], [7, 5, 0, 0]] {
                let (mut bytes, len, local) = packet();
                bytes.copy_within(20..len, 24);
                bytes[0] = 0x46;
                bytes[2..4].copy_from_slice(&((len + 4) as u16).to_be_bytes());
                bytes[20..24].copy_from_slice(&option);
                reseal(&mut bytes);
                assert!(parse_ipv4(&bytes[..len + 4], local).is_none());
            }
        }

        #[test]
        fn interface_subnet_rejects_routed_local_mismatch_and_keeps_edge_prefixes() {
            let interface = Ipv4Addr::new(192, 0, 2, 2);
            let local = Ipv4Addr::new(198, 51, 100, 2);
            assert!(checked_interface_subnet(local, interface, 0xffff_ff00).is_err());
            assert_eq!(
                checked_interface_subnet(Ipv4Addr::new(192, 0, 2, 10), interface, 0xffff_ff00)
                    .unwrap(),
                (interface, 24)
            );
            assert_eq!(
                checked_interface_subnet(local, interface, 0).unwrap(),
                (interface, 0)
            );
            for tail in [2, 3] {
                assert_eq!(
                    checked_interface_subnet(
                        Ipv4Addr::new(192, 0, 2, tail),
                        interface,
                        0xffff_fffe
                    )
                    .unwrap(),
                    (interface, 31)
                );
            }
            assert!(
                checked_interface_subnet(Ipv4Addr::new(192, 0, 2, 1), interface, 0xffff_fffe)
                    .is_err()
            );
            assert_eq!(
                checked_interface_subnet(interface, interface, u32::MAX).unwrap(),
                (interface, 32)
            );
            assert!(
                checked_interface_subnet(Ipv4Addr::new(192, 0, 2, 3), interface, u32::MAX).is_err()
            );
        }

        #[test]
        fn ipv6_interface_prefix_requires_distinct_unscoped_global_address() {
            let interface: Ipv6Addr = "2001:db8::2".parse().unwrap();
            let local: Ipv6Addr = "2001:db8::3".parse().unwrap();
            for prefix in 0..=127 {
                let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                assert!(checked_interface_ipv6(local, interface, mask, 0).is_ok());
                assert!(checked_interface_ipv6(interface, interface, mask, 0).is_err());
                if prefix != 0 {
                    let outside = Ipv6Addr::from(u128::from(local) ^ (1 << (128 - prefix)));
                    assert!(checked_interface_ipv6(outside, interface, mask, 0).is_err());
                }
            }
            assert!(checked_interface_ipv6(local, interface, u128::MAX, 0).is_err());
            let mask = u128::MAX << 64;
            assert!(checked_interface_ipv6(local, interface, mask, 1).is_err());
            for ip in [
                "2001:db8:1::3",
                "::",
                "::1",
                "ff02::1",
                "fe80::3",
                "fec0::3",
                "fc00::3",
                "::ffff:192.0.2.3",
            ] {
                assert!(checked_interface_ipv6(ip.parse().unwrap(), interface, mask, 0).is_err());
            }
            for ip in ["fe80::2", "fec0::2", "fc00::2", "::1", "ff02::2"] {
                assert!(checked_interface_ipv6(local, ip.parse().unwrap(), 0, 0).is_err());
            }
            for mask in [1, u128::MAX - 2, (u128::MAX << 64) | 1] {
                assert!(checked_interface_ipv6(local, interface, mask, 0).is_err());
            }
        }

        #[test]
        fn interface_netmask_requires_contiguous_prefix() {
            for prefix in 0..=32 {
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                assert_eq!(prefix_length(mask).unwrap(), prefix as u8);
            }
            for mask in [0xff00ff00, 0xffffff01, 1, 0x7fffffff] {
                assert!(prefix_length(mask).is_err());
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
        //= type=test
        //# RFC 1122 allows that if a retransmitted packet is identical to the
        //# original packet (which implies not only that the data boundaries have
        //# not changed, but also that none of the headers have changed), then
        //# the same IPv4 Identification field MAY be used (see Section 3.2.1.5
        //# of RFC 1122) (MAY-4).
        #[test]
        fn identical_atomic_datagrams_reuse_identification() {
            let (mut bytes, len, local) = packet();
            let original = bytes;
            let ip = IpMetadata {
                source: Ipv4Addr::new(10, 0, 0, 1).into(),
                destination: local.into(),
            };
            assert_eq!(build_ipv4(&mut bytes, ip, 20, 64, 0, 0).unwrap(), len);
            assert_eq!(&bytes[..len], &original[..len]);
            assert_eq!(&bytes[4..8], &[0, 0, 0x40, 0]);
        }

        // These assertions apply to this example, not arbitrary embedding applications.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.5
        //= type=test
        //# As a result of implementation differences and middlebox interactions,
        //# new applications SHOULD NOT employ the TCP urgent mechanism (SHLD-13).
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.2
        //= type=test
        //# New applications SHOULD NOT set the URGENT flag [39] due to
        //# implementation differences and middlebox issues (SHLD-13).
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
        //= type=test
        //# Generally, an application SHOULD NOT change the Diffserv field value
        //# during the course of a connection (SHLD-23).
        #[test]
        fn echo_flow_keeps_diffserv_stable_and_never_sends_urgent() {
            fn transfer(from: &mut Endpoint, to: &mut Endpoint, echo: bool) -> usize {
                let mut bytes = [0; MTU];
                let mut data = 0;
                for _ in 0..32 {
                    let output = from.poll_transmit(0, &mut bytes, 16).unwrap();
                    if let Some(packet) = output.packet {
                        let segment = ntcp::wire::parse(packet.ip, &bytes[..packet.len]).unwrap();
                        if echo {
                            assert_eq!(packet.dscp, 37);
                            assert_eq!(segment.header.flags & ntcp::wire::URG, 0);
                            data += segment.payload.len();
                        }
                        to.input_with_traffic_class(
                            0,
                            packet.ip,
                            (packet.dscp << 2) | packet.ecn,
                            &bytes[..packet.len],
                        )
                        .unwrap();
                    }
                    if !output.more_work {
                        return data;
                    }
                }
                panic!("bounded echo transfer did not quiesce");
            }
            let mut cfg = EndpointConfig::default();
            cfg.connection.nagle = false;
            let mut client = Endpoint::new(
                cfg.clone(),
                [1; 32],
                0,
                test_policy(Ipv4Addr::new(10, 0, 0, 1)),
            )
            .unwrap();
            cfg.dscp = 37;
            let mut server =
                Endpoint::new(cfg, [2; 32], 0, test_policy(Ipv4Addr::new(10, 0, 0, 2))).unwrap();
            let local = "10.0.0.1:1234".parse().unwrap();
            let remote = "10.0.0.2:8080".parse().unwrap();
            let listener = server.listen(remote, 1).unwrap();
            let id = client.connect(0, local, remote).unwrap();
            for _ in 0..3 {
                transfer(&mut client, &mut server, false);
                transfer(&mut server, &mut client, true);
            }
            let mut flow = Flow::new(server.accept(listener).unwrap());
            for input in [b"first".as_slice(), b"second".as_slice()] {
                client.write_urgent(id, input).unwrap();
                transfer(&mut client, &mut server, false);
                assert!(flow.drive(&mut server).unwrap());
                assert_eq!(transfer(&mut server, &mut client, true), input.len());
                let mut echoed = [0; 16];
                let count = client.read(id, &mut echoed).unwrap();
                assert_eq!(&echoed[..count], input);
            }
        }

        #[test]
        fn checksum_known_header() {
            let header = [
                0x45, 0, 0, 0x73, 0, 0, 0x40, 0, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0, 1, 0xc0,
                0xa8, 0, 0xc7,
            ];
            assert_eq!(checksum(&header), 0);
        }

        #[test]
        fn ipv4_roundtrip_and_options() {
            let (mut bytes, len, local) = packet();
            assert_eq!(bytes[0], 0x45);
            assert_eq!(&bytes[6..10], &[0x40, 0, 64, 6]);
            assert_eq!(checksum(&bytes[..20]), 0);
            let (ip, tcp) = parse_ipv4(&bytes, local).unwrap();
            assert_eq!(ip.destination, IpAddr::V4(local));
            assert_eq!(tcp, &[0x5a; 20]); // Ignores bytes beyond IP total length.
            bytes.copy_within(20..len, 24);
            bytes[20..24].fill(1); // Four IPv4 NOP options.
            bytes[0] = 0x46;
            bytes[2..4].copy_from_slice(&((len + 4) as u16).to_be_bytes());
            reseal(&mut bytes);
            assert_eq!(parse_ipv4(&bytes[..len + 4], local).unwrap().1, &[0x5a; 20]);
        }

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
        //= type=test
        //# When received options are passed up to TCP from the IP layer, a TCP
        //# implementation MUST ignore options that it does not understand (MUST-
        //# 50).
        #[test]
        fn unknown_ipv4_options_preserve_tcp_payload() {
            for option in [[158, 4, 0xa5, 0x5a], [30, 2, 1, 0]] {
                let (mut bytes, len, local) = packet();
                bytes.copy_within(20..len, 24);
                bytes[0] = 0x46;
                bytes[2..4].copy_from_slice(&((len + 4) as u16).to_be_bytes());
                bytes[20..24].copy_from_slice(&option);
                reseal(&mut bytes);
                let (ip, tcp) = parse_ipv4(&bytes[..len + 4], local).unwrap();
                assert_eq!(ip.destination, IpAddr::V4(local));
                assert_eq!(tcp, &[0x5a; 20]);
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
        //= type=test
        //# TCP implementations
        //# SHOULD pass the current Differentiated Services field value without
        //# change to the IP layer, when it sends segments on the connection
        //# (SHLD-22).
        #[test]
        fn outgoing_dscp_and_ttl_are_preserved() {
            let (mut bytes, _, local) = packet();
            let ip = IpMetadata {
                source: local.into(),
                destination: local.into(),
            };
            for dscp in 0..64 {
                for ttl in [1, 64, 255] {
                    build_ipv4(&mut bytes, ip, 20, ttl, dscp, 0).unwrap();
                    assert_eq!(bytes[1], dscp << 2);
                    assert_eq!(bytes[8], ttl);
                    assert_eq!(checksum(&bytes[..20]), 0);
                    assert_eq!(&bytes[20..40], &[0x5a; 20]);
                }
            }
        }

        #[test]
        //= https://www.rfc-editor.org/rfc/rfc3168#section-5
        //= type=test
        //= reason=IPv4 ECN/DSCP/checksum/DF matrix complements the IPv6 direct-TCP base-header matrix and two-Endpoint framed ECN feedback test.
        //# Bits 6 and 7 in the IPv4 TOS octet are designated as the ECN field. The IPv4 TOS octet corresponds to the Traffic Class octet in IPv6, and the ECN field is defined identically in both cases.
        // Actor/condition: IP adapter; IPv4 and IPv6 traffic class encoding.
        //= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
        //= type=test
        //= reason=IPv4 example sets DF for all packets; ECN/DSCP matrix explicitly asserts DF and no fragment offset, including both ECT codepoints.
        //# ECN-capable packets MAY have the DF (Don't Fragment) bit set.
        //= https://www.rfc-editor.org/rfc/rfc1191#section-2
        //= type=test
        //= reason=The atomic IPv4 codec sets DF on every packet it encodes and ntcp_ip::Fragmenter sets DF on every fragment, which every Host-originated fragment keeps outside owner-disabled routes; the codec's ECN/DSCP matrix asserts 0x4000 with no fragment offset. Keeping DF is the selected behavior wherever the host performs Path MTU Discovery, not optional clear-DF termination. On an IPv4 route or path whose owner disabled discovery (RFC 1191 section 6.6, the user's recorded decision B, 1191-093) the host performs none, and its TCP, Host::udp_send_datagram and Echo reply packets, source fragments included, leave DF clear with leased Identifications. User disposition (recorded): a native connection whose application sets IP_MTU_DISCOVER=IP_PMTUDISC_DONT does not perform Path MTU Discovery with its ordinary output, which it sends as IPv4 TCP packets without DF, each carrying an Identification leased from the Host allocator for its (source, destination, TCP) tuple; its PLPMTUD probes keep DF.
        //# and sends all datagrams on that path with the DF bit set.

        //= https://www.rfc-editor.org/rfc/rfc1191#section-2
        //= type=test
        //= reason=Enabled IPv4 PMTUD retains DF in the codec and reacts to validated lower-MTU feedback; zero-MTU and family-floor tests exercise decrease and bounded repair. This is not a claim about arbitrary external embeddings.
        //# Normally, the host continues to set DF in all datagrams, so that if the
        //# route changes and the new PMTU is lower, it will be discovered.

        fn ipv4_dscp_and_ecn_are_independent() {
            let (mut bytes, _, local) = packet();
            let ip = IpMetadata {
                source: local.into(),
                destination: local.into(),
            };
            for dscp in 0..64 {
                for ecn in 0..4 {
                    build_ipv4(&mut bytes, ip, 20, 64, dscp, ecn).unwrap();
                    assert_eq!(bytes[1], (dscp << 2) | ecn);
                    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0x4000); // DF, no fragments.
                    assert_eq!(checksum(&bytes[..20]), 0);
                    assert!(parse_ipv4(&bytes, local).is_some());
                }
            }
        }

        #[test]
        fn rejects_bad_lengths_checksum_and_fragments() {
            let (bytes, len, local) = packet();
            for truncated in 0..len {
                assert!(parse_ipv4(&bytes[..truncated], local).is_none());
            }
            for (offset, value) in [(0, 0x65), (0, 0x44), (0, 0x4f), (2, 1), (3, 19), (9, 17)] {
                let mut bad = bytes;
                bad[offset] = value;
                assert!(parse_ipv4(&bad[..len], local).is_none());
            }
            let mut bad = bytes;
            bad[8] ^= 1;
            assert!(parse_ipv4(&bad[..len], local).is_none());
            for flags in [0x2000u16, 1, 0x8000, 0x4001] {
                let mut bad = bytes;
                bad[6..8].copy_from_slice(&flags.to_be_bytes());
                reseal(&mut bad);
                assert!(parse_ipv4(&bad[..len], local).is_none());
            }
        }

        #[test]
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
        //= type=test
        //#   A TCP implementation MUST silently discard an incoming SYN segment
        //# |  that is addressed to a broadcast or multicast address [(MUST-57)].

        // Traceability limitation: Assertions cover multicast and limited broadcast
        // destinations only; no subnet-directed broadcast case.
        fn rejects_wrong_destination_and_nonunicast() {
            let (bytes, len, local) = packet();
            assert!(parse_ipv4(&bytes[..len], Ipv4Addr::new(10, 0, 0, 3)).is_none());
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
            //= type=test
            //# |  An incoming SYN with an invalid source address MUST be ignored
            //# |  either by TCP or by the IP layer [(MUST-63)] (see
            //# |  Section 3.2.1.3).

            // Traceability limitation: Assertions cover listed invalid IPv4 sources,
            // not prefix-directed broadcasts.
            for address in [
                [0, 0, 0, 0],
                [224, 0, 0, 1],
                [255, 255, 255, 255],
                [240, 0, 0, 1],
            ] {
                for offset in [12, 16] {
                    let mut bad = bytes;
                    bad[offset..offset + 4].copy_from_slice(&address);
                    reseal(&mut bad);
                    let destination = if offset == 16 {
                        Ipv4Addr::from(address)
                    } else {
                        local
                    };
                    assert!(parse_ipv4(&bad[..len], destination).is_none());
                }
            }
        }

        #[test]
        fn output_mtu_and_capacity() {
            let (mut bytes, _, local) = packet();
            let ip = IpMetadata {
                source: local.into(),
                destination: local.into(),
            };
            assert_eq!(build_ipv4(&mut bytes, ip, 1480, 64, 0, 0).unwrap(), MTU);
            assert_eq!(checksum(&bytes[..20]), 0);
            assert!(build_ipv4(&mut bytes, ip, 1481, 64, 0, 0).is_err());
            assert!(build_ipv4(&mut bytes, ip, usize::MAX, 64, 0, 0).is_err());
            assert!(build_ipv4(&mut bytes[..19], ip, 0, 64, 0, 0).is_err());
            assert!(open_tun("").is_err());
            assert!(open_tun(&"x".repeat(libc::IFNAMSIZ)).is_err());
            assert!(open_tun("bad\0name").is_err());
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "tun_echo requires Linux /dev/net/tun (IFF_TUN | IFF_NO_PI)",
    ))
}
