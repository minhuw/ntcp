// Test infrastructure only: real Endpoint input and committed production encoder.
extern crate std;

use super::*;
use crate::fast_open::{CredentialRegistry, ServerCookieContext};
use crate::{FastOpenKeyLease, FastOpenServerKey, LinuxSipHash24Key};
use std::{cell::Cell, hint::black_box, println, time::Instant as Clock, vec};

const ROUNDS: usize = 9;
const BATCH: usize = 128;
const WARMUP: usize = 16;
const NOW: u64 = 2 * crate::fast_open::LIFETIME_US + 17;
const MODES: &[&str] = &[
    "ordinary",
    "request",
    "current",
    "previous-epoch",
    "overlap-current",
    "overlap-retiring",
    "invalid",
    "overlap-invalid",
    "expired",
    "revoked",
    "malformed-length",
];

#[derive(Clone, Copy, Default)]
struct Recording {
    enabled: bool,
    ns: [u64; 2],
    calls: [u64; 2],
}
std::thread_local! {
    static RECORDER: Cell<Recording> = const { Cell::new(Recording {
        enabled: false, ns: [0; 2], calls: [0; 2],
    }) };
}

// One outer scope per actual context operation. No nesting, allocation or output.
// Disabled builds have no hook; disabled test runs still pay the TLS flag read.
pub(crate) struct Scope(Option<(Clock, usize)>);
impl Scope {
    pub(crate) fn new(kind: usize) -> Self {
        Self(RECORDER.with(|r| r.get().enabled.then(|| (Clock::now(), kind))))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if let Some((start, kind)) = self.0 {
            let ns = start.elapsed().as_nanos() as u64;
            RECORDER.with(|r| {
                let mut value = r.get();
                value.ns[kind] += ns;
                value.calls[kind] += 1;
                r.set(value);
            });
        }
    }
}
fn recording(enabled: bool) {
    RECORDER.with(|r| {
        r.set(Recording {
            enabled,
            ..Recording::default()
        })
    });
}
fn recorded() -> Recording {
    RECORDER.with(Cell::get)
}

#[derive(Clone)]
struct Packet {
    ip: IpMetadata,
    bytes: [u8; 256],
    len: usize,
    header: Header,
}
fn packet(
    ip: IpMetadata,
    header: Header,
    cookie: Option<wire::FastOpenCookie>,
    data: &[u8],
) -> Packet {
    let mut options = vec![];
    if header.flags & SYN != 0 {
        options.extend_from_slice(&[2, 4, 5, 180, 4, 2, 3, 3, 0]);
    }
    // Offer timestamps; this fixture keeps local timestamps/SACK disabled, so
    // the actual SYN-ACK must decline both options.
    options.extend_from_slice(&[8, 10, 0, 0, 0, 1, 0, 0, 0, 0]);
    if let Some(cookie) = cookie {
        options.extend_from_slice(&[34, (2 + cookie.as_bytes().len()) as u8]);
        options.extend_from_slice(cookie.as_bytes());
    }
    let mut bytes = [0; 256];
    let len = wire::encode(ip, header, &options, data, &mut bytes).unwrap();
    Packet {
        ip,
        bytes,
        len,
        header,
    }
}
fn key(linux: bool, byte: u8) -> FastOpenServerKey {
    if linux {
        FastOpenServerKey::LinuxSipHash24(LinuxSipHash24Key::new([byte; 16]))
    } else {
        FastOpenServerKey::HmacSha256([byte; 32])
    }
}
fn raw_key(linux: bool, byte: u8) -> (FastOpenCookiePolicy, [u8; 32]) {
    (key(linux, byte).policy(), [byte; 32])
}
fn lease(expired: bool) -> FastOpenKeyLease {
    FastOpenKeyLease {
        not_before: 0,
        issue_until: if expired {
            NOW
        } else {
            10 * crate::fast_open::LIFETIME_US
        },
        accept_until: if expired {
            NOW
        } else {
            11 * crate::fast_open::LIFETIME_US
        },
        units_per_second: 1_000_000,
    }
}
struct Fixture {
    endpoint: Endpoint,
    listener: ListenerId,
    ip: IpMetadata,
    mode: &'static str,
    ordinal: u16,
    population: usize,
    expected: Option<wire::FastOpenCookie>,
    offered: Option<wire::FastOpenCookie>,
    accepts: bool,
}
impl Fixture {
    fn new(linux: bool, v6: bool, loaded: bool, pooled: bool, mode: &'static str) -> Self {
        let config = EndpointConfig {
            preallocate_connections: if pooled {
                if loaded { 41 } else { 1 }
            } else {
                0
            },
            connection: ConnectionConfig {
                mss: 1460,
                send_capacity: 8192,
                receive_capacity: 8192,
                nagle: false,
                timestamps: false,
                sack: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut endpoint = Endpoint::new(config, [42; 32], 0, |_| true).unwrap();
        endpoint.enable_fast_open().unwrap();
        let ip = IpMetadata {
            source: if v6 { "2001:db8::1" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            destination: if v6 { "2001:db8::2" } else { "192.0.2.2" }
                .parse()
                .unwrap(),
        };
        let mut listener = None;
        for i in 0..if loaded { 64 } else { 1 } {
            listener = Some(
                endpoint
                    .listen(SocketAddr::new(ip.destination, 8000 + i), 64)
                    .unwrap(),
            );
        }
        let listener = listener.unwrap();
        endpoint.set_listener_fast_open(listener, 32).unwrap();
        let overlap = mode.starts_with("overlap-");
        if overlap || mode == "revoked" {
            endpoint
                .install_fast_open_key(0, key(linux, 7), lease(false), false)
                .unwrap();
        }
        endpoint
            .install_fast_open_key(1, key(linux, 8), lease(mode == "expired"), overlap)
            .unwrap();
        let byte = if matches!(mode, "overlap-retiring" | "revoked") {
            7
        } else {
            8
        };
        let (policy, secret) = raw_key(linux, byte);
        let cookie = policy
            .issue(
                &secret,
                ip.destination,
                ip.source,
                if mode == "previous-epoch" { 1 } else { 2 },
            )
            .unwrap();
        let offered = match mode {
            "ordinary" => None,
            "request" => Some(wire::FastOpenCookie::request()),
            "invalid" | "overlap-invalid" => Some(wire::FastOpenCookie::new(&[99; 8]).unwrap()),
            "malformed-length" => Some(wire::FastOpenCookie::new(&[99; 4]).unwrap()),
            _ => Some(cookie),
        };
        let accepts = matches!(
            mode,
            "current" | "previous-epoch" | "overlap-current" | "overlap-retiring"
        );
        let expected = if mode == "ordinary" || mode == "expired" || linux && accepts {
            None
        } else {
            let (policy, secret) = raw_key(linux, 8);
            policy.issue(&secret, ip.destination, ip.source, 2)
        };
        let mut fixture = Self {
            endpoint,
            listener,
            ip,
            mode,
            ordinal: 0,
            population: if loaded { 40 } else { 0 },
            expected,
            offered,
            accepts,
        };
        if loaded {
            // Real ordinary children: 32 established and 8 SYN-RECEIVED. All
            // SYN-ACKs committed; no background output contaminates measurement.
            for i in 0..40 {
                let syn = fixture.syn(None, &[]);
                fixture
                    .endpoint
                    .input(NOW, syn.ip, &syn.bytes[..syn.len])
                    .unwrap();
                let mut bytes = [0; 256];
                let tx = fixture
                    .endpoint
                    .poll_transmit(NOW, &mut bytes, 2048)
                    .unwrap()
                    .packet
                    .unwrap();
                let reply = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
                if i < 32 {
                    fixture.complete(&syn, reply.header, &[]);
                    let child = fixture.endpoint.accept(listener).unwrap();
                    assert_eq!(fixture.endpoint.state(child), Ok(State::Established));
                }
            }
        }
        fixture.assert_population();
        fixture
    }
    fn syn(&mut self, cookie: Option<wire::FastOpenCookie>, data: &[u8]) -> Packet {
        self.ordinal += 1;
        packet(
            self.ip,
            Header {
                source_port: 10000 + self.ordinal,
                destination_port: 8000 + self.listener.slot as u16,
                sequence: 1000 + u32::from(self.ordinal) * 100,
                acknowledgment: 0,
                flags: SYN,
                window: 8192,
                urgent_pointer: 0,
            },
            cookie,
            data,
        )
    }
    fn assert_population(&self) {
        let slots: Vec<_> = self.endpoint.slots.iter().flatten().collect();
        assert_eq!(slots.len(), self.population);
        assert_eq!(
            slots
                .iter()
                .filter(|s| s.connection.state() == State::Established)
                .count(),
            if self.population == 0 { 0 } else { 32 }
        );
        assert_eq!(
            slots
                .iter()
                .filter(|s| !s.connection.handshake_complete())
                .count(),
            if self.population == 0 { 0 } else { 8 }
        );
        assert_eq!(
            self.endpoint.listeners[self.listener.slot]
                .as_ref()
                .unwrap()
                .reset_debt,
            0
        );
        assert_eq!(
            self.endpoint.receive_pool.len(),
            self.endpoint
                .config
                .preallocate_connections
                .saturating_sub(self.population)
        );
    }
    fn complete(&mut self, syn: &Packet, reply: Header, data: &[u8]) {
        let ack = packet(
            syn.ip,
            Header {
                sequence: reply.acknowledgment,
                acknowledgment: reply.sequence.wrapping_add(1),
                flags: ACK,
                ..syn.header
            },
            None,
            data,
        );
        self.endpoint
            .input(NOW, ack.ip, &ack.bytes[..ack.len])
            .unwrap();
    }
    fn sample(&mut self, enabled: bool) -> (u64, Recording) {
        self.assert_population();
        let payload = if self.mode == "ordinary" {
            &b""[..]
        } else {
            &b"hello"[..]
        };
        let syn = self.syn(self.offered, payload);
        let mut output = [0; 256];
        recording(enabled);
        let start = Clock::now();
        let disposition = black_box(self.endpoint.input(
            black_box(NOW),
            black_box(syn.ip),
            black_box(&syn.bytes[..syn.len]),
        ));
        let result = black_box(
            self.endpoint
                .poll_transmit(NOW, black_box(&mut output), 2048),
        );
        let ns = start.elapsed().as_nanos() as u64;
        let record = recorded();
        recording(false);
        assert_eq!(disposition, Ok(InputDisposition::Processed));
        let tx = result
            .unwrap()
            .packet
            .expect("new admitted connection must emit SYN-ACK");
        assert_eq!(tx.connection.unwrap().slot, self.population);
        let reply = wire::parse(tx.ip, black_box(&output[..tx.len])).unwrap();
        assert_eq!(reply.header.flags & (SYN | ACK | RST), SYN | ACK);
        assert_eq!(
            tx.ip,
            IpMetadata {
                source: syn.ip.destination,
                destination: syn.ip.source
            }
        );
        assert_eq!(reply.header.source_port, syn.header.destination_port);
        assert_eq!(reply.header.destination_port, syn.header.source_port);
        assert!(reply.payload.is_empty());
        assert_eq!(
            reply.header.acknowledgment,
            syn.header.sequence + 1 + if self.accepts { 5 } else { 0 }
        );
        assert_eq!(reply.options.fast_open, self.expected);
        assert_eq!(reply.options.timestamps, None);
        assert!(!reply.options.sack_permitted);
        assert_eq!(
            self.endpoint.slots.iter().flatten().count(),
            self.population + 1
        );
        if enabled {
            assert_eq!(
                record.calls,
                [
                    u64::from(self.offered.is_some()),
                    u64::from(self.expected.is_some() || self.mode == "expired")
                ]
            );
        } else {
            assert_eq!(record.calls, [0, 0]);
        }
        let reply_header = reply.header;
        // Finish the real handshake and receive the stream before a peer reset. This
        // prevents repeated early resets from training debt/quota rejection.
        self.complete(&syn, reply_header, if self.accepts { &[] } else { payload });
        let child = self.endpoint.accept(self.listener).unwrap();
        assert_eq!(self.endpoint.state(child), Ok(State::Established));
        let mut data = [0; 16];
        if !payload.is_empty() {
            assert_eq!(self.endpoint.read(child, &mut data).unwrap(), payload.len());
            assert_eq!(&data[..payload.len()], payload);
        }
        let reset = packet(
            syn.ip,
            Header {
                sequence: syn.header.sequence + 1 + payload.len() as u32,
                acknowledgment: reply_header.sequence + 1,
                flags: RST | ACK,
                ..syn.header
            },
            None,
            &[],
        );
        self.endpoint
            .input(NOW, reset.ip, &reset.bytes[..reset.len])
            .unwrap();
        assert_eq!(self.endpoint.state(child), Ok(State::Closed));
        for _ in 0..4 {
            let _ = self.endpoint.poll_transmit(NOW, &mut output, 2048).unwrap();
        }
        self.endpoint.release(child).unwrap();
        for _ in 0..4 {
            let _ = self.endpoint.poll_transmit(NOW, &mut output, 2048).unwrap();
        }
        self.assert_population();
        (ns, record)
    }
    fn context(&self) -> (&ServerCookieContext, &CredentialRegistry) {
        (
            &self.endpoint.fast_open_cookie_policy,
            &self.endpoint.fast_open_credentials,
        )
    }
}
fn quantiles(values: &[u64]) -> [u64; 5] {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    [
        sorted[0],
        sorted[sorted.len() / 2],
        sorted[(sorted.len() - 1) * 90 / 100],
        sorted[(sorted.len() - 1) * 95 / 100],
        sorted[sorted.len() - 1],
    ]
}

fn calibration() {
    for round in 0..ROUNDS {
        for offset in 0..5 {
            let kind = (round + offset) % 5;
            recording(kind == 3);
            let mut full_internal_ns = 0u64;
            let start = Clock::now();
            for _ in 0..16384 {
                match kind {
                    0 => {
                        black_box(());
                    }
                    1 => {
                        let a = Clock::now();
                        black_box(a.elapsed());
                    }
                    2 | 3 => {
                        let scope = Scope::new(0);
                        black_box(());
                        drop(scope);
                    }
                    4 => {
                        // Match sample()'s internally observed full interval.
                        // Accumulation and black_box of the elapsed result are
                        // outside that interval, as is sample's recorder read.
                        let start = Clock::now();
                        black_box(());
                        let ns = start.elapsed().as_nanos() as u64;
                        full_internal_ns += black_box(ns);
                    }
                    _ => unreachable!(),
                }
            }
            let ns = start.elapsed().as_nanos();
            let record = recorded();
            recording(false);
            println!(
                "MAC_COST_JSON {{\"type\":\"calibration\",\"round\":{round},\"kind\":{kind},\"iterations\":16384,\"ns\":{ns},\"scope_ns\":{},\"calls\":{},\"full_internal_ns\":{full_internal_ns}}}",
                record.ns[0], record.calls[0]
            );
        }
    }
}
fn codecs(f: &Fixture, linux: bool, v6: bool, mode: &str) {
    let (policy, secret) = raw_key(linux, 8);
    let cookie = f.offered.unwrap_or(wire::FastOpenCookie::request());
    let expected_raw = policy.valid(&secret, f.ip.destination, f.ip.source, 2, cookie);
    let (context, registry) = f.context();
    let expected_issue = if mode == "expired" {
        None
    } else {
        policy.issue(&secret, f.ip.destination, f.ip.source, 2)
    };
    for round in 0..ROUNDS {
        for offset in 0..4 {
            let kind = (round + offset) % 4;
            let start = Clock::now();
            for _ in 0..1024 {
                match kind {
                    0 => {
                        black_box(
                            policy
                                .issue(
                                    black_box(&secret),
                                    black_box(f.ip.destination),
                                    black_box(f.ip.source),
                                    black_box(2),
                                )
                                .unwrap(),
                        );
                    }
                    1 => {
                        assert_eq!(
                            black_box(policy.valid(
                                black_box(&secret),
                                black_box(f.ip.destination),
                                black_box(f.ip.source),
                                black_box(2),
                                black_box(cookie)
                            )),
                            expected_raw
                        );
                    }
                    2 => {
                        assert_eq!(
                            black_box(context.issue(
                                black_box(registry),
                                black_box(NOW),
                                black_box(f.ip.destination),
                                black_box(f.ip.source)
                            )),
                            expected_issue
                        );
                    }
                    3 => {
                        assert_eq!(
                            black_box(context.valid(
                                black_box(registry),
                                black_box(NOW),
                                black_box(f.ip.destination),
                                black_box(f.ip.source),
                                black_box(cookie)
                            )),
                            f.accepts
                        );
                    }
                    _ => unreachable!(),
                }
            }
            let ns = start.elapsed().as_nanos();
            println!(
                "MAC_COST_JSON {{\"type\":\"codec\",\"linux\":{linux},\"v6\":{v6},\"mode\":\"{mode}\",\"kind\":{kind},\"round\":{round},\"iterations\":1024,\"ns\":{ns}}}"
            );
        }
    }
}

#[test]
fn fixtures_and_scopes_follow_actual_admission() {
    for linux in [false, true] {
        for v6 in [false, true] {
            for &mode in MODES {
                if linux && mode == "previous-epoch" {
                    continue;
                }
                let mut f = Fixture::new(linux, v6, false, true, mode);
                f.sample(true);
                f.sample(false);
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.2
//= type=test
//= reason=Release measurements now exist in integration/rfc_host/check_mac_cost.py and the ignored release_mac_cost core test: both policies, IPv4/IPv6, small/64-listener tables, allocating/pooled receive storage, current/previous epochs, current/retiring keys, request/invalid/expired/revoked/length controls, actual admission/issuance multiplicities and encoded committed SYN-ACKs. Raw rounds, source/executable/toolchain provenance, clock/recorder controls and signed disabled/enabled perturbation are retained. Measured repeated HMAC key/address setup justified sharing the prefix within each two-epoch verification without persistent state; cookie bytes and both comparisons are preserved. On the measured Xeon 6230R, pooled small-listener overlap/refresh admission was approximately 6.14/7.99 microseconds for IPv4/IPv6 versus 12.35/13.12 microseconds outside the observed scopes; Linux admission was approximately 0.12-0.26 microseconds. HMAC overlap remains substantial, raw codec drift and paired observer variation limit precise speedup inference, and no arbitrary compliance percentage is asserted. Keep the complete fast-relative property TODO pending independent quantitative review/T23 disposition; any further per-credential preparation experiment must preserve resource accounting and use these same real-path boundaries.
//# 3. The generation and verification are fast relative to the rest of SYN and SYN-ACK processing.
#[test]
#[ignore = "release measurement; run integration/rfc_host/check_mac_cost.py"]
fn release_mac_cost() {
    assert!(!cfg!(debug_assertions), "release build required");
    println!(
        "MAC_COST_JSON {{\"type\":\"method\",\"schema\":2,\"rounds\":{ROUNDS},\"batch\":{BATCH},\"warmup\":{WARMUP},\"features\":\"all-features including tfo-linux-cookie\",\"debug_assertions\":false,\"timer\":\"std::time::Instant monotonic elapsed nanoseconds\",\"scope\":\"inclusive ServerCookieContext valid/issue with registry/error checks; actual algorithms once; no nested scopes\",\"full\":\"Endpoint::input through poll_transmit production encode and commit; excludes packet/fixture construction, verification, stream completion, teardown\",\"population\":\"small: 1 listener slot0, 0 children; loaded: 64 listeners target slot63, 32 established + 8 ordinary pending children, target next connection slot40\",\"capacities\":\"max_connections1024 max_listeners64 max_buffer_bytes268435456 backlog64 fast_open_limit32 send8192 receive8192 mss1460 timestamps/sack disabled (peer offers both; SYN-ACK decline asserted); pool0 or small1/loaded41; pending quota ownership0 existing ordinary pending8; measured tuples start at slot0 or40\",\"order\":\"rotate cases each round, alternate enabled/disabled order each round+case; same tuples in paired fixtures\",\"limitations\":\"scope timers perturb actual execution; raw codec and context series kind0=raw issue current key, kind1=raw current-key verify offered bytes, kind2=inclusive current issue, kind3=inclusive current+retiring verify. Caller ticks=7200000017us (epoch2), previous epoch1, finite leases not_before0 issue_until36000000000 accept_until39600000000; expired both deadlines7200000017. Keys7/8 fixed public fixtures, HMAC secret32 or raw Linux16; data5bytes except ordinary0. Calibration kind0=black_box loop,1=clock read-pair loop,2=disabled empty scope,3=enabled empty scope,4=matched empty full interval (full_internal_ns records internal elapsed; ns is whole loop throughput); disabled test hooks still read TLS; enabled scope excludes recorder write and opening read; raw same-path exclusions include observer work; separate paired difference is an estimate, never a per-packet observation; no outlier removal or hardware compliance threshold\"}}"
    );
    calibration();
    let mut fixtures = vec![];
    for linux in [false, true] {
        for v6 in [false, true] {
            for loaded in [false, true] {
                for pooled in [false, true] {
                    for &mode in MODES {
                        if linux && mode == "previous-epoch" {
                            continue;
                        }
                        fixtures.push((linux, v6, loaded, pooled, mode));
                    }
                }
            }
        }
    }
    for round in 0..ROUNDS {
        for step in 0..fixtures.len() {
            let index = (step + round * 19) % fixtures.len();
            let (linux, v6, loaded, pooled, mode) = fixtures[index];
            let mut a = Fixture::new(linux, v6, loaded, pooled, mode);
            let mut b = Fixture::new(linux, v6, loaded, pooled, mode);
            for _ in 0..WARMUP {
                a.sample(false);
                b.sample(true);
            }
            if round == 0 && !loaded && pooled && mode != "ordinary" {
                codecs(&a, linux, v6, mode);
            }
            for offset in 0..2 {
                let enabled = (round + index + offset) % 2 == 1;
                let f = if enabled { &mut b } else { &mut a };
                let mut full = [0; BATCH];
                let mut scopes = [0; BATCH];
                let mut calls = [0; 2];
                for i in 0..BATCH {
                    let (ns, r) = f.sample(enabled);
                    full[i] = ns;
                    scopes[i] = r.ns.iter().sum();
                    for k in 0..2 {
                        calls[k] += r.calls[k];
                    }
                    assert!(ns > scopes[i]);
                }
                let sum: u64 = full.iter().sum();
                let scope: u64 = scopes.iter().sum();
                let remaining: Vec<u64> = full.iter().zip(scopes).map(|(f, s)| f - s).collect();
                println!(
                    "MAC_COST_JSON {{\"type\":\"handshake\",\"linux\":{linux},\"v6\":{v6},\"loaded\":{loaded},\"pooled\":{pooled},\"mode\":\"{mode}\",\"round\":{round},\"enabled\":{enabled},\"iterations\":{BATCH},\"full_ns\":{sum},\"scope_ns\":{scope},\"outside_scope_ns\":{},\"valid_calls\":{},\"issue_calls\":{},\"full_quantiles_ns\":{:?},\"scope_quantiles_ns\":{:?},\"outside_quantiles_ns\":{:?}}}",
                    sum - scope,
                    calls[0],
                    calls[1],
                    quantiles(&full),
                    quantiles(&scopes),
                    quantiles(&remaining)
                );
            }
        }
    }
    println!(
        "MAC_COST_JSON {{\"type\":\"complete\",\"cases\":{},\"rounds\":{ROUNDS}}}",
        fixtures.len()
    );
}
