#![no_std]

extern crate alloc;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub max_flows: usize,
    pub max_packets: usize,
    pub max_retained_bytes: usize,
    pub quantum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    Allocation,
    FlowLimit,
    PacketLimit,
    RetainedLimit,
    InvalidMetadata,
    InvalidClock,
    StaleKey,
    StalePacket,
    StaleToken,
    Busy,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowKey {
    namespace: u64,
    identity: u64,
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketId {
    flow: FlowKey,
    slot: usize,
    ordinal: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TryToken {
    packet: PacketId,
    attempt: u64,
}

impl FlowKey {
    pub fn identity(self) -> u64 {
        self.identity
    }
}

impl PacketId {
    pub fn flow(self) -> FlowKey {
        self.flow
    }
}

impl TryToken {
    pub fn packet_id(self) -> PacketId {
        self.packet
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub wire_bytes: u64,
    pub retained_bytes: usize,
    pub not_before: u64,
}

#[derive(Debug)]
pub struct AdmissionError<P> {
    pub error: Error,
    pub payload: P,
}

#[derive(Debug)]
pub struct Attempt<'a, P> {
    pub token: TryToken,
    pub payload: &'a P,
    pub metadata: Metadata,
}

#[derive(Debug)]
pub enum Poll<'a, P> {
    Ready(Attempt<'a, P>),
    Idle,
    BudgetExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Accepted,
    Dropped,
    Retry { not_before: u64 },
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Accepted,
    Dropped,
    Cancelled,
    Quarantined,
}

#[derive(Debug)]
pub struct Returned<P> {
    pub payload: P,
    pub metadata: Metadata,
    pub disposition: Disposition,
}

#[derive(Debug)]
pub enum Resolution<P> {
    Retried,
    Returned(Returned<P>),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub flows: usize,
    pub packets: usize,
    pub retained_bytes: usize,
}

#[derive(Default)]
struct Flow {
    key: Option<FlowKey>,
    head: Option<usize>,
    tail: Option<usize>,
    deficit: u128,
    in_turn: bool,
}

struct Packet<P> {
    id: PacketId,
    payload: P,
    metadata: Metadata,
    lease: Option<TryToken>,
    paid: bool,
}

struct Slot<P> {
    packet: Option<Packet<P>>,
    next: Option<usize>,
}

pub struct Scheduler<P> {
    namespace: u64,
    config: Config,
    flows: Vec<Flow>,
    packets: Vec<Slot<P>>,
    free: Option<usize>,
    usage: Usage,
    generation: u64,
    ordinal: u64,
    attempt: u64,
    now: u64,
    cursor: usize,
}

impl<P> Scheduler<P> {
    // Caller supplies a distinct namespace for every scheduler lifetime whose handles can mix.
    pub fn new(namespace: u64, config: Config) -> Result<Self, Error> {
        if config.max_flows == 0 || config.max_packets == 0 || config.quantum == 0 {
            return Err(Error::InvalidConfig);
        }
        let mut flows = Vec::new();
        let mut packets = Vec::new();
        flows
            .try_reserve_exact(config.max_flows)
            .map_err(|_| Error::Allocation)?;
        packets
            .try_reserve_exact(config.max_packets)
            .map_err(|_| Error::Allocation)?;
        flows.resize_with(config.max_flows, Flow::default);
        for slot in 0..config.max_packets {
            packets.push(Slot {
                packet: None,
                next: (slot + 1 < config.max_packets).then_some(slot + 1),
            });
        }
        Ok(Self {
            namespace,
            config,
            flows,
            packets,
            free: Some(0),
            usage: Usage::default(),
            generation: 0,
            ordinal: 0,
            attempt: 0,
            now: 0,
            cursor: 0,
        })
    }

    pub fn usage(&self) -> Usage {
        self.usage
    }

    pub fn open_flow(&mut self, identity: u64) -> Result<FlowKey, Error> {
        let slot = self
            .flows
            .iter()
            .position(|flow| flow.key.is_none())
            .ok_or(Error::FlowLimit)?;
        let generation = self.generation.checked_add(1).ok_or(Error::Exhausted)?;
        let key = FlowKey {
            namespace: self.namespace,
            identity,
            slot,
            generation,
        };
        self.generation = generation;
        self.flows[slot].key = Some(key);
        self.usage.flows += 1;
        Ok(key)
    }

    pub fn disable_flow(&mut self, key: FlowKey) -> Result<(), Error> {
        let flow = self.flow(key)?;
        if flow.head.is_some() {
            return Err(Error::Busy);
        }
        self.flows[key.slot] = Flow::default();
        self.usage.flows -= 1;
        Ok(())
    }

    fn flow(&self, key: FlowKey) -> Result<&Flow, Error> {
        self.flows
            .get(key.slot)
            .filter(|flow| flow.key == Some(key))
            .ok_or(Error::StaleKey)
    }

    fn packet(&self, id: PacketId) -> Result<&Packet<P>, Error> {
        self.flow(id.flow)?;
        self.packets
            .get(id.slot)
            .and_then(|slot| slot.packet.as_ref())
            .filter(|packet| packet.id == id)
            .ok_or(Error::StalePacket)
    }

    pub fn enqueue(
        &mut self,
        key: FlowKey,
        metadata: Metadata,
        payload: P,
    ) -> Result<PacketId, AdmissionError<P>> {
        let result = (|| {
            self.flow(key)?;
            if metadata.wire_bytes == 0 || metadata.not_before == u64::MAX {
                return Err(Error::InvalidMetadata);
            }
            let slot = self.free.ok_or(Error::PacketLimit)?;
            let retained = self
                .usage
                .retained_bytes
                .checked_add(metadata.retained_bytes)
                .filter(|bytes| *bytes <= self.config.max_retained_bytes)
                .ok_or(Error::RetainedLimit)?;
            let ordinal = self.ordinal.checked_add(1).ok_or(Error::Exhausted)?;
            Ok((slot, retained, ordinal))
        })();
        let (slot, retained, ordinal) = match result {
            Ok(values) => values,
            Err(error) => return Err(AdmissionError { error, payload }),
        };
        let id = PacketId {
            flow: key,
            slot,
            ordinal,
        };
        self.ordinal = ordinal;
        self.free = self.packets[slot].next;
        self.packets[slot] = Slot {
            packet: Some(Packet {
                id,
                payload,
                metadata,
                lease: None,
                paid: false,
            }),
            next: None,
        };
        let flow = &mut self.flows[key.slot];
        if let Some(tail) = flow.tail {
            self.packets[tail].next = Some(slot);
        } else {
            flow.head = Some(slot);
        }
        flow.tail = Some(slot);
        self.usage.packets += 1;
        self.usage.retained_bytes = retained;
        Ok(id)
    }

    fn advance(&mut self) {
        self.cursor = if self.cursor + 1 == self.flows.len() {
            0
        } else {
            self.cursor + 1
        };
    }

    pub fn poll_ready(&mut self, now: u64, budget: &mut usize) -> Result<Poll<'_, P>, Error> {
        if now == u64::MAX || now < self.now {
            return Err(Error::InvalidClock);
        }
        self.now = now;
        let mut inactive = 0;
        // ponytail: bounded slot scan; use an active ring if sparse flow tables become costly.
        while *budget > 0 {
            *budget -= 1;
            let flow = &mut self.flows[self.cursor];
            let ready = flow.head.filter(|head| {
                let packet = self.packets[*head].packet.as_ref().unwrap();
                packet.lease.is_none() && packet.metadata.not_before <= now
            });
            let Some(head) = ready else {
                self.advance();
                inactive += 1;
                if inactive == self.flows.len() {
                    return Ok(Poll::Idle);
                }
                continue;
            };
            inactive = 0;
            let packet = self.packets[head].packet.as_mut().unwrap();
            if !packet.paid {
                if !flow.in_turn {
                    // Deficit before a new turn is less than a u64 packet charge.
                    flow.deficit += u128::from(self.config.quantum);
                    flow.in_turn = true;
                }
                if flow.deficit < u128::from(packet.metadata.wire_bytes) {
                    flow.in_turn = false;
                    self.advance();
                    continue;
                }
            }
            let attempt = self.attempt.checked_add(1).ok_or(Error::Exhausted)?;
            self.attempt = attempt;
            if !packet.paid {
                flow.deficit -= u128::from(packet.metadata.wire_bytes);
                packet.paid = true;
            }
            let token = TryToken {
                packet: packet.id,
                attempt,
            };
            packet.lease = Some(token);
            // An unresolved lease skips its flow without awarding another quantum.
            return Ok(Poll::Ready(self.view(token)?));
        }
        Ok(Poll::BudgetExhausted)
    }

    pub fn view(&self, token: TryToken) -> Result<Attempt<'_, P>, Error> {
        let packet = self.packet(token.packet).map_err(|_| Error::StaleToken)?;
        if packet.lease != Some(token) {
            return Err(Error::StaleToken);
        }
        Ok(Attempt {
            token,
            payload: &packet.payload,
            metadata: packet.metadata,
        })
    }

    pub fn next_wakeup(&self) -> Option<u64> {
        self.flows
            .iter()
            .filter_map(|flow| {
                let packet = self.packets[flow.head?].packet.as_ref()?;
                (packet.lease.is_none() && packet.metadata.not_before > self.now)
                    .then_some(packet.metadata.not_before)
            })
            .min()
    }

    pub fn resolve(&mut self, token: TryToken, outcome: Outcome) -> Result<Resolution<P>, Error> {
        self.view(token)?;
        if let Outcome::Retry { not_before } = outcome {
            if not_before == u64::MAX {
                return Err(Error::InvalidMetadata);
            }
            let packet = self.packets[token.packet.slot].packet.as_mut().unwrap();
            packet.lease = None;
            packet.metadata.not_before = not_before;
            if self.cursor == token.packet.flow.slot {
                self.advance();
            }
            return Ok(Resolution::Retried);
        }
        let disposition = match outcome {
            Outcome::Accepted => Disposition::Accepted,
            Outcome::Dropped => Disposition::Dropped,
            Outcome::Unknown => Disposition::Quarantined,
            Outcome::Retry { .. } => unreachable!(),
        };
        Ok(Resolution::Returned(self.remove(
            token.packet,
            None,
            disposition,
        )))
    }

    pub fn cancel(&mut self, id: PacketId) -> Result<Returned<P>, Error> {
        if self.packet(id)?.lease.is_some() {
            return Err(Error::Busy);
        }
        let mut previous = None;
        let mut current = self.flows[id.flow.slot].head;
        // ponytail: arbitrary cancellation scans one bounded FIFO; add back-links if needed.
        while current != Some(id.slot) {
            previous = current;
            current = self.packets[current.unwrap()].next;
        }
        Ok(self.remove(id, previous, Disposition::Cancelled))
    }

    fn remove(
        &mut self,
        id: PacketId,
        previous: Option<usize>,
        disposition: Disposition,
    ) -> Returned<P> {
        let next = self.packets[id.slot].next;
        let flow = &mut self.flows[id.flow.slot];
        if let Some(previous) = previous {
            self.packets[previous].next = next;
        } else {
            flow.head = next;
        }
        if flow.tail == Some(id.slot) {
            flow.tail = previous;
        }
        if flow.head.is_none() {
            flow.deficit = 0;
            flow.in_turn = false;
        }
        let packet = self.packets[id.slot].packet.take().unwrap();
        self.packets[id.slot].next = self.free;
        self.free = Some(id.slot);
        self.usage.packets -= 1;
        self.usage.retained_bytes -= packet.metadata.retained_bytes;
        Returned {
            payload: packet.payload,
            metadata: packet.metadata,
            disposition,
        }
    }
}

#[cfg(test)]
mod tests;
