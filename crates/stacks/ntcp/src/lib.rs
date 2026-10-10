//! # ntcp
//!
//! A standards-first, event-driven TCP stack in Rust.
//!
//! The intended design separates TCP protocol state from packet I/O, clocks,
//! and scheduling so callers can embed it in their own runtime.

#![no_std]

extern crate alloc;

#[cfg(test)]
mod allocation_tests;
mod buffer;
mod connection;
mod cubic;
mod endpoint;
mod output_reservation;
pub use output_reservation::{
    GsoLimits, TransmitAttempt, TransmitGroup, TransmitGroupLimits, TransmitGroupView,
    TransmitSegmentation,
};
#[cfg(test)]
mod endpoint_tests;
mod hystart;
mod ipv4_options;
mod pacing;
mod pmtud;
pub use pmtud::PathMtuInfo;
mod pmtud_config;
pub use pmtud_config::{Ipv4Plateaus, PmtudConfig, PmtudPolicy, SearchAging};
mod rack;
mod recovery;
mod rx_timestamp;
mod sack;
mod schedule;
mod seq;
mod tx_timestamp;
pub mod wire;

pub use connection::{
    CallerTimebase, CloseReason, ConnectionConfig, ConnectionEvents, Error, Instant,
    KeepaliveConfig, NetworkError, PacingConfig, State, TimestampGranularity, TransportInfo, Tuple,
};
pub use endpoint::{
    AddressValidation, ConnectionId, Endpoint, EndpointConfig, EndpointError, Event,
    InputDisposition, ListenerId, PollTransmit, Transmit,
};
pub use ipv4_options::{
    Ipv4Options, Ipv4OptionsError, OutgoingIpv4Options, SourceRoute, TimestampRequest,
};
pub use recovery::{CongestionAlgorithm, InitialWindow, PrrAlgorithm, RecoveryAlgorithm};
pub use wire::{IpMetadata, WireError};

pub use tx_timestamp::{
    TxStreamRange, TxTimestampClock, TxTimestampEvent, TxTimestampOutcome, TxTimestampRequest,
    TxTimestampSource, TxTimestampStage, TxTimestampToken,
};

pub use rx_timestamp::{
    RxPacketTimestamps, RxReadTimestamps, RxTimestamp, RxTimestampStatus, SendProgress,
    TimestampClock, TimestampSource,
};
