//! # ntcp
//!
//! A standards-first, event-driven TCP stack in Rust.
//!
//! The intended design separates TCP protocol state from packet I/O, clocks,
//! and scheduling so callers can embed it in their own runtime.

#![no_std]

extern crate alloc;

mod buffer;
mod connection;
mod endpoint;
#[cfg(test)]
mod endpoint_tests;
mod ipv4_options;
mod recovery;
mod schedule;
mod seq;
pub mod wire;

pub use connection::{
    CloseReason, ConnectionConfig, ConnectionEvents, Error, Instant, KeepaliveConfig, NetworkError,
    State, Tuple,
};
pub use endpoint::{
    ConnectionId, Endpoint, EndpointConfig, EndpointError, Event, InputDisposition, ListenerId,
    PollTransmit, Transmit,
};
pub use ipv4_options::{
    Ipv4Options, Ipv4OptionsError, OutgoingIpv4Options, SourceRoute, TimestampRequest,
};
pub use recovery::RecoveryAlgorithm;
pub use wire::{IpMetadata, WireError};
