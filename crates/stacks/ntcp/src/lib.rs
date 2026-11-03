//! # ntcp
//!
//! A standards-first, event-driven TCP stack in Rust.
//!
//! The intended design separates TCP protocol state from packet I/O, clocks,
//! and scheduling so callers can embed it in their own runtime.

#![no_std]

extern crate alloc;

pub use ntcp_buffer::Payload;

#[cfg(test)]
mod allocation_tests;
mod buffer;
mod connection;
mod cubic;
mod endpoint;
mod fast_open;
#[cfg(feature = "tfo-linux-cookie")]
pub use fast_open::LinuxSipHash24Key;
pub use fast_open::{
    FastOpenClientPolicy, FastOpenCookieLifetime, FastOpenCookiePolicy, FastOpenEarlyDataPolicy,
    FastOpenKeyLease, FastOpenServerKey,
};
#[cfg(test)]
mod fast_open_policy_tests;
#[cfg(test)]
mod fast_open_tests;
mod managed_path;
pub use managed_path::{DiscoveryIntent, FactoryRole, ManagedError, ManagedOpenOptions, ManagedPathInfo, PathFactoryRequest, PathProvider, PreparedPath, TransportCeilings};
mod output_reservation;
pub use output_reservation::{GsoLimits, TransmitAttempt, TransmitSegmentation};
#[cfg(test)]
mod endpoint_tests;
mod hystart;
mod ipv4_options;
mod pacing;
mod pmtud;
pub use pmtud::{
    AdministrativeClip, AdministrativeDeferral, AdministrativeSearch, PathMtuInfo, PmtuFeedback,
    PmtuReport,
};
mod pmtud_config;
pub use pmtud_config::{Ipv4Plateaus, PmtudConfig, PmtudPolicy, SearchAging};
mod route_policy;
pub use route_policy::RoutePolicy;
mod rack;
mod receive_metadata;
#[cfg(test)]
mod receive_metadata_tests;
mod recovery;
mod rx_timestamp;
pub use receive_metadata::RxPacketMetadata;
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
    ActiveOpenOptions, AddressValidation, ConfirmedProbe, ConnectionId, CorrelatedPmtu,
    CorrelatedSegment, Endpoint, EndpointConfig, EndpointError, Event, InputDisposition,
    ListenerId, PendingPmtuApplied, PhysicalReceipt, PollTransmit, Transmit,
};
pub use ipv4_options::{
    EncodedIpv4Options, Ipv4Options, Ipv4OptionsError, Ipv4Timestamp, Ipv4TimestampProvider, OutgoingIpv4Options,
    SourceRoute, TimestampRequest, copied_fragment_options,
};
pub use recovery::{CongestionAlgorithm, InitialWindow, RecoveryAlgorithm};
pub use wire::{IpMetadata, WireError};

pub use tx_timestamp::{
    TxStreamRange, TxTimestampClock, TxTimestampEvent, TxTimestampOutcome, TxTimestampRequest,
    TxTimestampSource, TxTimestampStage, TxTimestampToken,
};

pub use rx_timestamp::{
    RxPacketTimestamps, RxReadTimestamps, RxTimestamp, RxTimestampStatus, SendProgress,
    TimestampClock,
};

#[cfg(test)]
mod destination_route_tests;
