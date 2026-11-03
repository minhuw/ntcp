//! Owner-authorized local path administration (RFC 1191 section 6.6, RFC
//! 8201 section 5.6): the binary protocol, the control server an embedding
//! serves from its Host owner loop, and the client the `ntcp-pathctl`
//! utility uses. See `server` for exposure, authority and bounds.

pub mod cli;
pub mod client;
pub mod protocol;
pub mod server;

pub use server::{ControlConfig, Server};
