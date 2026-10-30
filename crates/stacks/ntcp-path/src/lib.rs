#![no_std]

extern crate alloc;

mod plateaus;
mod service;

pub use plateaus::Ipv4Plateaus;
pub use service::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidArgument,
    Capacity,
    Allocation,
    Exhausted,
    ForeignContext,
    StaleHandle,
    Duplicate,
    NoRoute,
    SourceNotOwned,
    SelectionChanged,
    Invalidated,
}
