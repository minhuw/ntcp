//! # ntcp
//!
//! A standards-first, event-driven TCP stack in Rust.
//!
//! **Early development:** this release is a library scaffold. It does not
//! implement TCP, expose a networking API, or claim RFC conformance.
//!
//! The intended design separates TCP protocol state from packet I/O, clocks,
//! and scheduling so callers can embed it in their own runtime.

#![no_std]
