//! This crate provides Rust bindings to [uplink-c](https://github.com/storj/uplink-c/), the C interface for the storj uplink API library.
//!
//! [TODO]() is the safe wrapper crate for this library.

// Ignore style warnings for for uplink-c bindings
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Include uplink-c bindings (generated by build.rs)
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
