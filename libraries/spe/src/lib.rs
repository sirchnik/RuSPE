// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

#![no_std]
#![feature(abi_cmse_nonsecure_call, cmse_nonsecure_entry)]

pub mod attest;
pub mod cose;
pub mod hil;
pub mod internal_trusted_storage;
pub mod psa;
pub mod serial;
pub mod service;
pub mod spm;
pub mod static_init;
#[cfg(all(target_arch = "arm", target_os = "none"))]
pub mod veneers;

pub use psa_interface::{StatusCode, into_psa_status};
