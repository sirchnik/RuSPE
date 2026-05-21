// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

#![cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    feature(cmse_nonsecure_entry)
)]
#![no_std]

pub mod hil;
pub mod internal_trusted_storage;
mod libs;
pub mod psa;
pub mod service;
pub mod spm;
#[cfg(all(target_arch = "arm", target_os = "none"))]
pub mod veneers;

pub use psa_interface::status::{StatusCode, into_psa_status};
