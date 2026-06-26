// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![cfg_attr(
    all(target_arch = "arm", target_os = "none", feature = "veneers"),
    feature(cmse_nonsecure_entry)
)]
#![no_std]

#[cfg(target_arch = "arm")]
pub mod faults;
pub mod hil;
pub mod internal_trusted_storage;
mod libs;

pub mod psa;
pub mod service;
pub mod spm;
#[cfg(all(target_arch = "arm", target_os = "none", feature = "veneers"))]
pub mod veneers;

pub use psa_interface::status::{StatusCode, into_psa_status};
