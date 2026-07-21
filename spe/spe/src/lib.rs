// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![cfg_attr(
    all(target_arch = "arm", target_os = "none", feature = "veneers"),
    feature(cmse_nonsecure_entry)
)]
#![cfg_attr(target_arch = "arm", feature(abi_cmse_nonsecure_call))]
#![no_std]

#[cfg(target_arch = "arm")]
pub mod faults;
pub mod hil;
pub mod internal_trusted_storage;
pub mod libs;

pub mod service;
pub mod spm;
pub mod spm_api;
pub mod startup;
pub mod svc_handler;
#[cfg(all(target_arch = "arm", target_os = "none", feature = "veneers"))]
pub mod veneers;

pub use psa_interface::status::{StatusCode, into_psa_status};
