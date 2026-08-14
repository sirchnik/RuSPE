// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]

#[cfg(target_arch = "arm")]
pub mod faults;
pub mod libs;

pub mod service;
pub mod spm;
pub mod spm_api;
pub mod startup;
pub mod svc_handler;
#[cfg(all(target_arch = "arm", target_os = "none", feature = "veneers"))]
pub mod veneers;

pub use psa_interface::status::{StatusCode, into_psa_status};
