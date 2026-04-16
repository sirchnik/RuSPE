// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

#![no_std]
#![feature(abi_cmse_nonsecure_call, cmse_nonsecure_entry)]

pub mod attest;
pub mod serial;
mod service;
pub mod static_init;
pub mod veneers;
