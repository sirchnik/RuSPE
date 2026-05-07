// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

#![no_std]

pub mod status;
pub mod types;

mod interface_trait;
pub mod psa_api;

pub use crate::interface_trait::PsaApiCallInterface;
