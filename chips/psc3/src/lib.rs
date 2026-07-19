#![no_std]

// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

pub mod platform;
pub mod ppc;
pub mod security;
pub mod services;

pub use platform::Psc3SecPlatform;
pub use security::configure_security;
