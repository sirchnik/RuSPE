#![no_std]

// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

pub mod platform;
pub mod services;
pub mod uart;

pub use platform::MuscaB1SecPlatform;
