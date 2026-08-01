// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#![no_std]

#[cfg(all(not(test), not(miri)))]
pub mod ffi_alloc;

pub mod attest;
pub mod crypto;
