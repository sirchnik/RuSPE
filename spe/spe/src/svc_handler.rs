// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

//! SVC handler.
//!
//! The SVC handler (`svc_handler`) and its dispatch function are now generated
//! by the [`define_spm_api!`] macro, which has direct access to the SPM
//! implementation. This eliminates the need for `extern "Rust"` link-time
//! symbol binding between the `spe` library crate and downstream board crates.
//!
//! Board crates should reference `global_spm_api::svc_handler` (or the module
//! where `define_spm_api!` is invoked) instead of
//! `spe::svc_handler::svc_handler`.
