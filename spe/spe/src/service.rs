// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::spm_api::{PsaMsg, SpmApi};

pub struct Info {
    pub version: u32,
}

pub trait Service<A: SpmApi> {
    fn info(&self) -> Info;
    fn call(&self, msg: PsaMsg, api: &A) -> Result<(), psa_interface::status::StatusCode>;
    fn init(&mut self, api: &A) -> Result<(), psa_interface::status::StatusCode>;
    fn deinit(&mut self, api: &A) -> Result<(), psa_interface::status::StatusCode>;
}
