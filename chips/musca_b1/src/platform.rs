// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use psa_interface;
use spe::{
    psa::psa_call::{CallerAttributes, PsaMsg},
    service::Service,
    spm::{CustomMpuRegion, SpmPlatform},
};

use crate::services;
use ruspe_cortexm::cmse;

pub struct MuscaB1SecPlatform {
    pub initial_attestation: services::InitialAttestation,
    pub crypto: services::Crypto,
}

impl SpmPlatform for MuscaB1SecPlatform {
    fn call(&self, msg: PsaMsg) -> Result<(), spe::StatusCode> {
        match msg.handle {
            psa_interface::types::ServiceHandle::AttestationService => {
                self.initial_attestation.call(msg)
            }
            psa_interface::types::ServiceHandle::Crypto => self.crypto.call(msg),
            _ => Err(spe::StatusCode::NotSupported),
        }
    }

    fn has_permission_on_memory(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: CallerAttributes,
    ) -> bool {
        if len == 0 {
            return true;
        }

        if base.is_null() {
            return false;
        }

        let access_type = match (caller.ns, caller.privileged) {
            (true, false) => cmse::AccessType::NonSecureUnprivileged,
            (true, true) => cmse::AccessType::NonSecure,
            (false, false) => cmse::AccessType::Unprivileged,
            (false, true) => cmse::AccessType::Current,
        };

        if let Some(target) = cmse::TestTarget::check_range(base as *mut u32, len, access_type) {
            if caller.ns {
                if is_write {
                    target.ns_read_and_writable()
                } else {
                    target.ns_readable()
                }
            } else {
                if is_write {
                    target.read_and_writable()
                } else {
                    target.readable()
                }
            }
        } else {
            false
        }
    }

    fn custom_mpu_regions(
        &self,
        _handle: psa_interface::types::ServiceHandle,
    ) -> &[CustomMpuRegion] {
        &[]
    }
}
