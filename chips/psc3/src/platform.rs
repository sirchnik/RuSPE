// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use psa_interface;
use spe::{
    psa::psa_call::{CallerAttributes, PsaMsg},
    service::Service,
    spm::{CustomMpuRegion, Permissions, SpmPlatform},
};

use ruspe_cortexm::cmse;

use crate::services;

pub struct Psc3SecPlatform {
    pub initial_attestation: services::InitialAttestation,
    pub crypto: services::Crypto,
}

impl SpmPlatform for Psc3SecPlatform {
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

        // Determine the TT instruction variant based on caller attributes:
        // - NS + unprivileged → TTAT (NonSecureUnprivileged): checks NS MPU as unprivileged
        // - NS + privileged   → TTA  (NonSecure): checks NS MPU as privileged
        // - S  + unprivileged → TTT  (Unprivileged): checks current-security MPU as unprivileged
        // - S  + privileged   → TT   (Current): checks current-security MPU as privileged
        let access_type = match (caller.ns, caller.privileged) {
            (true, false) => cmse::AccessType::NonSecureUnprivileged,
            (true, true) => cmse::AccessType::NonSecure,
            (false, false) => cmse::AccessType::Unprivileged,
            (false, true) => cmse::AccessType::Current,
        };

        if let Some(target) = cmse::TestTarget::check_range(base as *mut u32, len, access_type) {
            if caller.ns {
                // Non-Secure caller: check NS permission bits
                if is_write {
                    target.ns_read_and_writable()
                } else {
                    target.ns_readable()
                }
            } else {
                // Secure caller (inter-partition): check current-state permission bits
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
        handle: psa_interface::types::ServiceHandle,
    ) -> &[CustomMpuRegion] {
        if (handle as isize) == (psa_interface::types::ServiceHandle::AttestationService as isize) {
            static REGIONS: [CustomMpuRegion; 2] = [
                CustomMpuRegion {
                    base: 0x4223_0000 as *const u8,
                    size: 0x200,
                    permissions: Permissions::ReadWriteOnly,
                },
                CustomMpuRegion {
                    base: 0x4261_0180 as *const u8,
                    size: 0x20,
                    permissions: Permissions::ReadOnly,
                },
            ];
            &REGIONS
        } else {
            &[]
        }
    }
}
