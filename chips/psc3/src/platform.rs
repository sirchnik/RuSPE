// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cortex_m::cmse;
use psa_interface;
use spe::service::Service;
use spe::spm::spm_fn::SfnPlatform;
use spe::spm_api::{CallerAttributes, PsaMsg};

use crate::services;

pub struct Psc3SecPlatform<
    C: psa_interface::PsaApiCallInterface + Sync,
    A: spe::spm_api::SpmApi + Sync,
> {
    pub api: A,
    pub initial_attestation: services::InitialAttestation<C>,
    pub crypto: services::Crypto,
}

impl<C: psa_interface::PsaApiCallInterface + Sync, A: spe::spm_api::SpmApi + Sync> SfnPlatform
    for Psc3SecPlatform<C, A>
{
    fn call(&self, msg: PsaMsg) -> Result<(), spe::StatusCode> {
        match msg.handle {
            psa_interface::types::ServiceHandle::AttestationService => {
                self.initial_attestation.call(msg, &self.api)
            }
            psa_interface::types::ServiceHandle::Crypto => self.crypto.call(msg, &self.api),
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
        // - NS + unprivileged -> TTAT (NonSecureUnprivileged): checks NS MPU as
        //   unprivileged
        // - NS + privileged   -> TTA  (NonSecure): checks NS MPU as privileged
        // - S  + unprivileged -> TTT  (Unprivileged): checks current-security MPU as
        //   unprivileged
        // - S  + privileged   -> TT   (Current): checks current-security MPU as
        //   privileged
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

    fn version(&self, handle: psa_interface::types::ServiceHandle) -> Option<u32> {
        match handle {
            psa_interface::types::ServiceHandle::AttestationService => {
                Some(services::InitialAttestation::<C>::VERSION)
            }
            psa_interface::types::ServiceHandle::Crypto => Some(services::Crypto::VERSION),
            _ => None,
        }
    }
}
