// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cortex_m::cmse;
use psa_interface::PsaApiCallInterface;
use psa_interface::types::ServiceHandle;
use spe::service::Service;
use spe::spm::spm_fn::SfnPlatform;
use spe::spm_api::{CallerAttributes, PsaMsg, SpmApi};

use crate::services;

pub struct Psc3SecPlatform<C: PsaApiCallInterface + Sync, A: SpmApi + Sync> {
    pub api: A,
    pub initial_attestation: services::InitialAttestation<C>,
    pub crypto: services::Crypto,
}

impl<C: PsaApiCallInterface + Sync, A: SpmApi + Sync> SfnPlatform for Psc3SecPlatform<C, A> {
    fn call(&self, msg: PsaMsg) -> Result<(), spe::StatusCode> {
        #[expect(
            clippy::match_wildcard_for_single_variants,
            reason = "not all services implemented"
        )]
        match msg.handle {
            ServiceHandle::AttestationService => self.initial_attestation.call(msg, &self.api),
            ServiceHandle::Crypto => self.crypto.call(msg, &self.api),
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

        cmse::TestTarget::check_range(base as *mut u32, len, access_type).is_some_and(|target| {
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
        })
    }

    fn version(&self, handle: ServiceHandle) -> Option<u32> {
        #[expect(
            clippy::match_wildcard_for_single_variants,
            reason = "not all services implemented"
        )]
        match handle {
            ServiceHandle::AttestationService => Some(services::InitialAttestation::<C>::VERSION),
            ServiceHandle::Crypto => Some(services::Crypto::VERSION),
            _ => None,
        }
    }
}
