// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Infineon Technologies AG 2026.

use core::cmp;

use psa_interface;
use spe::{
    attest::attest_service::{self, CERTIFICATION_REF_MAX_SIZE},
    crypto::crypto_service,
    psa::psa_call::PsaMsg,
    service::Service,
    spm::spm::SpmPlatform,
};
use tock_psc3::cryptolite;

const NS_FLASH_START: usize = 0x2201_4000;
const NS_FLASH_END: usize = 0x2204_0000;
const NS_RAM_START: usize = 0x2400_4000;
const NS_RAM_END: usize = 0x2400_F000;
const SHARED_RAM_START: usize = 0x2400_F000;
const SHARED_RAM_END: usize = 0x2401_0000;

fn range_is_within(start: usize, end_exclusive: usize, base: *const u8, len: usize) -> bool {
    let Some(end) = (base as usize).checked_add(len) else {
        return false;
    };

    base as usize >= start && end <= end_exclusive
}

fn range_is_readable_by_nonsecure(base: *const u8, len: usize) -> bool {
    range_is_within(NS_FLASH_START, NS_FLASH_END, base, len)
        || range_is_within(NS_RAM_START, NS_RAM_END, base, len)
        || range_is_within(SHARED_RAM_START, SHARED_RAM_END, base, len)
}

fn range_is_writable_by_nonsecure(base: *const u8, len: usize) -> bool {
    range_is_within(NS_RAM_START, NS_RAM_END, base, len)
        || range_is_within(SHARED_RAM_START, SHARED_RAM_END, base, len)
}

pub struct Psc3AttestPlatform;

impl attest_service::AttestPlatform for Psc3AttestPlatform {
    fn security_lifecycle(&self) -> Result<u32, spe::StatusCode> {
        Ok(12288)
    }

    fn verification_service(&self, buf: &mut [u8]) -> Result<usize, spe::StatusCode> {
        let s = b"https://psa-verifier.org";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        Ok(len)
    }

    fn profile_definition(&self, buf: &mut [u8]) -> Result<usize, spe::StatusCode> {
        let s = b"tag:psacertified.org,2023:psa#tfm";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        Ok(len)
    }

    fn boot_seed(&self, seed: &mut [u8; 32]) -> Result<(), spe::StatusCode> {
        let cryptolite = cryptolite::Cryptolite::new();
        if cryptolite
            .trng_init(&cryptolite::TrngConfig::default())
            .and_then(|()| cryptolite.trng_enable())
            .is_err()
        {
            return Err(spe::StatusCode::GenericError);
        }
        cryptolite
            .trng_try_fill_bytes(seed)
            .map_err(|_| spe::StatusCode::GenericError)
    }
    // TODO get key from `raw_data_pc012`

    fn implementation_id(&self, buf: &mut [u8; 32]) -> Result<(), spe::StatusCode> {
        let s = b"acme-implementation-id-000000001";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        if len < buf.len() {
            buf[len..].fill(0);
        }
        Ok(())
    }

    fn instance_id(&self, buf: &mut [u8; 33]) -> Result<(), spe::StatusCode> {
        buf[0] = 0x01;
        buf[1..].fill(0x02);
        Ok(())
    }

    fn cert_ref(
        &self,
        buf: &mut [u8; CERTIFICATION_REF_MAX_SIZE],
    ) -> Result<usize, spe::StatusCode> {
        let s = b"0123456789012-12345";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        if len < buf.len() {
            buf[len..].fill(0);
        }
        Ok(len)
    }
}

pub struct Psc3SecPlatform {
    pub initial_attestation: attest_service::AttestService<Psc3AttestPlatform>,
    pub crypto: crypto_service::CryptoService,
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

    fn has_real_permission(&self, base: *const u8, len: usize, is_write: bool) -> bool {
        if len == 0 {
            return true;
        }

        if is_write {
            range_is_writable_by_nonsecure(base, len)
        } else {
            range_is_readable_by_nonsecure(base, len)
        }
    }
}
