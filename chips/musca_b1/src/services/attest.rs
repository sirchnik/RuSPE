// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use core::cmp;
use spe_services::attest::attest_service::{self, CERTIFICATION_REF_MAX_SIZE};

pub struct MuscaB1AttestPlatform;

impl attest_service::AttestPlatform for MuscaB1AttestPlatform {
    fn security_lifecycle(&self) -> Result<u32, spe::StatusCode> {
        Ok(0x3000) // Secured
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
        seed.fill(0xAA);
        Ok(())
    }

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

pub type InitialAttestation = attest_service::AttestService<MuscaB1AttestPlatform>;
