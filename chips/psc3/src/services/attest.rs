use core::cmp;
use spe_services::attest::attest_service::{self, CERTIFICATION_REF_MAX_SIZE};
use tock_psc3::cryptolite;

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

pub type InitialAttestation = attest_service::AttestService<Psc3AttestPlatform>;
