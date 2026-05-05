use core::cmp;
use psa_interface;
use psc3::cryptolite;
use spe::{
    attest::attest_service::{self, CERTIFICATION_REF_MAX_SIZE},
    crypto::crypto_service,
    psa::psa_call::PsaMsg,
    service::Service,
    spm::spm::SpmPlatform,
    StatusCode,
};
pub struct Psc3AttestPlatform;

impl attest_service::AttestPlatform for Psc3AttestPlatform {
    fn security_lifecycle(&self) -> Result<u32, StatusCode> {
        Ok(12288)
    }

    fn verification_service(&self, buf: &mut [u8]) -> Result<usize, StatusCode> {
        let s = b"https://psa-verifier.org";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        Ok(len)
    }

    fn profile_definition(&self, buf: &mut [u8]) -> Result<usize, StatusCode> {
        let s = b"tag:psacertified.org,2023:psa#tfm";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        Ok(len)
    }

    fn boot_seed(&self, seed: &mut [u8; 32]) -> Result<(), StatusCode> {
        let cryptolite = cryptolite::Cryptolite::new();
        if cryptolite
            .trng_init(&cryptolite::TrngConfig::default())
            .and_then(|()| cryptolite.trng_enable())
            .is_err()
        {
            return Err(StatusCode::GenericError);
        }
        cryptolite
            .trng_try_fill_bytes(seed)
            .map_err(|_| StatusCode::GenericError)
    }
    // TODO get key from `raw_data_pc012`

    fn implementation_id(&self, buf: &mut [u8; 32]) -> Result<(), StatusCode> {
        let s = b"acme-implementation-id-000000001";
        let len = cmp::min(buf.len(), s.len());
        buf[..len].copy_from_slice(&s[..len]);
        if len < buf.len() {
            buf[len..].fill(0);
        }
        Ok(())
    }

    fn cert_ref(&self, buf: &mut [u8; CERTIFICATION_REF_MAX_SIZE]) -> Result<usize, StatusCode> {
        // No certification reference provided; return empty string.
        Ok(0)
    }
}

pub struct Psc3SecPlatform {
    pub initial_attestation: attest_service::AttestService<Psc3AttestPlatform>,
    pub crypto: crypto_service::CryptoService,
}

impl SpmPlatform for Psc3SecPlatform {
    fn call(&self, msg: PsaMsg) -> Result<(), StatusCode> {
        return match msg.handle {
            psa_interface::types::ServiceHandle::AttestationService => {
                self.initial_attestation.call(msg)
            }
            psa_interface::types::ServiceHandle::Crypto => self.crypto.call(msg),
            _ => Err(StatusCode::NotSupported),
        };
    }
}
