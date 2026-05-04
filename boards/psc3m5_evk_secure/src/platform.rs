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
    fn security_lifecycle(&self, buf: &mut [u8]) -> Result<(), StatusCode> {
        todo!()
    }

    fn verfication_service(&self, buf: &mut [u8]) -> Result<(), StatusCode> {
        todo!()
    }

    fn profile_definition(&self, buf: &mut [u8]) -> Result<(), StatusCode> {
        todo!()
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
        todo!()
    }

    fn cert_ref(&self, buf: &mut [u8; CERTIFICATION_REF_MAX_SIZE]) -> Result<(), StatusCode> {
        todo!()
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
