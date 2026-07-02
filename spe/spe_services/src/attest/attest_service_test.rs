use super::*;
use psa_interface::status::StatusCode;
use psa_interface::types;

struct MockPlatform;
impl AttestPlatform for MockPlatform {
    fn security_lifecycle(&self) -> Result<u32, StatusCode> {
        Ok(12288)
    }
    fn verification_service(&self, buf: &mut [u8]) -> Result<usize, StatusCode> {
        let s = b"https://psa-verifier.org";
        buf[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }
    fn profile_definition(&self, buf: &mut [u8]) -> Result<usize, StatusCode> {
        let s = b"tag:psacertified.org,2023:psa#tfm";
        buf[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }
    fn boot_seed(&self, seed: &mut [u8; 32]) -> Result<(), StatusCode> {
        seed.fill(0x22);
        Ok(())
    }
    fn implementation_id(&self, buf: &mut [u8; 32]) -> Result<(), StatusCode> {
        let s = b"acme-implementation-id-00000001\x00";
        buf.copy_from_slice(s);
        Ok(())
    }
    fn instance_id(&self, buf: &mut [u8; 33]) -> Result<(), StatusCode> {
        buf.fill(0x33);
        Ok(())
    }
    fn cert_ref(&self, buf: &mut [u8; CERTIFICATION_REF_MAX_SIZE]) -> Result<usize, StatusCode> {
        let s = b"1234567890123-12345";
        buf[..s.len()].copy_from_slice(s);
        Ok(s.len())
    }
}

struct MockPsaClient;
impl psa_interface::PsaApiCallInterface for MockPsaClient {
    fn psa_framework_version() -> u32 {
        1
    }
    fn psa_version(_service_id: u32) -> u32 {
        1
    }
    fn psa_call(
        _handle: types::ServiceHandle,
        _ctrl_param: types::CtrlParam,
        _in_vec: &[types::FFInVec],
        out_vec: &mut [types::FFOutVec],
    ) -> types::PsaStatus {
        if !out_vec.is_empty() {
            out_vec[0].len = 64;
        }
        0
    }
}

#[test]
fn test_initial_attest_get_token() {
    let service = AttestService::<MockPlatform, MockPsaClient>::new(MockPlatform);
    let challenge = [0x11; 32];
    let mut token = [0u8; PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];

    let size = service
        .initial_attest_get_token(&challenge, &[], &mut token)
        .expect("Failed to get token");

    assert!(size > 0);
    assert!(size <= PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE);
}

#[test]
fn test_initial_attest_get_token_size() {
    let service = AttestService::<MockPlatform, MockPsaClient>::new(MockPlatform);
    let challenge = [0x11; 32];

    let predicted_size = service
        .initial_attest_get_token_size(challenge.len(), &[])
        .expect("Failed to get token size");

    let mut token = [0u8; PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];
    let actual_size = service
        .initial_attest_get_token(&challenge, &[], &mut token)
        .expect("Failed to get token");

    assert_eq!(predicted_size, actual_size);
}

#[test]
fn test_challenge_size_unsupported() {
    let service = AttestService::<MockPlatform, MockPsaClient>::new(MockPlatform);
    let challenge = [0x11; 16]; // Unsupported size
    let mut token = [0u8; PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];

    let result = service.initial_attest_get_token(&challenge, &[], &mut token);
    assert_eq!(result, Err(StatusCode::InvalidArgument));

    let size_result = service.initial_attest_get_token_size(challenge.len(), &[]);
    assert_eq!(size_result, Err(StatusCode::InvalidArgument));
}
