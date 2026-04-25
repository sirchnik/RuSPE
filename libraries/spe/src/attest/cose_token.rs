use crate::{
    cose::{CoseSign1, CoseSign1Error, RustCryptoBackend, Sign1Options, encode_payload_bstr},
    StatusCode,
};
use minicbor::{Encoder, encode::write::Cursor};

const EAT_NONCE_LABEL: i64 = 10;
const TOKEN_KEY_ID: &[u8] = b"11";

// Temporary development key used to exercise the token path.
const ATTESTATION_PRIVATE_KEY: [u8; 32] = [
    0x3d, 0x42, 0x9a, 0x83, 0xef, 0xe3, 0x87, 0x10, 0xab, 0x9a, 0xb4, 0xc0, 0x2c, 0xcb, 0xbe, 0x0b,
    0x87, 0xab, 0x69, 0x36, 0xdd, 0xf4, 0x14, 0x57, 0xea, 0x30, 0xf9, 0x6c, 0xa6, 0xf2, 0xcd, 0xee,
];

const MAX_PAYLOAD_SIZE: usize = 128;
const MAX_ENCODED_PAYLOAD_BSTR_SIZE: usize = MAX_PAYLOAD_SIZE + 9;

fn map_cose_error(err: CoseSign1Error) -> StatusCode {
    match err {
        CoseSign1Error::BufferTooSmall => StatusCode::BufferTooSmall,
        _ => StatusCode::InvalidArgument,
    }
}

fn encode_payload(challenge: &[u8], out: &mut [u8]) -> Result<usize, StatusCode> {
    // Minimal EAT payload with nonce claim bound to the caller-provided challenge.
    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(1)
        .map_err(|_| StatusCode::BufferTooSmall)?
        .i64(EAT_NONCE_LABEL)
        .map_err(|_| StatusCode::BufferTooSmall)?
        .bytes(challenge)
        .map_err(|_| StatusCode::BufferTooSmall)?;

    Ok(enc.writer().position())
}

pub fn encode_initial_attestation_token(
    challenge: &[u8],
    token: &mut [u8],
) -> Result<usize, StatusCode> {
    let mut payload = [0u8; MAX_PAYLOAD_SIZE];
    let payload_len = encode_payload(challenge, &mut payload)?;

    let mut payload_bstr = [0u8; MAX_ENCODED_PAYLOAD_BSTR_SIZE];
    let payload_bstr_len =
        encode_payload_bstr(&payload[..payload_len], &mut payload_bstr).map_err(map_cose_error)?;

    let signer = CoseSign1::new(
        RustCryptoBackend,
        &ATTESTATION_PRIVATE_KEY,
        Sign1Options::default(),
    )
    .with_key_id(TOKEN_KEY_ID);

    let encoded = signer
        .encode_from_payload_bstr(&payload_bstr[..payload_bstr_len], token)
        .map_err(map_cose_error)?;

    Ok(encoded.encoded_len)
}

pub fn compute_initial_attestation_token_size(challenge_size: usize) -> Result<usize, StatusCode> {
    let challenge = [0u8; 64];
    if challenge_size > challenge.len() {
        return Err(StatusCode::InvalidArgument);
    }

    let mut token = [0u8; crate::attest::attest_service::PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];
    encode_initial_attestation_token(&challenge[..challenge_size], &mut token)
}
