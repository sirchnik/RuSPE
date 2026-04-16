#[repr(C)]
pub enum PsaHandle {
    Crypto,
    SecureStorage,
    Attestation,
}
// TODO enums
pub type PsaStatus = i32;

#[repr(C)]
pub struct PsaInVec {
    pub base: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct PsaOutVec {
    pub base: *mut u8,
    pub len: usize,
}
