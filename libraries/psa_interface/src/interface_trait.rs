use crate::types;

pub trait PsaApiCallInterface {
    fn psa_framework_version() -> u32;
    fn psa_version(service_id: u32) -> u32;
    fn psa_call(
        handle: types::PsaHandle,
        ctrl_param: types::VectorDescriptor,
        in_vec: &[types::PsaInVec],
        out_vec: &mut [types::PsaOutVec],
    ) -> types::PsaStatus;
}
