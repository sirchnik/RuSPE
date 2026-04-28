use psa_interface::{PsaApiCallInterface, types};

unsafe extern "C" {
    /// Retrieve the version of the PSA Framework API that is implemented.
    fn psa_framework_version_veneer() -> u32;

    /// Return version of secure function provided by secure binary.
    fn psa_version_veneer(service_id: u32) -> u32;

    /// Call a secure function referenced by a connection handle.
    fn psa_call_veneer(
        handle: types::PsaHandle,
        ctrl_param: types::VectorDescriptor,
        in_vec: *const types::PsaInVec,
        out_vec: *mut types::PsaOutVec,
    ) -> types::PsaStatus;
}

pub struct PsaVeneerClient;

impl PsaApiCallInterface for PsaVeneerClient {
    fn psa_framework_version() -> u32 {
        unsafe { psa_framework_version_veneer() }
    }

    fn psa_version(service_id: u32) -> u32 {
        unsafe { psa_version_veneer(service_id) }
    }

    fn psa_call(
        handle: types::PsaHandle,
        ctrl_param: types::VectorDescriptor,
        in_vec: &[types::PsaInVec],
        out_vec: &mut [types::PsaOutVec],
    ) -> types::PsaStatus {
        let in_vec_ptr = if in_vec.is_empty() {
            core::ptr::null()
        } else {
            in_vec.as_ptr()
        };

        let out_vec_ptr = if out_vec.is_empty() {
            core::ptr::null_mut()
        } else {
            out_vec.as_mut_ptr()
        };

        unsafe { psa_call_veneer(handle, ctrl_param, in_vec_ptr, out_vec_ptr) }
    }
}
