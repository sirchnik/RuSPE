//! Veneer function stubs translated from TFM veneer C header.
// These are placeholders for secure function entry points.

// TODO: Do I need reentrance protection like here: secure_fw/partitions/ns_agent_tz/psa_api_veneers_v80m.c ?

// unsafe(no_mangle) is required to ensure these functions are linkable from
// non-secure code. It is unsafe because there could be name collisions.

use crate::psa::psa_api::psa_call;
use crate::psa_interface::{PsaHandle, PsaInVec, PsaOutVec, PsaStatus, VectorDescriptor};

/// Retrieve the version of the PSA Framework API that is implemented.
#[unsafe(no_mangle)]
pub extern "cmse-nonsecure-entry" fn tfm_psa_framework_version_veneer() -> u32 {
    unimplemented!("PSA framework version veneer not implemented")
}

/// Return version of secure function provided by secure binary.
#[unsafe(no_mangle)]
pub extern "cmse-nonsecure-entry" fn tfm_psa_version_veneer(service_id: u32) -> u32 {
    let _ = service_id;
    unimplemented!("PSA version veneer not implemented")
}

/// Call a secure function referenced by a connection handle.
#[unsafe(no_mangle)]
pub extern "cmse-nonsecure-entry" fn tfm_psa_call_veneer(
    handle: PsaHandle,
    ctrl_param: VectorDescriptor,
    in_vec: *const PsaInVec,
    out_vec: *mut PsaOutVec,
) -> PsaStatus {
    psa_call(handle, ctrl_param, in_vec, out_vec)
}

/// Close connection to secure function referenced by a connection handle.
#[unsafe(no_mangle)]
pub extern "cmse-nonsecure-entry" fn tfm_psa_close_veneer(handle: PsaHandle) {
    let _ = handle;
    unimplemented!("PSA close veneer not implemented")
}

// TODO: Do I need this?
// /// Connect to secure function.
// #[unsafe(no_mangle)]
// pub extern "cmse-nonsecure-entry"  fn tfm_psa_connect_veneer(sid: u32, version: u32) -> psa_handle_t {
//     let _ = (sid, version);
//     unimplemented!("PSA connect veneer not implemented")
// }
