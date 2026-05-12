//! Veneer function stubs translated from TFM veneer C header.
// These are placeholders for secure function entry points.

// TODO: Do I need reentrance protection like here: secure_fw/partitions/ns_agent_tz/psa_api_veneers_v80m.c ?
// 2. Why is Reentrancy a Problem?
// If a Secure function is not designed to be reentrant (meaning it doesn't handle multiple simultaneous instances of itself), a second call could:
// Corrupt the Secure Stack: Overwrite local variables or return addresses of the first call.
// Bypass Security Logic: If a function checks a permission at the start and relies on that state, a reentrant call might alter the state while the first instance is still mid-execution.
// Leak Data: State from the first "half-finished" call might be accessible to the second call.

// unsafe(no_mangle) is required to ensure these functions are linkable from
// non-secure code. It is unsafe because there could be name collisions.

use crate::psa::psa_api;
use psa_interface::status::into_psa_status;
use psa_interface::types::{CtrlParam, FFInVec, FFOutVec, PsaStatus, ServiceHandle};

/// Retrieve the version of the PSA Framework API that is implemented.
#[unsafe(no_mangle)]
pub extern "cmse-nonsecure-entry" fn psa_framework_version_veneer() -> u32 {
    unimplemented!("PSA framework version veneer not implemented")
}

/// Return version of secure function provided by secure binary.
#[unsafe(no_mangle)]
pub extern "cmse-nonsecure-entry" fn psa_version_veneer(service_id: u32) -> u32 {
    let _ = service_id;
    unimplemented!("PSA version veneer not implemented")
}

/// Call a secure function referenced by a connection handle.
#[unsafe(no_mangle)]
pub extern "cmse-nonsecure-entry" fn psa_call_veneer(
    handle: ServiceHandle,
    ctrl_param: CtrlParam,
    in_vec: *const FFInVec,
    out_vec: *mut FFOutVec,
) -> PsaStatus {
    // Safety: The caller (NSPE) provides valid pointers per the PSA FF-M ABI contract.
    into_psa_status(unsafe { psa_api::psa_call(handle, ctrl_param, in_vec, out_vec) })
}

// /// Close connection to secure function referenced by a connection handle.
// #[unsafe(no_mangle)]
// pub extern "cmse-nonsecure-entry" fn tfm_psa_close_veneer(handle: PsaHandle) {
//     let _ = handle;
//     unimplemented!("PSA close veneer not implemented")
// }

// TODO: Do I need this?
// /// Connect to secure function.
// #[unsafe(no_mangle)]
// pub extern "cmse-nonsecure-entry"  fn tfm_psa_connect_veneer(sid: u32, version: u32) -> psa_handle_t {
//     let _ = (sid, version);
//     unimplemented!("PSA connect veneer not implemented")
// }
