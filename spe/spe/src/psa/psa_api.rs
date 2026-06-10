//! Entry points for PSA API calls from NSPE and other partitions.

use core::panic;

use cortexm33::support;

use crate::{
    StatusCode,
    libs::once_lock::OnceLock,
    psa::psa_call::CallerAttributes,
    psa::{psa_call, psa_iovec_api},
    spm::SpmCall,
};
use psa_interface::PsaApiCallInterface;
use psa_interface::types::{CtrlParam, FFInVec, FFOutVec, ServiceHandle};

static SPM: OnceLock<&'static dyn SpmCall> = OnceLock::new();

fn get_spm() -> &'static dyn SpmCall {
    *SPM.try_get()
        .expect("SPM must be initialized with set_spm() before PSA API use")
}

pub(crate) fn try_get_spm() -> Option<&'static dyn SpmCall> {
    SPM.try_get().copied().ok()
}

pub fn set_spm(spm: &'static dyn SpmCall) {
    if SPM.try_set(spm).is_err() {
        panic!("SPM already initialized");
    }
}

pub struct InternalPsaClient;

impl PsaApiCallInterface for InternalPsaClient {
    fn psa_framework_version() -> u32 {
        todo!();
    }

    fn psa_version(_service_id: u32) -> u32 {
        todo!();
    }

    fn psa_call(
        handle: ServiceHandle,
        ctrl_param: CtrlParam,
        in_vec: &[FFInVec],
        out_vec: &mut [FFOutVec],
    ) -> psa_interface::types::PsaStatus {
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

        crate::into_psa_status(unsafe {
            psa_call::psa_call(
                handle,
                ctrl_param,
                in_vec_ptr,
                out_vec_ptr,
                get_spm(),
                CallerAttributes::SECURE_PRIVILEGED,
            )
        })
    }
}

pub unsafe fn psa_call(
    handle: ServiceHandle,
    ctrl_param: CtrlParam,
    in_vec: *const FFInVec,
    out_vec: *mut FFOutVec,
) -> Result<(), StatusCode> {
    if support::is_interrupt_context() {
        panic!("psa_call cannot be called from an interrupt context");
    }

    // get current comp

    let spm = get_spm();

    // check comp changed during exe

    // NS veneer entry: caller is Non-Secure.
    // Privilege is determined by reading CONTROL_NS.nPRIV at runtime.
    let privileged = !support::is_ns_unprivileged();
    let caller = CallerAttributes {
        ns: true,
        privileged,
    };

    unsafe { psa_call::psa_call(handle, ctrl_param, in_vec, out_vec, spm, caller) }
}

pub fn psa_map_invec<R>(
    msg_handle: ServiceHandle,
    invec_idx: u32,
    f: impl FnOnce(&[u8]) -> R,
) -> R {
    if let Some(spm) = try_get_spm() {
        psa_iovec_api::psa_map_invec(spm, msg_handle, invec_idx, f)
    } else {
        crate::psa::psa_svc_api::psa_map_invec(msg_handle, invec_idx, f)
    }
}

pub fn psa_map_outvec<R>(
    msg_handle: ServiceHandle,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    if let Some(spm) = try_get_spm() {
        psa_iovec_api::psa_map_outvec(spm, msg_handle, outvec_idx, f)
    } else {
        crate::psa::psa_svc_api::psa_map_outvec(msg_handle, outvec_idx, f)
    }
}

pub fn psa_map_invec_outvec<R>(
    msg_handle: ServiceHandle,
    invec_idx: u32,
    outvec_idx: u32,
    f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
) -> R {
    if let Some(spm) = try_get_spm() {
        psa_iovec_api::psa_map_invec_outvec(spm, msg_handle, invec_idx, outvec_idx, f)
    } else {
        crate::psa::psa_svc_api::psa_map_invec_outvec(msg_handle, invec_idx, outvec_idx, f)
    }
}
