use core::panic;

use cortexm33::support;

use crate::{
    StatusCode,
    libs::once_lock::OnceLock,
    psa::{psa_call, psa_iovec_api},
    spm::spm,
};
use psa_interface::types::{PsaHandle, PsaInVec, PsaOutVec, VectorDescriptor};

///! Entry points for PSA API calls from NSPE and other partitions.

static SPM: OnceLock<&'static spm::Spm> = OnceLock::new();

fn get_spm() -> &'static spm::Spm {
    SPM.get()
        .expect("SPM must be initialized with set_spm() before PSA API use")
}

pub fn set_spm(spm: &'static spm::Spm) {
    SPM.set(spm).unwrap();
}

pub fn psa_call(
    handle: PsaHandle,
    ctrl_param: VectorDescriptor,
    in_vec: *const PsaInVec,
    out_vec: *mut PsaOutVec,
) -> Result<(), StatusCode> {
    if support::is_interrupt_context() {
        panic!("psa_call cannot be called from an interrupt context");
    }

    // get current comp

    let spm = get_spm();

    let result = psa_call::psa_call(handle, ctrl_param, in_vec, out_vec, spm);

    // check comp changed during exe

    result
}

pub fn psa_map_invec<R>(msg_handle: PsaHandle, invec_idx: u32, f: impl FnOnce(&[u8]) -> R) -> R {
    psa_iovec_api::psa_map_invec(get_spm(), msg_handle, invec_idx, f)
}

pub fn psa_map_outvec<R>(
    msg_handle: PsaHandle,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    psa_iovec_api::psa_map_outvec(get_spm(), msg_handle, outvec_idx, f)
}

pub fn psa_map_invec_outvec<R>(
    msg_handle: PsaHandle,
    invec_idx: u32,
    outvec_idx: u32,
    f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
) -> R {
    psa_iovec_api::psa_map_invec_outvec(get_spm(), msg_handle, invec_idx, outvec_idx, f)
}
