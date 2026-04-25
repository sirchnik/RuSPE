use core::{cell::OnceCell, panic};

use cortexm33::support;

use crate::{
    psa::{psa_call, psa_iovec_api},
    psa_interface::{PsaHandle, PsaInVec, PsaOutVec, PsaStatus, VectorDescriptor},
    spm::spm,
};

///! Entry points for PSA API calls from NSPE and other partitions.

struct SingleThreadValue<T> {
    value: T,
}

// expect only single core (maybe todo)
unsafe impl<T> Sync for SingleThreadValue<T> {}

static SPM: SingleThreadValue<OnceCell<&'static spm::Spm>> = SingleThreadValue {
    value: OnceCell::new(),
};

pub(crate) fn get_spm() -> &'static spm::Spm {
    SPM.value
        .get()
        .expect("SPM must be initialized with set_spm() before PSA API use")
}

pub fn set_spm(spm: &'static spm::Spm) {
    SPM.value
        .set(spm)
        .expect("set_spm() may only be called once");
}

pub fn psa_call(
    handle: PsaHandle,
    ctrl_param: VectorDescriptor,
    in_vec: *const PsaInVec,
    out_vec: *mut PsaOutVec,
) -> PsaStatus {
    if support::is_interrupt_context() {
        panic!("psa_call cannot be called from an interrupt context");
    }

    // get current comp

    let spm = get_spm();

    let status = psa_call::psa_call(handle, ctrl_param, in_vec, out_vec, spm);

    // check comp changed during exe

    return status;
}

pub fn psa_map_invec(msg_handle: PsaHandle, invec_idx: u32) -> psa_iovec_api::MappedInVec {
    psa_iovec_api::psa_map_invec(msg_handle, invec_idx)
}

pub fn psa_map_outvec(msg_handle: PsaHandle, outvec_idx: u32) -> psa_iovec_api::MappedOutVec {
    psa_iovec_api::psa_map_outvec(msg_handle, outvec_idx)
}

pub fn psa_unmap_invec(msg_handle: PsaHandle, invec_idx: u32) {
    psa_iovec_api::psa_unmap_invec(msg_handle, invec_idx)
}

pub fn psa_unmap_outvec(msg_handle: PsaHandle, outvec_idx: u32, written_len: usize) {
    psa_iovec_api::psa_unmap_outvec(msg_handle, outvec_idx, written_len)
}
