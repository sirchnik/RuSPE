use core::{cell::OnceCell, panic};

use cortexm33::support;

use crate::{
    psa::psa_call,
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

pub fn set_spm(spm: &'static spm::Spm) {
    SPM.value.set(spm).unwrap();
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

    let spm = SPM.value.get().unwrap();

    let status = psa_call::psa_call(handle, ctrl_param, in_vec, out_vec, spm);

    // check comp changed during exe

    return status;
}
