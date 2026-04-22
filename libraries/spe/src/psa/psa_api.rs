use core::panic;

use cortexm33::support;

use crate::{
    psa::psa_call,
    psa_interface::{PsaHandle, PsaInVec, PsaOutVec, PsaStatus, VectorDescriptor},
};

///! Entry points for PSA API calls from NSPE and other partitions.

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

    let status = psa_call::psa_call(handle, ctrl_param, in_vec, out_vec);

    // check comp changed during exe

    return status;
}
