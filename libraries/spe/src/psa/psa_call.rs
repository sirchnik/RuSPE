use crate::{
    psa_interface::{PsaHandle, PsaInVec, PsaOutVec, PsaStatus, VectorDescriptor},
    spm::spm,
    spm::spm::Connection,
};
use core::{ptr, slice};

const PSA_SUCCESS: PsaStatus = 0;
const PSA_ERROR_PROGRAMMER_ERROR: PsaStatus = -129;
const PSA_MAX_IOVEC: usize = 4;

#[derive(Clone, Copy, Debug)]
pub struct PsaMsg {
    pub handle: PsaHandle,
    pub msg_type: i32,
    // client_id: u32, // TODO: Do I need this?
    pub in_size: [Option<usize>; PSA_MAX_IOVEC],
    pub out_size: [Option<usize>; PSA_MAX_IOVEC],
}

impl PsaMsg {
    const fn new(handle: PsaHandle, msg_type: i32) -> Self {
        Self {
            handle,
            msg_type,
            in_size: [None; PSA_MAX_IOVEC],
            out_size: [None; PSA_MAX_IOVEC],
        }
    }
}

fn validate_call_params(ctrl_param: VectorDescriptor) -> Result<(i32, usize, usize), PsaStatus> {
    let msg_type = ctrl_param.unpack_type();

    // The request type must be zero or positive.
    if msg_type < 0 {
        return Err(PSA_ERROR_PROGRAMMER_ERROR);
    }

    if !ctrl_param.has_iovec() {
        return Ok((msg_type, 0, 0));
    }

    // C equivalent:
    // if ((ivec_num > (SIZE_MAX - ovec_num)) || ((ivec_num + ovec_num) > PSA_MAX_IOVEC))
    let ivec_num = ctrl_param.in_len();
    let ovec_num = ctrl_param.out_len();
    match ivec_num.checked_add(ovec_num) {
        Some(total) if total <= PSA_MAX_IOVEC => Ok((msg_type, ivec_num, ovec_num)),
        _ => Err(PSA_ERROR_PROGRAMMER_ERROR),
    }
}

fn validate_vec_pointer_shape(
    has_iovec: bool,
    ivec_num: usize,
    ovec_num: usize,
    in_vec: *const PsaInVec,
    out_vec: *mut PsaOutVec,
) -> PsaStatus {
    if !has_iovec {
        return PSA_SUCCESS;
    }

    // Mirrors the C memory-check preconditions in a safe subset.
    if ivec_num > 0 && in_vec.is_null() {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    if ovec_num > 0 && out_vec.is_null() {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    PSA_SUCCESS
}

fn validate_invec_payload_nonoverlap(in_vecs: &[PsaInVec]) -> PsaStatus {
    // Mirrors TF-M's invec anti-overlap checks to avoid double-fetch
    // inconsistencies between distinct input payload buffers.
    if in_vecs.len() < 2 {
        return PSA_SUCCESS;
    }

    for i in 0..(in_vecs.len() - 1) {
        let left_base = in_vecs[i].base as usize;
        let left_end = match left_base.checked_add(in_vecs[i].len) {
            Some(end) => end,
            None => return PSA_ERROR_PROGRAMMER_ERROR,
        };

        for right in &in_vecs[(i + 1)..] {
            let right_base = right.base as usize;
            let right_end = match right_base.checked_add(right.len) {
                Some(end) => end,
                None => return PSA_ERROR_PROGRAMMER_ERROR,
            };

            // Non-overlap condition copied from C:
            // (right_end <= left_base) || (right_base >= left_end)
            if !((right_end <= left_base) || (right_base >= left_end)) {
                return PSA_ERROR_PROGRAMMER_ERROR;
            }
        }
    }

    PSA_SUCCESS
}

pub fn psa_call_from_slices(
    handle: PsaHandle,
    ctrl_param: VectorDescriptor,
    in_vecs: &[PsaInVec],
    out_vecs: &mut [PsaOutVec],
    _spm: &spm::Spm,
) -> Result<Connection, PsaStatus> {
    let (msg_type, ivec_num, ovec_num) = match validate_call_params(ctrl_param) {
        Ok(values) => values,
        Err(status) => return Err(status),
    };

    if in_vecs.len() != ivec_num || out_vecs.len() != ovec_num {
        return Err(PSA_ERROR_PROGRAMMER_ERROR);
    }

    let overlap_status = validate_invec_payload_nonoverlap(in_vecs);
    if overlap_status != PSA_SUCCESS {
        return Err(PSA_ERROR_PROGRAMMER_ERROR);
    }

    let mut msg = PsaMsg::new(handle, msg_type);
    let _ = (msg.handle, msg.msg_type);
    let mut invec_base: [*const u8; PSA_MAX_IOVEC] = [ptr::null(); PSA_MAX_IOVEC];
    let mut invec_accessed = [0; PSA_MAX_IOVEC];
    let mut outvec_base: [*mut u8; PSA_MAX_IOVEC] = [ptr::null_mut(); PSA_MAX_IOVEC];
    let mut outvec_written = [0; PSA_MAX_IOVEC];

    for (idx, in_vec) in in_vecs.iter().enumerate() {
        invec_base[idx] = in_vec.base;
        invec_accessed[idx] = 0;
        msg.in_size[idx] = Some(in_vec.len);
    }

    for (idx, out_vec) in out_vecs.iter_mut().enumerate() {
        outvec_base[idx] = out_vec.base;
        outvec_written[idx] = 0;
        msg.out_size[idx] = Some(out_vec.len);
    }

    Ok(Connection {
        msg,
        invec_base,
        invec_accessed,
        invec_mapped: [false; PSA_MAX_IOVEC],
        invec_unmapped: [false; PSA_MAX_IOVEC],
        outvec_base,
        outvec_written,
        outvec_mapped: [false; PSA_MAX_IOVEC],
        outvec_unmapped: [false; PSA_MAX_IOVEC],
    })
}

pub fn psa_call(
    handle: PsaHandle,
    ctrl_param: VectorDescriptor,
    in_vec: *const PsaInVec,
    out_vec: *mut PsaOutVec,
    spm: &spm::Spm,
) -> PsaStatus {
    let (_msg_type, ivec_num, ovec_num) = match validate_call_params(ctrl_param) {
        Ok(values) => values,
        Err(status) => return status,
    };

    let pointer_status =
        validate_vec_pointer_shape(ctrl_param.has_iovec(), ivec_num, ovec_num, in_vec, out_vec);
    if pointer_status != PSA_SUCCESS {
        return pointer_status;
    }

    let in_vecs: &[PsaInVec] = if ivec_num == 0 {
        &[]
    } else {
        // ### Safety
        // `validate_vec_pointer_shape()` guarantees `in_vec` is non-null when
        // `ivec_num > 0`. The caller provides the C ABI contract that the pointer
        // references at least `ivec_num` contiguous `PsaInVec` elements.
        unsafe { slice::from_raw_parts(in_vec, ivec_num) }
    };

    let out_vecs: &mut [PsaOutVec] = if ovec_num == 0 {
        &mut []
    } else {
        // ### Safety
        // `validate_vec_pointer_shape()` guarantees `out_vec` is non-null when
        // `ovec_num > 0`. The caller provides the C ABI contract that the pointer
        // references at least `ovec_num` contiguous `PsaOutVec` elements with
        // unique mutable access for the duration of this call.
        unsafe { slice::from_raw_parts_mut(out_vec, ovec_num) }
    };

    let Ok(connection) = psa_call_from_slices(handle, ctrl_param, in_vecs, out_vecs, spm) else {
        return PSA_ERROR_PROGRAMMER_ERROR;
    };

    spm.call(connection);
    0
}
