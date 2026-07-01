// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::spm::spm::{Connection, PSA_MAX_IOVEC, SpmCall, SpmError};
use core::{panic, ptr, slice};
use psa_interface::{
    status::StatusCode,
    types::{CtrlParam, FFInVec, FFOutVec, ServiceHandle},
};

use crate::spm_api::{CallerAttributes, PsaMsg};
pub fn validate_call_params(ctrl_param: CtrlParam) -> Result<(i32, usize, usize), StatusCode> {
    let msg_type = ctrl_param.unpack_type();

    // The request type must be zero or positive.
    if msg_type < 0 {
        return Err(StatusCode::ProgrammerError);
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
        _ => Err(StatusCode::ProgrammerError),
    }
}

pub fn validate_vec_pointer_shape(
    has_iovec: bool,
    ivec_num: usize,
    ovec_num: usize,
    in_vec: *const FFInVec,
    out_vec: *mut FFOutVec,
) -> Result<(), StatusCode> {
    if !has_iovec {
        return Ok(());
    }

    // Mirrors the C memory-check preconditions in a safe subset.
    if ivec_num > 0 && in_vec.is_null() {
        return Err(StatusCode::ProgrammerError);
    }

    if ovec_num > 0 && out_vec.is_null() {
        return Err(StatusCode::ProgrammerError);
    }

    Ok(())
}

pub fn validate_invec_payload_nonoverlap(in_vecs: &[FFInVec]) -> Result<(), StatusCode> {
    // Mirrors TF-M's invec anti-overlap checks to avoid double-fetch
    // inconsistencies between distinct input payload buffers.
    if in_vecs.len() < 2 {
        return Ok(());
    }

    for i in 0..(in_vecs.len() - 1) {
        let left_base = in_vecs[i].base as usize;
        let left_end = left_base
            .checked_add(in_vecs[i].len)
            .ok_or(StatusCode::ProgrammerError)?;

        for right in &in_vecs[(i + 1)..] {
            let right_base = right.base as usize;
            let right_end = right_base
                .checked_add(right.len)
                .ok_or(StatusCode::ProgrammerError)?;

            // Non-overlap condition copied from C:
            // (right_end <= left_base) || (right_base >= left_end)
            if !((right_end <= left_base) || (right_base >= left_end)) {
                return Err(StatusCode::ProgrammerError);
            }
        }
    }

    Ok(())
}

pub fn call_from_slices(
    handle: ServiceHandle,
    ctrl_param: CtrlParam,
    in_vecs: &[FFInVec],
    out_vecs: &mut [FFOutVec],
    caller: CallerAttributes,
) -> Result<Connection, StatusCode> {
    let (msg_type, ivec_num, ovec_num) = validate_call_params(ctrl_param)?;

    if in_vecs.len() != ivec_num || out_vecs.len() != ovec_num {
        return Err(StatusCode::ProgrammerError);
    }

    validate_invec_payload_nonoverlap(in_vecs)?;

    let mut msg = PsaMsg::new(handle, msg_type, caller);
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

pub fn validate_pointer_range(base: *const u8, len: usize, vector_kind: &str) {
    if len == 0 {
        return;
    }

    if base.is_null() {
        panic!("{} base pointer is null", vector_kind);
    }

    if (base as usize).checked_add(len).is_none() {
        panic!("{} range overflows pointer space", vector_kind);
    }
}

pub fn validate_real_permission<S: SpmCall>(
    spm: &S,
    base: *const u8,
    len: usize,
    vector_kind: &str,
    is_write: bool,
    caller: CallerAttributes,
) {
    if len == 0 {
        return;
    }

    if !spm.has_real_permission(base, len, is_write, caller) {
        panic!(
            "{} is not permitted by real memory access control",
            vector_kind
        );
    }
}

pub fn with_connection_for_handle<S: SpmCall, R>(
    spm: &S,
    msg_handle: ServiceHandle,
    f: impl FnOnce(&mut Connection) -> R,
) -> R {
    let mut result: Option<R> = None;
    let mut f = Some(f);
    match spm.with_active_connection(|connection: &mut Connection| {
        if (connection.msg.handle as isize) != (msg_handle as isize) {
            panic!("invalid message handle for active connection");
        }

        if connection.msg.msg_type < 0 {
            panic!("message handle does not refer to a request message");
        }

        let f = f.take().unwrap();
        result = Some(f(connection));
    }) {
        Ok(()) => {}
        Err(SpmError::NoActiveConnection) => panic!("no active SPM connection"),
        Err(err) => panic!("failed to access active SPM connection: {:?}", err),
    }

    result.expect("no active SPM connection")
}

pub fn prepare_invec<S: SpmCall>(
    spm: &S,
    connection: &mut Connection,
    invec_idx: u32,
) -> (usize, usize, *const u8) {
    let index = invec_idx as usize;
    if index >= PSA_MAX_IOVEC {
        panic!("invec index is out of range");
    }

    let in_len = connection.msg.in_size[index].unwrap_or(0);

    if connection.invec_mapped[index] {
        panic!("input vector is already mapped");
    }

    if connection.invec_accessed[index] != 0 {
        panic!("input vector was already accessed by read/skip");
    }

    let base = connection.invec_base[index];

    validate_pointer_range(base, in_len, "input vector");
    validate_real_permission(
        spm,
        base,
        in_len,
        "input vector",
        false,
        connection.msg.caller,
    );

    connection.invec_mapped[index] = true;

    (index, in_len, base)
}

pub fn mark_invec_unmapped(connection: &mut Connection, index: usize) {
    if connection.invec_unmapped[index] {
        panic!("input vector is already unmapped");
    }

    connection.invec_unmapped[index] = true;
}

pub fn prepare_outvec<S: SpmCall>(
    spm: &S,
    connection: &mut Connection,
    outvec_idx: u32,
) -> (usize, usize, *mut u8) {
    let index = outvec_idx as usize;
    if index >= PSA_MAX_IOVEC {
        panic!("outvec index is out of range");
    }

    let out_len = connection.msg.out_size[index].unwrap_or(0);

    if connection.outvec_mapped[index] {
        panic!("output vector is already mapped");
    }

    if connection.outvec_written[index] != 0 {
        panic!("output vector was already written");
    }

    let base = connection.outvec_base[index];

    validate_pointer_range(base.cast_const(), out_len, "output vector");
    validate_real_permission(
        spm,
        base.cast_const(),
        out_len,
        "output vector",
        true,
        connection.msg.caller,
    );

    connection.outvec_mapped[index] = true;

    (index, out_len, base)
}

pub fn commit_outvec_write(
    connection: &mut Connection,
    out_index: usize,
    out_len: usize,
    written_len: usize,
) {
    if connection.outvec_unmapped[out_index] {
        panic!("output vector is already unmapped");
    }

    if written_len > out_len {
        panic!("written length exceeds output vector capacity");
    }

    connection.outvec_written[out_index] = written_len;
    connection.msg.out_size[out_index] = Some(written_len);
    connection.outvec_unmapped[out_index] = true;
}

pub fn with_mapped_invec<S: SpmCall, R>(
    spm: &S,
    connection: &mut Connection,
    invec_idx: u32,
    f: impl FnOnce(&[u8]) -> R,
) -> R {
    let (index, in_len, base) = prepare_invec(spm, connection, invec_idx);

    let invec = if in_len == 0 {
        &[]
    } else {
        // # Safety:
        // `base` is checked non-null in `prepare_invec`, and `in_len` is from the
        // SPM-tracked input vector size for this message.
        unsafe { slice::from_raw_parts(base, in_len) }
    };
    let result = f(invec);

    mark_invec_unmapped(connection, index);

    result
}

pub fn with_mapped_outvec<S: SpmCall, R>(
    spm: &S,
    connection: &mut Connection,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    let (index, out_len, base) = prepare_outvec(spm, connection, outvec_idx);

    let outvec = if out_len == 0 {
        &mut []
    } else {
        // Safety:
        // base is checked non-null in prepare_outvec, and out_len is
        // the SPM-tracked output vector size for this message.
        unsafe { slice::from_raw_parts_mut(base, out_len) }
    };
    let (result, written_len) = f(outvec);

    commit_outvec_write(connection, index, out_len, written_len);

    result
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RawVec {
    pub base: *mut u8,
    pub len: usize,
}

pub fn prepare_invec_raw<S: SpmCall>(
    spm: &S,
    msg_handle: ServiceHandle,
    invec_idx: u32,
) -> Result<RawVec, StatusCode> {
    let mut raw = None;
    match spm.with_active_connection(|connection: &mut Connection| {
        if (connection.msg.handle as isize) != (msg_handle as isize) {
            panic!("invalid message handle for active connection");
        }

        if connection.msg.msg_type < 0 {
            panic!("message handle does not refer to a request message");
        }

        let (_, in_len, base) = prepare_invec(spm, connection, invec_idx);
        raw = Some(RawVec {
            base: base.cast_mut(),
            len: in_len,
        });
    }) {
        Ok(()) => Ok(raw.expect("no active SPM connection")),
        Err(SpmError::NoActiveConnection) => Err(StatusCode::CommunicationFailure),
        Err(_) => Err(StatusCode::CommunicationFailure),
    }
}

pub fn finish_invec_raw<S: SpmCall>(
    spm: &S,
    msg_handle: ServiceHandle,
    invec_idx: u32,
) -> Result<(), StatusCode> {
    match spm.with_active_connection(|connection: &mut Connection| {
        if (connection.msg.handle as isize) != (msg_handle as isize) {
            panic!("invalid message handle for active connection");
        }

        if connection.msg.msg_type < 0 {
            panic!("message handle does not refer to a request message");
        }

        mark_invec_unmapped(connection, invec_idx as usize);
    }) {
        Ok(()) => Ok(()),
        Err(SpmError::NoActiveConnection) => Err(StatusCode::CommunicationFailure),
        Err(_) => Err(StatusCode::CommunicationFailure),
    }
}

pub fn prepare_outvec_raw<S: SpmCall>(
    spm: &S,
    msg_handle: ServiceHandle,
    outvec_idx: u32,
) -> Result<RawVec, StatusCode> {
    let mut raw = None;
    match spm.with_active_connection(|connection: &mut Connection| {
        if (connection.msg.handle as isize) != (msg_handle as isize) {
            panic!("invalid message handle for active connection");
        }

        if connection.msg.msg_type < 0 {
            panic!("message handle does not refer to a request message");
        }

        let (_, out_len, base) = prepare_outvec(spm, connection, outvec_idx);
        raw = Some(RawVec { base, len: out_len });
    }) {
        Ok(()) => Ok(raw.expect("no active SPM connection")),
        Err(SpmError::NoActiveConnection) => Err(StatusCode::CommunicationFailure),
        Err(_) => Err(StatusCode::CommunicationFailure),
    }
}

pub fn finish_outvec_raw<S: SpmCall>(
    spm: &S,
    msg_handle: ServiceHandle,
    outvec_idx: u32,
    written_len: usize,
) -> Result<(), StatusCode> {
    match spm.with_active_connection(|connection: &mut Connection| {
        if (connection.msg.handle as isize) != (msg_handle as isize) {
            panic!("invalid message handle for active connection");
        }

        if connection.msg.msg_type < 0 {
            panic!("message handle does not refer to a request message");
        }

        let index = outvec_idx as usize;
        let out_len = connection.msg.out_size[index].unwrap_or(0);
        commit_outvec_write(connection, index, out_len, written_len);
    }) {
        Ok(()) => Ok(()),
        Err(SpmError::NoActiveConnection) => Err(StatusCode::CommunicationFailure),
        Err(_) => Err(StatusCode::CommunicationFailure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use psa_interface::status::StatusCode;
    use psa_interface::types::{CtrlParam, FFInVec, FFOutVec};

    #[test]
    fn test_validate_call_params_invalid_msg_type() {
        let param = CtrlParam::new(-1, 0, false, 0, false);
        let res = validate_call_params(param);
        assert_eq!(res, Err(StatusCode::ProgrammerError));
    }

    #[test]
    fn test_validate_call_params_valid() {
        let param = CtrlParam::new(1, 2, false, 1, false);
        let res = validate_call_params(param);
        assert_eq!(res, Ok((1, 2, 1)));
    }

    #[test]
    fn test_validate_call_params_max_iovec_exceeded() {
        let param = CtrlParam::new(1, 3, false, 2, false); // 3+2 = 5 > 4 (PSA_MAX_IOVEC)
        let res = validate_call_params(param);
        assert_eq!(res, Err(StatusCode::ProgrammerError));
    }

    #[test]
    fn test_validate_vec_pointer_shape() {
        let invec = FFInVec {
            base: ptr::null(),
            len: 0,
        };
        let mut outvec = FFOutVec {
            base: ptr::null_mut(),
            len: 0,
        };

        let res = validate_vec_pointer_shape(true, 1, 0, ptr::null(), &mut outvec as *mut _);
        assert_eq!(res, Err(StatusCode::ProgrammerError));

        let res = validate_vec_pointer_shape(true, 0, 1, &invec as *const _, ptr::null_mut());
        assert_eq!(res, Err(StatusCode::ProgrammerError));

        let res = validate_vec_pointer_shape(true, 1, 1, &invec as *const _, &mut outvec as *mut _);
        assert_eq!(res, Ok(()));

        let res = validate_vec_pointer_shape(false, 1, 1, ptr::null(), ptr::null_mut());
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn test_validate_invec_payload_nonoverlap() {
        let buf = [0u8; 100];
        let ptr = buf.as_ptr();

        let in_vecs_ok = [
            FFInVec { base: ptr, len: 10 },
            FFInVec {
                base: unsafe { ptr.add(10) },
                len: 10,
            },
        ];
        assert_eq!(validate_invec_payload_nonoverlap(&in_vecs_ok), Ok(()));

        let in_vecs_overlap = [
            FFInVec { base: ptr, len: 15 },
            FFInVec {
                base: unsafe { ptr.add(10) },
                len: 10,
            },
        ];
        assert_eq!(
            validate_invec_payload_nonoverlap(&in_vecs_overlap),
            Err(StatusCode::ProgrammerError)
        );
    }
}
