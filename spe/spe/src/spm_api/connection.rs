// SPDX-FileCopyrightText: Infineon Technologies AG
// SPDX-FileCopyrightText: 2018-2023, Arm Limited.
// SPDX-FileCopyrightText: 2026 The TrustedFirmware-M
// Contributors.
//
// SPDX-License-Identifier: MIT

use core::{ptr, slice};

use psa_interface::status::StatusCode;
use psa_interface::types::{CtrlParam, FFInVec, FFOutVec, ServiceHandle};

use crate::spm::spm::{Connection, PSA_MAX_IOVEC, SpmCall};
use crate::spm_api::{CallerAttributes, MaybeUsize, PsaMsg};

/// Access the active connection after verifying it matches `msg_handle` and
/// refers to a request message. Returns `CommunicationFailure` if no
/// connection is active.
fn with_validated_connection<S: SpmCall, R>(
    spm: &S,
    msg_handle: ServiceHandle,
    f: impl FnOnce(&mut Connection) -> Result<R, StatusCode>,
) -> Result<R, StatusCode> {
    let mut result: Result<R, StatusCode> = Err(StatusCode::CommunicationFailure);
    let mut f = Some(f);

    let access_result = spm.with_active_connection(|connection: &mut Connection| {
        if (connection.msg.handle as isize) != (msg_handle as isize) {
            result = Err(StatusCode::InvalidHandle);
            return;
        }
        if connection.msg.msg_type < 0 {
            result = Err(StatusCode::ProgrammerError);
            return;
        }
        if let Some(func) = f.take() {
            result = func(connection);
        }
    });

    match access_result {
        Ok(()) => result,
        Err(_) => Err(StatusCode::CommunicationFailure),
    }
}
/// # Errors
///
/// See `StatusCode` for error conditions.
pub const fn validate_call_params(
    ctrl_param: CtrlParam,
) -> Result<(i32, usize, usize), StatusCode> {
    let msg_type = ctrl_param.unpack_type();

    // The request type must be zero or positive.
    if msg_type < 0 {
        return Err(StatusCode::ProgrammerError);
    }

    if !ctrl_param.has_iovec() {
        return Ok((msg_type, 0, 0));
    }

    // C equivalent:
    // if ((ivec_num > (SIZE_MAX - ovec_num)) || ((ivec_num + ovec_num) >
    // PSA_MAX_IOVEC))
    let ivec_num = ctrl_param.in_len();
    let ovec_num = ctrl_param.out_len();
    match ivec_num.checked_add(ovec_num) {
        Some(total) if total <= PSA_MAX_IOVEC => Ok((msg_type, ivec_num, ovec_num)),
        _ => Err(StatusCode::ProgrammerError),
    }
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub const fn validate_vec_pointer_shape(
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

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn validate_invec_payload_nonoverlap(in_vecs: &[FFInVec]) -> Result<(), StatusCode> {
    // Mirrors TF-M's invec anti-overlap checks to avoid double-fetch
    // inconsistencies between distinct input payload buffers.
    if in_vecs.len() < 2 {
        return Ok(());
    }

    for i in 0..(in_vecs.len() - 1) {
        let Some(left_vec) = in_vecs.get(i) else {
            return Err(StatusCode::ProgrammerError);
        };
        let left_base = left_vec.base as usize;
        let left_end = left_base
            .checked_add(left_vec.len)
            .ok_or(StatusCode::ProgrammerError)?;

        let slice_rest = in_vecs.get((i + 1)..).unwrap_or(&[]);
        for right in slice_rest {
            let right_base = right.base as usize;
            let right_end = right_base
                .checked_add(right.len)
                .ok_or(StatusCode::ProgrammerError)?;

            let ranges_overlap = right_base < left_end && left_base < right_end;
            if ranges_overlap {
                return Err(StatusCode::ProgrammerError);
            }
        }
    }

    Ok(())
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn call_from_slices<S: SpmCall>(
    spm: &S,
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
    let mut invec_base: [*const u8; PSA_MAX_IOVEC] = [ptr::null(); PSA_MAX_IOVEC];
    let mut invec_accessed = [0; PSA_MAX_IOVEC];
    let mut outvec_base: [*mut u8; PSA_MAX_IOVEC] = [ptr::null_mut(); PSA_MAX_IOVEC];
    let mut outvec_written = [0; PSA_MAX_IOVEC];

    for (idx, in_vec) in in_vecs.iter().enumerate() {
        if let Some(slot) = invec_base.get_mut(idx) {
            *slot = in_vec.base;
        }
        if let Some(slot) = invec_accessed.get_mut(idx) {
            *slot = 0;
        }
        if let Some(slot) = msg.in_size.get_mut(idx) {
            *slot = MaybeUsize::some(in_vec.len);
        }

        validate_pointer_range(in_vec.base, in_vec.len)?;
        validate_memory_permission(spm, in_vec.base, in_vec.len, false, caller)?;
    }

    for (idx, out_vec) in out_vecs.iter_mut().enumerate() {
        if let Some(slot) = outvec_base.get_mut(idx) {
            *slot = out_vec.base;
        }
        if let Some(slot) = outvec_written.get_mut(idx) {
            *slot = 0;
        }
        if let Some(slot) = msg.out_size.get_mut(idx) {
            *slot = MaybeUsize::some(out_vec.len);
        }

        validate_pointer_range(out_vec.base, out_vec.len)?;
        validate_memory_permission(spm, out_vec.base, out_vec.len, true, caller)?;
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

/// Validates that `[base, base+len)` does not wrap around the address space
/// and that `base` is non-null when `len > 0`.
///
/// # Errors
///
/// Returns `ProgrammerError` on null pointer or address overflow.
pub fn validate_pointer_range(base: *const u8, len: usize) -> Result<(), StatusCode> {
    if len == 0 {
        return Ok(());
    }

    if base.is_null() {
        return Err(StatusCode::ProgrammerError);
    }

    if (base as usize).checked_add(len).is_none() {
        return Err(StatusCode::ProgrammerError);
    }

    Ok(())
}

/// Checks that the caller has the required memory permission for the range.
///
/// # Errors
///
/// Returns `InvalidArgument` if the permission check fails.
pub fn validate_memory_permission<S: SpmCall>(
    spm: &S,
    base: *const u8,
    len: usize,
    is_write: bool,
    caller: CallerAttributes,
) -> Result<(), StatusCode> {
    if len == 0 {
        return Ok(());
    }

    if spm.has_real_permission(base, len, is_write, caller) {
        Ok(())
    } else {
        Err(StatusCode::InvalidArgument)
    }
}

pub fn with_connection_for_handle<S: SpmCall, R>(
    spm: &S,
    msg_handle: ServiceHandle,
    f: impl FnOnce(&mut Connection) -> Result<R, StatusCode>,
) -> Result<R, StatusCode> {
    with_validated_connection(spm, msg_handle, f)
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn prepare_invec(
    connection: &mut Connection,
    invec_idx: u32,
) -> Result<(usize, usize, *const u8), StatusCode> {
    let index = invec_idx as usize;
    if index >= PSA_MAX_IOVEC {
        return Err(StatusCode::ProgrammerError);
    }

    let in_len = connection
        .msg
        .in_size
        .get(index)
        .map_or(0, |m| m.unwrap_or(0));

    let is_mapped = match connection.invec_mapped.get(index) {
        Some(&b) => b,
        None => true,
    };
    let is_accessed = match connection.invec_accessed.get(index) {
        Some(&val) => val != 0,
        None => true,
    };

    if is_mapped || is_accessed {
        return Err(StatusCode::ProgrammerError);
    }

    let Some(&base) = connection.invec_base.get(index) else {
        return Err(StatusCode::ProgrammerError);
    };

    if let Some(mapped) = connection.invec_mapped.get_mut(index) {
        *mapped = true;
    }

    Ok((index, in_len, base))
}

pub fn mark_invec_unmapped(connection: &mut Connection, index: usize) -> Result<(), StatusCode> {
    let Some(slot) = connection.invec_unmapped.get_mut(index) else {
        return Err(StatusCode::ProgrammerError);
    };
    if *slot {
        return Err(StatusCode::ProgrammerError);
    }
    *slot = true;
    Ok(())
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn prepare_outvec(
    connection: &mut Connection,
    outvec_idx: u32,
) -> Result<(usize, usize, *mut u8), StatusCode> {
    let index = outvec_idx as usize;
    if index >= PSA_MAX_IOVEC {
        return Err(StatusCode::ProgrammerError);
    }

    let out_len = connection
        .msg
        .out_size
        .get(index)
        .map_or(0, |m| m.unwrap_or(0));

    let is_mapped = match connection.outvec_mapped.get(index) {
        Some(&b) => b,
        None => true,
    };
    let is_written = match connection.outvec_written.get(index) {
        Some(&val) => val != 0,
        None => true,
    };

    if is_mapped || is_written {
        return Err(StatusCode::ProgrammerError);
    }

    let Some(&base) = connection.outvec_base.get(index) else {
        return Err(StatusCode::ProgrammerError);
    };

    if let Some(mapped) = connection.outvec_mapped.get_mut(index) {
        *mapped = true;
    }

    Ok((index, out_len, base))
}

pub fn commit_outvec_write(
    connection: &mut Connection,
    out_index: usize,
    out_len: usize,
    written_len: usize,
) -> Result<(), StatusCode> {
    let Some(unmapped) = connection.outvec_unmapped.get_mut(out_index) else {
        return Err(StatusCode::ProgrammerError);
    };
    if *unmapped || written_len > out_len {
        return Err(StatusCode::ProgrammerError);
    }

    if let Some(w) = connection.outvec_written.get_mut(out_index) {
        *w = written_len;
    }
    if let Some(size) = connection.msg.out_size.get_mut(out_index) {
        *size = MaybeUsize::some(written_len);
    }
    *unmapped = true;
    Ok(())
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn with_mapped_invec<S: SpmCall, R>(
    _spm: &S,
    connection: &mut Connection,
    invec_idx: u32,
    f: impl FnOnce(&[u8]) -> R,
) -> Result<R, StatusCode> {
    let (index, in_len, base) = prepare_invec(connection, invec_idx)?;

    let invec = if in_len == 0 {
        &[]
    } else {
        // # Safety:
        // `base` is checked non-null in `prepare_invec`, and `in_len` is from the
        // SPM-tracked input vector size for this message.
        unsafe { slice::from_raw_parts(base, in_len) }
    };
    let result = f(invec);

    mark_invec_unmapped(connection, index)?;

    Ok(result)
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn with_mapped_outvec<S: SpmCall, R>(
    _spm: &S,
    connection: &mut Connection,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> Result<R, StatusCode> {
    let (index, out_len, base) = prepare_outvec(connection, outvec_idx)?;

    let outvec = if out_len == 0 {
        &mut []
    } else {
        // Safety:
        // base is checked non-null in prepare_outvec, and out_len is
        // the SPM-tracked output vector size for this message.
        unsafe { slice::from_raw_parts_mut(base, out_len) }
    };
    let (result, written_len) = f(outvec);

    commit_outvec_write(connection, index, out_len, written_len)?;

    Ok(result)
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RawVec {
    pub base: *mut u8,
    pub len: usize,
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn prepare_invec_raw<S: SpmCall>(
    spm: &S,
    msg_handle: ServiceHandle,
    invec_idx: u32,
) -> Result<RawVec, StatusCode> {
    with_validated_connection(spm, msg_handle, |connection| {
        let (_, in_len, base) = prepare_invec(connection, invec_idx)?;
        Ok(RawVec {
            base: base.cast_mut(),
            len: in_len,
        })
    })
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn finish_invec_raw<S: SpmCall>(
    spm: &S,
    msg_handle: ServiceHandle,
    invec_idx: u32,
) -> Result<(), StatusCode> {
    with_validated_connection(spm, msg_handle, |connection| {
        mark_invec_unmapped(connection, invec_idx as usize)
    })
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn prepare_outvec_raw<S: SpmCall>(
    spm: &S,
    msg_handle: ServiceHandle,
    outvec_idx: u32,
) -> Result<RawVec, StatusCode> {
    with_validated_connection(spm, msg_handle, |connection| {
        let (_, out_len, base) = prepare_outvec(connection, outvec_idx)?;
        Ok(RawVec { base, len: out_len })
    })
}

/// # Errors
///
/// See `StatusCode` for error conditions.
pub fn finish_outvec_raw<S: SpmCall>(
    spm: &S,
    msg_handle: ServiceHandle,
    outvec_idx: u32,
    written_len: usize,
) -> Result<(), StatusCode> {
    with_validated_connection(spm, msg_handle, |connection| {
        let index = outvec_idx as usize;
        let out_len = connection
            .msg
            .out_size
            .get(index)
            .map_or(0, |m| m.unwrap_or(0));
        commit_outvec_write(connection, index, out_len, written_len)
    })
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use psa_interface::status::StatusCode;
    use psa_interface::types::{CtrlParam, FFInVec, FFOutVec};

    use super::*;

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

    #[test]
    fn test_validate_invec_payload_single_vec_always_ok() {
        let buf = [0u8; 16];
        let in_vecs = [FFInVec {
            base: buf.as_ptr(),
            len: 16,
        }];
        assert_eq!(validate_invec_payload_nonoverlap(&in_vecs), Ok(()));
    }

    #[test]
    fn test_validate_invec_payload_empty_always_ok() {
        let in_vecs: &[FFInVec] = &[];
        assert_eq!(validate_invec_payload_nonoverlap(in_vecs), Ok(()));
    }

    #[test]
    fn test_validate_invec_adjacent_regions_ok() {
        let buf = [0u8; 30];
        let base = buf.as_ptr();
        let in_vecs = [
            FFInVec { base, len: 10 },
            FFInVec {
                base: unsafe { base.add(10) },
                len: 10,
            },
            FFInVec {
                base: unsafe { base.add(20) },
                len: 10,
            },
        ];
        assert_eq!(validate_invec_payload_nonoverlap(&in_vecs), Ok(()));
    }

    #[test]
    fn test_validate_pointer_range_zero_len() {
        assert_eq!(validate_pointer_range(ptr::null(), 0), Ok(()));
    }

    #[test]
    fn test_validate_pointer_range_null_nonzero_len() {
        assert_eq!(
            validate_pointer_range(ptr::null(), 10),
            Err(StatusCode::ProgrammerError)
        );
    }

    #[test]
    fn test_validate_pointer_range_overflow() {
        let base = usize::MAX as *const u8;
        assert_eq!(
            validate_pointer_range(base, 1),
            Err(StatusCode::ProgrammerError)
        );
    }

    #[test]
    fn test_validate_pointer_range_valid() {
        let buf = [0u8; 32];
        assert_eq!(validate_pointer_range(buf.as_ptr(), 32), Ok(()));
    }

    #[test]
    fn test_validate_call_params_negative_msg_type() {
        // 0xFFFF as u16 → unpack_type() interprets as i16(-1) → i32(-1)
        let param = CtrlParam::new(0xFFFF, 0, false, 0, false);
        assert_eq!(
            validate_call_params(param),
            Err(StatusCode::ProgrammerError)
        );
    }

    #[test]
    fn test_validate_call_params_zero_msg_type_no_iovec() {
        let param = CtrlParam::new(0, 0, false, 0, false);
        assert_eq!(validate_call_params(param), Ok((0, 0, 0)));
    }

    #[test]
    fn test_validate_call_params_boundary_max_iovec() {
        // Exactly at PSA_MAX_IOVEC (4): 2 in + 2 out = 4
        let param = CtrlParam::new(1, 2, false, 2, false);
        assert_eq!(validate_call_params(param), Ok((1, 2, 2)));
    }

    fn make_test_connection(in_len: usize, out_len: usize) -> Connection {
        let msg = PsaMsg::new(ServiceHandle::Crypto, 1, CallerAttributes::NS_UNPRIVILEGED);
        let mut conn = Connection {
            msg,
            invec_base: [ptr::null(); PSA_MAX_IOVEC],
            invec_accessed: [0; PSA_MAX_IOVEC],
            invec_mapped: [false; PSA_MAX_IOVEC],
            invec_unmapped: [false; PSA_MAX_IOVEC],
            outvec_base: [ptr::null_mut(); PSA_MAX_IOVEC],
            outvec_written: [0; PSA_MAX_IOVEC],
            outvec_mapped: [false; PSA_MAX_IOVEC],
            outvec_unmapped: [false; PSA_MAX_IOVEC],
        };
        // Use non-null sentinel addresses for testing (never dereferenced).
        conn.invec_base[0] = 0x1000 as *const u8;
        conn.msg.in_size[0] = MaybeUsize::some(in_len);
        conn.outvec_base[0] = 0x2000 as *mut u8;
        conn.msg.out_size[0] = MaybeUsize::some(out_len);
        conn
    }

    #[test]
    fn test_prepare_invec_valid() {
        let mut conn = make_test_connection(16, 0);
        let result = prepare_invec(&mut conn, 0);
        assert!(result.is_ok());
        let (index, len, base) = result.unwrap();
        assert_eq!(index, 0);
        assert_eq!(len, 16);
        assert!(!base.is_null());
        assert!(conn.invec_mapped[0]);
    }

    #[test]
    fn test_prepare_invec_out_of_bounds() {
        let mut conn = make_test_connection(16, 0);
        assert_eq!(
            prepare_invec(&mut conn, PSA_MAX_IOVEC as u32),
            Err(StatusCode::ProgrammerError)
        );
    }

    #[test]
    fn test_prepare_invec_already_mapped() {
        let mut conn = make_test_connection(16, 0);
        conn.invec_mapped[0] = true;
        assert_eq!(
            prepare_invec(&mut conn, 0),
            Err(StatusCode::ProgrammerError)
        );
    }

    #[test]
    fn test_prepare_invec_already_accessed() {
        let mut conn = make_test_connection(16, 0);
        conn.invec_accessed[0] = 1;
        assert_eq!(
            prepare_invec(&mut conn, 0),
            Err(StatusCode::ProgrammerError)
        );
    }

    #[test]
    fn test_prepare_outvec_valid() {
        let mut conn = make_test_connection(0, 32);
        let result = prepare_outvec(&mut conn, 0);
        assert!(result.is_ok());
        let (index, len, base) = result.unwrap();
        assert_eq!(index, 0);
        assert_eq!(len, 32);
        assert!(!base.is_null());
        assert!(conn.outvec_mapped[0]);
    }

    #[test]
    fn test_prepare_outvec_already_written() {
        let mut conn = make_test_connection(0, 32);
        conn.outvec_written[0] = 1;
        assert_eq!(
            prepare_outvec(&mut conn, 0),
            Err(StatusCode::ProgrammerError)
        );
    }

    #[test]
    fn test_mark_invec_unmapped() {
        let mut conn = make_test_connection(16, 0);
        mark_invec_unmapped(&mut conn, 0).unwrap();
        assert!(conn.invec_unmapped[0]);
    }

    #[test]
    fn test_mark_invec_unmapped_double_returns_error() {
        let mut conn = make_test_connection(16, 0);
        conn.invec_unmapped[0] = true;
        assert_eq!(
            mark_invec_unmapped(&mut conn, 0),
            Err(StatusCode::ProgrammerError)
        );
    }

    #[test]
    fn test_commit_outvec_write_valid() {
        let mut conn = make_test_connection(0, 32);
        assert_eq!(commit_outvec_write(&mut conn, 0, 32, 10), Ok(()));
        assert_eq!(conn.outvec_written[0], 10);
        assert_eq!(conn.msg.out_size[0], MaybeUsize::some(10));
        assert!(conn.outvec_unmapped[0]);
    }

    #[test]
    fn test_commit_outvec_write_overflow_returns_error() {
        let mut conn = make_test_connection(0, 32);
        assert_eq!(
            commit_outvec_write(&mut conn, 0, 32, 33),
            Err(StatusCode::ProgrammerError)
        );
    }

    #[test]
    fn test_commit_outvec_write_already_unmapped_returns_error() {
        let mut conn = make_test_connection(0, 32);
        conn.outvec_unmapped[0] = true;
        assert_eq!(
            commit_outvec_write(&mut conn, 0, 32, 10),
            Err(StatusCode::ProgrammerError)
        );
    }
}
