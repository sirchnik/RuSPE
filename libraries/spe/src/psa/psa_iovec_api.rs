use core::{panic, slice};

use crate::spm::spm::{Connection, PSA_MAX_IOVEC, SpmCall};

use psa_interface::types::PsaHandle;

fn with_connection_for_handle<R>(
    spm: &dyn SpmCall,
    msg_handle: PsaHandle,
    f: impl FnOnce(&mut Connection) -> R,
) -> R {
    let mut result: Option<R> = None;
    let mut f = Some(f);
    spm.with_active_connection_dyn(&mut |connection| {
        if (connection.msg.handle as isize) != (msg_handle as isize) {
            panic!("invalid message handle for active connection");
        }

        if connection.msg.msg_type < 0 {
            panic!("message handle does not refer to a request message");
        }

        let f = f.take().unwrap();
        result = Some(f(connection));
    });

    result.expect("no active SPM connection")
}

fn prepare_invec(connection: &mut Connection, invec_idx: u32) -> (usize, usize, *const u8) {
    let index = invec_idx as usize;
    if index >= PSA_MAX_IOVEC {
        panic!("invec index is out of range");
    }

    let in_len = connection.msg.in_size[index].unwrap_or(0);
    if in_len == 0 {
        panic!("input vector length is zero");
    }

    if connection.invec_mapped[index] {
        panic!("input vector is already mapped");
    }

    if connection.invec_accessed[index] != 0 {
        panic!("input vector was already accessed by read/skip");
    }

    let base = connection.invec_base[index];
    if base.is_null() {
        panic!("input vector base pointer is null");
    }

    connection.invec_mapped[index] = true;

    (index, in_len, base)
}

fn mark_invec_unmapped(connection: &mut Connection, index: usize) {
    if connection.invec_unmapped[index] {
        panic!("input vector is already unmapped");
    }

    connection.invec_unmapped[index] = true;
}

fn prepare_outvec(connection: &mut Connection, outvec_idx: u32) -> (usize, usize, *mut u8) {
    let index = outvec_idx as usize;
    if index >= PSA_MAX_IOVEC {
        panic!("outvec index is out of range");
    }

    let out_len = connection.msg.out_size[index].unwrap_or(0);
    if out_len == 0 {
        panic!("output vector length is zero");
    }

    if connection.outvec_mapped[index] {
        panic!("output vector is already mapped");
    }

    if connection.outvec_written[index] != 0 {
        panic!("output vector was already written");
    }

    let base = connection.outvec_base[index];
    if base.is_null() {
        panic!("output vector base pointer is null");
    }

    connection.outvec_mapped[index] = true;

    (index, out_len, base)
}

fn commit_outvec_write(
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

fn with_mapped_invec<R>(
    connection: &mut Connection,
    invec_idx: u32,
    f: impl FnOnce(&[u8]) -> R,
) -> R {
    let (index, in_len, base) = prepare_invec(connection, invec_idx);

    // ### Safety
    // `base` is checked non-null in `prepare_invec`, and `in_len` is from the
    // SPM-tracked input vector size for this message.
    let invec = unsafe { slice::from_raw_parts(base, in_len) };
    let result = f(invec);

    mark_invec_unmapped(connection, index);

    result
}

fn with_mapped_outvec<R>(
    connection: &mut Connection,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    let (index, out_len, base) = prepare_outvec(connection, outvec_idx);

    // ### Safety
    // `base` is checked non-null in `prepare_outvec`, and `out_len` is from
    // the SPM-tracked output vector size for this message.
    let outvec = unsafe { slice::from_raw_parts_mut(base, out_len) };
    let (result, written_len) = f(outvec);

    commit_outvec_write(connection, index, out_len, written_len);

    result
}

pub fn psa_map_invec<R>(
    spm: &dyn SpmCall,
    msg_handle: PsaHandle,
    invec_idx: u32,
    f: impl FnOnce(&[u8]) -> R,
) -> R {
    with_connection_for_handle(spm, msg_handle, |connection| {
        with_mapped_invec(connection, invec_idx, f)
    })
}

pub fn psa_map_outvec<R>(
    spm: &dyn SpmCall,
    msg_handle: PsaHandle,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    with_connection_for_handle(spm, msg_handle, |connection| {
        with_mapped_outvec(connection, outvec_idx, f)
    })
}

pub fn psa_map_invec_outvec<R>(
    spm: &dyn SpmCall,
    msg_handle: PsaHandle,
    invec_idx: u32,
    outvec_idx: u32,
    f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
) -> R {
    with_connection_for_handle(spm, msg_handle, |connection| {
        let (in_index, in_len, in_base) = prepare_invec(connection, invec_idx);
        let (out_index, out_len, out_base) = prepare_outvec(connection, outvec_idx);

        // ### Safety
        // `in_base` and `out_base` are checked non-null by `prepare_invec` and
        // `prepare_outvec`, and lengths are SPM-tracked vector sizes.
        let invec = unsafe { slice::from_raw_parts(in_base, in_len) };
        // ### Safety
        // See rationale above for output pointer and bounds.
        let outvec = unsafe { slice::from_raw_parts_mut(out_base, out_len) };

        let (result, written_len) = f(invec, outvec);

        commit_outvec_write(connection, out_index, out_len, written_len);
        mark_invec_unmapped(connection, in_index);

        result
    })
}
