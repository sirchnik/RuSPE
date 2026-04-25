use core::{panic, slice};

use crate::{
    psa::psa_api,
    spm::spm::{Connection, PSA_MAX_IOVEC},
};

use psa_interface::PsaHandle;

fn with_connection_for_handle<R>(msg_handle: PsaHandle, f: impl FnOnce(&mut Connection) -> R) -> R {
    let spm = psa_api::get_spm();

    let Some(result) = spm.with_active_connection(|connection| {
        if (connection.msg.handle as isize) != (msg_handle as isize) {
            panic!("invalid message handle for active connection");
        }

        if connection.msg.msg_type < 0 {
            panic!("message handle does not refer to a request message");
        }

        f(connection)
    }) else {
        panic!("no active SPM connection");
    };

    result
}

pub fn psa_map_invec<R>(msg_handle: PsaHandle, invec_idx: u32, f: impl FnOnce(&[u8]) -> R) -> R {
    with_connection_for_handle(msg_handle, |connection| {
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

        if connection.invec_base[index].is_null() {
            panic!("input vector base pointer is null");
        }

        connection.invec_mapped[index] = true;

        // ### Safety
        // `invec_base[index]` is checked non-null above. `in_len` comes from the
        // SPM-tracked input vector size for this message and is the exact number
        // of readable bytes associated with this pointer.
        let invec = unsafe { slice::from_raw_parts(connection.invec_base[index], in_len) };
        let result = f(invec);

        if connection.invec_unmapped[index] {
            panic!("input vector is already unmapped");
        }

        connection.invec_unmapped[index] = true;

        result
    })
}

pub fn psa_map_outvec<R>(
    msg_handle: PsaHandle,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    with_connection_for_handle(msg_handle, |connection| {
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

        if connection.outvec_base[index].is_null() {
            panic!("output vector base pointer is null");
        }

        connection.outvec_mapped[index] = true;

        // ### Safety
        // `outvec_base[index]` is checked non-null above. `out_len` comes from
        // the SPM-tracked output vector size for this message and is the exact
        // writable extent associated with this pointer.
        let outvec = unsafe { slice::from_raw_parts_mut(connection.outvec_base[index], out_len) };
        let (result, written_len) = f(outvec);

        if connection.outvec_unmapped[index] {
            panic!("output vector is already unmapped");
        }

        if written_len > out_len {
            panic!("written length exceeds output vector capacity");
        }

        connection.outvec_written[index] = written_len;
        connection.msg.out_size[index] = Some(written_len);
        connection.outvec_unmapped[index] = true;

        result
    })
}
