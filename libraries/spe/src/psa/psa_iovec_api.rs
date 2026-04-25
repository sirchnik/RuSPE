use core::panic;

use crate::{
    psa::psa_api,
    spm::spm::{Connection, PSA_MAX_IOVEC},
};

use psa_interface::PsaHandle;

#[derive(Clone, Copy, Debug)]
pub struct MappedInVec {
    pub base: *const u8,
    pub len: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct MappedOutVec {
    pub base: *mut u8,
    pub len: usize,
}

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

pub fn psa_map_invec(msg_handle: PsaHandle, invec_idx: u32) -> MappedInVec {
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

        MappedInVec {
            base: connection.invec_base[index],
            len: in_len,
        }
    })
}

pub fn psa_unmap_invec(msg_handle: PsaHandle, invec_idx: u32) {
    with_connection_for_handle(msg_handle, |connection| {
        let index = invec_idx as usize;
        if index >= PSA_MAX_IOVEC {
            panic!("invec index is out of range");
        }

        if !connection.invec_mapped[index] {
            panic!("input vector has not been mapped");
        }

        if connection.invec_unmapped[index] {
            panic!("input vector is already unmapped");
        }

        connection.invec_unmapped[index] = true;
    });
}

pub fn psa_map_outvec(msg_handle: PsaHandle, outvec_idx: u32) -> MappedOutVec {
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

        MappedOutVec {
            base: connection.outvec_base[index],
            len: out_len,
        }
    })
}

pub fn psa_unmap_outvec(msg_handle: PsaHandle, outvec_idx: u32, written_len: usize) {
    with_connection_for_handle(msg_handle, |connection| {
        let index = outvec_idx as usize;
        if index >= PSA_MAX_IOVEC {
            panic!("outvec index is out of range");
        }

        if !connection.outvec_mapped[index] {
            panic!("output vector has not been mapped");
        }

        if connection.outvec_unmapped[index] {
            panic!("output vector is already unmapped");
        }

        let capacity = connection.msg.out_size[index].unwrap_or(0);
        if written_len > capacity {
            panic!("written length exceeds output vector capacity");
        }

        connection.outvec_written[index] = written_len;
        connection.msg.out_size[index] = Some(written_len);
        connection.outvec_unmapped[index] = true;
    });
}
