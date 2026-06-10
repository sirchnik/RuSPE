use core::{panic, slice};

use crate::spm::spm::{Connection, PSA_MAX_IOVEC, SpmCall, SpmError};

use crate::psa::psa_call::CallerAttributes;
use psa_interface::types::ServiceHandle;

fn validate_pointer_range(base: *const u8, len: usize, vector_kind: &str) {
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

fn validate_real_permission(
    spm: &dyn SpmCall,
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

fn with_connection_for_handle<R>(
    spm: &dyn SpmCall,
    msg_handle: ServiceHandle,
    f: impl FnOnce(&mut Connection) -> R,
) -> R {
    let mut result: Option<R> = None;
    let mut f = Some(f);
    match spm.with_active_connection(&mut |connection| {
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

fn prepare_invec(
    spm: &dyn SpmCall,
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
    validate_real_permission(spm, base, in_len, "input vector", false, connection.msg.caller);

    connection.invec_mapped[index] = true;

    (index, in_len, base)
}

fn mark_invec_unmapped(connection: &mut Connection, index: usize) {
    if connection.invec_unmapped[index] {
        panic!("input vector is already unmapped");
    }

    connection.invec_unmapped[index] = true;
}

fn prepare_outvec(
    spm: &dyn SpmCall,
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
    spm: &dyn SpmCall,
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

fn with_mapped_outvec<R>(
    spm: &dyn SpmCall,
    connection: &mut Connection,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    let (index, out_len, base) = prepare_outvec(spm, connection, outvec_idx);

    let outvec = if out_len == 0 {
        &mut []
    } else {
        // # Safety:
        // `base` is checked non-null in `prepare_outvec`, and `out_len` is from
        // the SPM-tracked output vector size for this message.
        unsafe { slice::from_raw_parts_mut(base, out_len) }
    };
    let (result, written_len) = f(outvec);

    commit_outvec_write(connection, index, out_len, written_len);

    result
}

pub fn psa_map_invec<R>(
    spm: &dyn SpmCall,
    msg_handle: ServiceHandle,
    invec_idx: u32,
    f: impl FnOnce(&[u8]) -> R,
) -> R {
    with_connection_for_handle(spm, msg_handle, |connection| {
        with_mapped_invec(spm, connection, invec_idx, f)
    })
}

pub fn psa_map_outvec<R>(
    spm: &dyn SpmCall,
    msg_handle: ServiceHandle,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    with_connection_for_handle(spm, msg_handle, |connection| {
        with_mapped_outvec(spm, connection, outvec_idx, f)
    })
}

pub fn psa_map_invec_outvec<R>(
    spm: &dyn SpmCall,
    msg_handle: ServiceHandle,
    invec_idx: u32,
    outvec_idx: u32,
    f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
) -> R {
    with_connection_for_handle(spm, msg_handle, |connection| {
        let (in_index, in_len, in_base) = prepare_invec(spm, connection, invec_idx);
        let (out_index, out_len, out_base) = prepare_outvec(spm, connection, outvec_idx);

        let invec = if in_len == 0 {
            &[]
        } else {
            // # Safety:
            // `in_base` is checked non-null by `prepare_invec`, and `in_len` is
            // an SPM-tracked vector size for this message.
            unsafe { slice::from_raw_parts(in_base, in_len) }
        };
        let outvec = if out_len == 0 {
            &mut []
        } else {
            // # Safety:
            // `out_base` is checked non-null by `prepare_outvec`, and `out_len` is
            // an SPM-tracked vector size for this message.
            unsafe { slice::from_raw_parts_mut(out_base, out_len) }
        };

        let (result, written_len) = f(invec, outvec);

        commit_outvec_write(connection, out_index, out_len, written_len);
        mark_invec_unmapped(connection, in_index);

        result
    })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{psa::psa_call::{CallerAttributes, PsaMsg}, spm::spm::SpmError};
    use core::{cell::RefCell, ptr};

    struct TestSpm {
        connection: RefCell<Connection>,
        allow_read: bool,
        allow_write: bool,
    }

    unsafe impl Sync for TestSpm {}

    impl SpmCall for TestSpm {
        fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
            let _ = connection;
            Ok(())
        }

        fn with_active_connection(
            &self,
            f: &mut dyn FnMut(&mut Connection),
        ) -> Result<(), SpmError> {
            let mut connection = self.connection.borrow_mut();
            f(&mut connection);
            Ok(())
        }

        fn has_real_permission(
            &self,
            _base: *const u8,
            _len: usize,
            is_write: bool,
            _caller: CallerAttributes,
        ) -> bool {
            if is_write {
                self.allow_write
            } else {
                self.allow_read
            }
        }
    }

    fn make_connection(
        in_base: *const u8,
        in_len: usize,
        out_base: *mut u8,
        out_len: usize,
    ) -> Connection {
        Connection {
            msg: PsaMsg {
                handle: ServiceHandle::Crypto,
                msg_type: 1,
                caller: CallerAttributes::NS_UNPRIVILEGED,
                in_size: [Some(in_len), None, None, None],
                out_size: [Some(out_len), None, None, None],
            },
            invec_base: [in_base, ptr::null(), ptr::null(), ptr::null()],
            invec_accessed: [0; PSA_MAX_IOVEC],
            invec_mapped: [false; PSA_MAX_IOVEC],
            invec_unmapped: [false; PSA_MAX_IOVEC],
            outvec_base: [out_base, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()],
            outvec_written: [0; PSA_MAX_IOVEC],
            outvec_mapped: [false; PSA_MAX_IOVEC],
            outvec_unmapped: [false; PSA_MAX_IOVEC],
        }
    }

    fn make_test_spm(connection: Connection, allow_read: bool, allow_write: bool) -> TestSpm {
        TestSpm {
            connection: RefCell::new(connection),
            allow_read,
            allow_write,
        }
    }

    #[test]
    fn zero_length_vectors_allow_null_bases() {
        let spm = make_test_spm(
            make_connection(ptr::null(), 0, ptr::null_mut(), 0),
            true,
            true,
        );

        let in_result = psa_map_invec(&spm, ServiceHandle::Crypto, 0, |buf| {
            assert!(buf.is_empty());
            buf.len()
        });
        assert_eq!(in_result, 0);

        let out_result = psa_map_outvec(&spm, ServiceHandle::Crypto, 0, |buf| {
            assert!(buf.is_empty());
            (buf.len(), buf.len())
        });
        assert_eq!(out_result, 0);
    }

    #[test]
    #[should_panic(expected = "input vector base pointer is null")]
    fn nonzero_input_vector_rejects_null_base() {
        let spm = make_test_spm(
            make_connection(ptr::null(), 1, ptr::null_mut(), 0),
            true,
            true,
        );

        let _ = psa_map_invec(&spm, ServiceHandle::Crypto, 0, |_| ());
    }

    #[test]
    #[should_panic(expected = "output vector base pointer is null")]
    fn nonzero_output_vector_rejects_null_base() {
        let spm = make_test_spm(
            make_connection(ptr::null(), 0, ptr::null_mut(), 1),
            true,
            true,
        );

        let _ = psa_map_outvec(&spm, ServiceHandle::Crypto, 0, |_| ((), 0));
    }

    #[test]
    #[should_panic(expected = "input vector range overflows pointer space")]
    fn nonzero_input_vector_rejects_overflowing_range() {
        let spm = make_test_spm(
            make_connection(usize::MAX as *const u8, 1, ptr::null_mut(), 0),
            true,
            true,
        );

        let _ = psa_map_invec(&spm, ServiceHandle::Crypto, 0, |_| ());
    }

    #[test]
    #[should_panic(expected = "output vector range overflows pointer space")]
    fn nonzero_output_vector_rejects_overflowing_range() {
        let spm = make_test_spm(
            make_connection(ptr::null(), 0, usize::MAX as *mut u8, 1),
            true,
            true,
        );

        let _ = psa_map_outvec(&spm, ServiceHandle::Crypto, 0, |_| ((), 0));
    }

    #[test]
    #[should_panic(expected = "input vector is not permitted by real memory access control")]
    fn nonzero_input_vector_rejects_permission_failure() {
        let spm = make_test_spm(
            make_connection(0x2400_4000 as *const u8, 1, ptr::null_mut(), 0),
            false,
            true,
        );

        let _ = psa_map_invec(&spm, ServiceHandle::Crypto, 0, |_| ());
    }

    #[test]
    #[should_panic(expected = "output vector is not permitted by real memory access control")]
    fn nonzero_output_vector_rejects_permission_failure() {
        let spm = make_test_spm(
            make_connection(ptr::null(), 0, 0x2400_4000 as *mut u8, 1),
            true,
            false,
        );

        let _ = psa_map_outvec(&spm, ServiceHandle::Crypto, 0, |_| ((), 0));
    }
}
