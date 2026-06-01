use core::{mem, slice};

use psa_interface::{
    status::StatusCode,
    types::{CtrlParam, FFInVec, FFOutVec, PsaStatus, ServiceHandle},
};

use crate::psa::{psa_api, psa_call, psa_iovec_api::RawVec};

pub const SVC_ELEVATE: u8 = 0;
pub const SVC_PSA_PREPARE_INVEC: u8 = 1;
pub const SVC_PSA_FINISH_INVEC: u8 = 2;
pub const SVC_PSA_PREPARE_OUTVEC: u8 = 3;
pub const SVC_PSA_FINISH_OUTVEC: u8 = 4;
pub const SVC_CALL_UNPRIV: u8 = 5;
pub const SVC_PSA_CALL: u8 = 6;

#[repr(C)]
pub struct SvcStackFrame {
    pub r0: usize,
    pub r1: usize,
    pub r2: usize,
    pub r3: usize,
    pub r12: usize,
    pub lr: usize,
    pub pc: usize,
    pub xpsr: usize,
}

fn service_handle_from_raw(raw: usize) -> Result<ServiceHandle, StatusCode> {
    match raw as u32 {
        x if x == ServiceHandle::InternalTrustedStorageService as u32 => {
            Ok(ServiceHandle::InternalTrustedStorageService)
        }
        x if x == ServiceHandle::Crypto as u32 => Ok(ServiceHandle::Crypto),
        x if x == ServiceHandle::AttestationService as u32 => Ok(ServiceHandle::AttestationService),
        _ => Err(StatusCode::InvalidHandle),
    }
}

fn set_status(frame: &mut SvcStackFrame, status: StatusCode) {
    frame.r0 = (status as PsaStatus) as usize;
}

fn set_success(frame: &mut SvcStackFrame) {
    set_status(frame, StatusCode::_Success);
}

fn set_error(frame: &mut SvcStackFrame, status: StatusCode) {
    frame.r1 = 0;
    frame.r2 = 0;
    frame.r3 = 0;
    set_status(frame, status);
}

fn set_raw_vec(frame: &mut SvcStackFrame, raw: RawVec) {
    frame.r1 = raw.base as usize;
    frame.r2 = raw.len;
    frame.r3 = 0;
    set_success(frame);
}

fn ctrl_param_from_raw(raw: usize) -> CtrlParam {
    unsafe { mem::transmute::<u32, CtrlParam>(raw as u32) }
}

fn handle_svc_with_spm(
    svc_num: u8,
    frame: &mut SvcStackFrame,
    spm: Option<&dyn crate::spm::SpmCall>,
) -> bool {
    let Some(spm) = spm else {
        return match svc_num {
            SVC_PSA_PREPARE_INVEC
            | SVC_PSA_FINISH_INVEC
            | SVC_PSA_PREPARE_OUTVEC
            | SVC_PSA_FINISH_OUTVEC
            | SVC_PSA_CALL => {
                set_error(frame, StatusCode::CommunicationFailure);
                true
            }
            _ => false,
        };
    };

    let handle = match service_handle_from_raw(frame.r0) {
        Ok(handle) => handle,
        Err(status) => {
            set_error(frame, status);
            return true;
        }
    };

    match svc_num {
        SVC_PSA_PREPARE_INVEC => {
            match crate::psa::psa_iovec_api::psa_prepare_invec(spm, handle, frame.r1 as u32) {
                Ok(raw) => set_raw_vec(frame, raw),
                Err(status) => set_error(frame, status),
            }
        }
        SVC_PSA_FINISH_INVEC => {
            match crate::psa::psa_iovec_api::psa_finish_invec(spm, handle, frame.r1 as u32) {
                Ok(()) => set_success(frame),
                Err(status) => set_error(frame, status),
            }
        }
        SVC_PSA_PREPARE_OUTVEC => {
            match crate::psa::psa_iovec_api::psa_prepare_outvec(spm, handle, frame.r1 as u32) {
                Ok(raw) => set_raw_vec(frame, raw),
                Err(status) => set_error(frame, status),
            }
        }
        SVC_PSA_FINISH_OUTVEC => {
            match crate::psa::psa_iovec_api::psa_finish_outvec(
                spm,
                handle,
                frame.r1 as u32,
                frame.r2,
            ) {
                Ok(()) => set_success(frame),
                Err(status) => set_error(frame, status),
            }
        }
        SVC_PSA_CALL => {
            let result = unsafe {
                psa_call::psa_call(
                    handle,
                    ctrl_param_from_raw(frame.r1),
                    frame.r2 as *const FFInVec,
                    frame.r3 as *mut FFOutVec,
                    spm,
                    psa_call::CallerAttributes::SECURE_UNPRIVILEGED,
                )
            };

            match result {
                Ok(()) => set_success(frame),
                Err(status) => set_error(frame, status),
            }
        }
        _ => return false,
    }

    true
}

pub fn handle_svc(svc_num: u8, frame: &mut SvcStackFrame) -> bool {
    handle_svc_with_spm(svc_num, frame, psa_api::try_get_spm())
}

fn status_from_raw(raw: usize) -> Result<(), StatusCode> {
    match StatusCode::try_from(raw as PsaStatus) {
        Ok(StatusCode::_Success) => Ok(()),
        Ok(status) => Err(status),
        Err(_) => Err(StatusCode::CommunicationFailure),
    }
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[inline(always)]
unsafe fn svc_call<const SVC_NUM: u8>(
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> (usize, usize, usize, usize) {
    use core::arch::asm;
    use cortexm33::support;

    let out0: usize;
    let out1: usize;
    let out2: usize;
    let out3: usize;

    support::dmb();
    unsafe {
        asm!(
            "svc {svc_num}",
            svc_num = const SVC_NUM,
            inlateout("r0") arg0 => out0,
            inlateout("r1") arg1 => out1,
            inlateout("r2") arg2 => out2,
            inlateout("r3") arg3 => out3,
            lateout("r12") _,
            options(nostack),
        );
    }
    support::dmb();

    (out0, out1, out2, out3)
}

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
unsafe fn svc_call<const SVC_NUM: u8>(
    _: usize,
    _: usize,
    _: usize,
    _: usize,
) -> (usize, usize, usize, usize) {
    let _ = SVC_NUM;
    panic!("SVC PSA bridge is only available on ARM bare-metal targets")
}

pub unsafe fn psa_call(
    handle: ServiceHandle,
    ctrl_param: CtrlParam,
    in_vec: *const FFInVec,
    out_vec: *mut FFOutVec,
) -> Result<(), StatusCode> {
    let (status, _, _, _) = unsafe {
        svc_call::<SVC_PSA_CALL>(
            handle as usize,
            mem::transmute::<CtrlParam, u32>(ctrl_param) as usize,
            in_vec as usize,
            out_vec as usize,
        )
    };
    status_from_raw(status)
}

pub fn psa_map_invec<R>(
    msg_handle: ServiceHandle,
    invec_idx: u32,
    f: impl FnOnce(&[u8]) -> R,
) -> R {
    let (status, base, len, _) = unsafe {
        svc_call::<SVC_PSA_PREPARE_INVEC>(msg_handle as usize, invec_idx as usize, 0, 0)
    };
    status_from_raw(status).unwrap_or_else(|err| panic!("failed to map input vector: {:?}", err));

    let invec = if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(base as *const u8, len) }
    };
    let result = f(invec);

    let (status, _, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_INVEC>(msg_handle as usize, invec_idx as usize, 0, 0)
    };
    status_from_raw(status).unwrap_or_else(|err| panic!("failed to unmap input vector: {:?}", err));

    result
}

pub fn psa_map_outvec<R>(
    msg_handle: ServiceHandle,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    let (status, base, len, _) = unsafe {
        svc_call::<SVC_PSA_PREPARE_OUTVEC>(msg_handle as usize, outvec_idx as usize, 0, 0)
    };
    status_from_raw(status).unwrap_or_else(|err| panic!("failed to map output vector: {:?}", err));

    let outvec = if len == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(base as *mut u8, len) }
    };
    let (result, written_len) = f(outvec);

    let (status, _, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_OUTVEC>(msg_handle as usize, outvec_idx as usize, written_len, 0)
    };
    status_from_raw(status)
        .unwrap_or_else(|err| panic!("failed to commit output vector: {:?}", err));

    result
}

pub fn psa_map_invec_outvec<R>(
    msg_handle: ServiceHandle,
    invec_idx: u32,
    outvec_idx: u32,
    f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
) -> R {
    let (in_status, in_base, in_len, _) = unsafe {
        svc_call::<SVC_PSA_PREPARE_INVEC>(msg_handle as usize, invec_idx as usize, 0, 0)
    };
    status_from_raw(in_status)
        .unwrap_or_else(|err| panic!("failed to map input vector: {:?}", err));

    let (out_status, out_base, out_len, _) = unsafe {
        svc_call::<SVC_PSA_PREPARE_OUTVEC>(msg_handle as usize, outvec_idx as usize, 0, 0)
    };
    status_from_raw(out_status)
        .unwrap_or_else(|err| panic!("failed to map output vector: {:?}", err));

    let invec = if in_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(in_base as *const u8, in_len) }
    };
    let outvec = if out_len == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(out_base as *mut u8, out_len) }
    };

    let (result, written_len) = f(invec, outvec);

    let (out_status, _, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_OUTVEC>(msg_handle as usize, outvec_idx as usize, written_len, 0)
    };
    status_from_raw(out_status)
        .unwrap_or_else(|err| panic!("failed to commit output vector: {:?}", err));

    let (in_status, _, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_INVEC>(msg_handle as usize, invec_idx as usize, 0, 0)
    };
    status_from_raw(in_status)
        .unwrap_or_else(|err| panic!("failed to unmap input vector: {:?}", err));

    result
}

pub fn psa_read(
    msg_handle: ServiceHandle,
    invec_idx: u32,
    buffer: &mut [u8],
) -> Result<usize, StatusCode> {
    let (status, base, len, _) = unsafe {
        svc_call::<SVC_PSA_PREPARE_INVEC>(msg_handle as usize, invec_idx as usize, 0, 0)
    };
    let result = (|| {
        status_from_raw(status)?;

        if len > buffer.len() {
            return Err(StatusCode::BufferTooSmall);
        }

        if len != 0 {
            let invec = unsafe { slice::from_raw_parts(base as *const u8, len) };
            buffer[..len].copy_from_slice(invec);
        }

        Ok(len)
    })();

    let (finish_status, _, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_INVEC>(msg_handle as usize, invec_idx as usize, 0, 0)
    };
    status_from_raw(finish_status)?;

    result
}

pub fn psa_write(
    msg_handle: ServiceHandle,
    outvec_idx: u32,
    buffer: &[u8],
) -> Result<usize, StatusCode> {
    let (status, base, len, _) = unsafe {
        svc_call::<SVC_PSA_PREPARE_OUTVEC>(msg_handle as usize, outvec_idx as usize, 0, 0)
    };
    status_from_raw(status)?;

    let (result, written_len) = if len < buffer.len() {
        if len != 0 {
            unsafe { slice::from_raw_parts_mut(base as *mut u8, len) }.fill(0);
        }
        (Err(StatusCode::BufferTooSmall), 0)
    } else {
        if !buffer.is_empty() {
            let outvec = unsafe { slice::from_raw_parts_mut(base as *mut u8, len) };
            outvec[..buffer.len()].copy_from_slice(buffer);
        }
        // TODO: Decide whether service-side copy APIs should support TF-M-style
        // partial reads/writes or keep the current strict full-fit behavior.
        (Ok(buffer.len()), buffer.len())
    };

    let (finish_status, _, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_OUTVEC>(msg_handle as usize, outvec_idx as usize, written_len, 0)
    };
    status_from_raw(finish_status)?;

    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{
        psa::psa_call::{CallerAttributes, PsaMsg},
        spm::{Connection, SpmCall, SpmError},
    };
    use core::ptr;
    use std::sync::{Mutex, Once};

    struct TestSpmState {
        call_result: Result<(), crate::StatusCode>,
        last_connection: Option<Connection>,
    }

    struct TestSpm {
        state: Mutex<TestSpmState>,
    }

    impl TestSpm {
        const fn new() -> Self {
            Self {
                state: Mutex::new(TestSpmState {
                    call_result: Ok(()),
                    last_connection: None,
                }),
            }
        }

        fn reset(&self, call_result: Result<(), crate::StatusCode>) {
            let mut state = self.state.lock().unwrap();
            state.call_result = call_result;
            state.last_connection = None;
        }

        fn last_connection(&self) -> Option<Connection> {
            self.state.lock().unwrap().last_connection
        }
    }

    impl SpmCall for TestSpm {
        fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
            let mut state = self.state.lock().unwrap();
            state.last_connection = Some(connection);
            state.call_result
        }

        fn with_active_connection(
            &self,
            _f: &mut dyn FnMut(&mut Connection),
        ) -> Result<(), SpmError> {
            Err(SpmError::NoActiveConnection)
        }

        fn has_real_permission(
            &self,
            _base: *const u8,
            _len: usize,
            _is_write: bool,
            _caller: CallerAttributes,
        ) -> bool {
            true
        }
    }

    static TEST_SPM: TestSpm = TestSpm::new();
    static INSTALL_SPM: Once = Once::new();

    fn install_test_spm() {
        INSTALL_SPM.call_once(|| psa_api::set_spm(&TEST_SPM));
    }

    fn ctrl_param_bits(ctrl_param: CtrlParam) -> usize {
        unsafe { mem::transmute::<CtrlParam, u32>(ctrl_param) as usize }
    }

    fn empty_connection() -> Connection {
        Connection {
            msg: PsaMsg {
                handle: ServiceHandle::Crypto,
                msg_type: 1,
                caller: CallerAttributes::SECURE_UNPRIVILEGED,
                in_size: [None; crate::spm::PSA_MAX_IOVEC],
                out_size: [None; crate::spm::PSA_MAX_IOVEC],
            },
            invec_base: [ptr::null(); crate::spm::PSA_MAX_IOVEC],
            invec_accessed: [0; crate::spm::PSA_MAX_IOVEC],
            invec_mapped: [false; crate::spm::PSA_MAX_IOVEC],
            invec_unmapped: [false; crate::spm::PSA_MAX_IOVEC],
            outvec_base: [ptr::null_mut(); crate::spm::PSA_MAX_IOVEC],
            outvec_written: [0; crate::spm::PSA_MAX_IOVEC],
            outvec_mapped: [false; crate::spm::PSA_MAX_IOVEC],
            outvec_unmapped: [false; crate::spm::PSA_MAX_IOVEC],
        }
    }

    #[test]
    fn handle_svc_psa_call_dispatches_secure_unprivileged_connection() {
        install_test_spm();
        TEST_SPM.reset(Ok(()));

        let input = [0x11u8, 0x22];
        let mut output = [0u8; 4];
        let in_vec = [FFInVec {
            base: input.as_ptr(),
            len: input.len(),
        }];
        let mut out_vec = [FFOutVec {
            base: output.as_mut_ptr(),
            len: output.len(),
        }];
        let mut frame = SvcStackFrame {
            r0: ServiceHandle::Crypto as usize,
            r1: ctrl_param_bits(CtrlParam::new(7, 1, false, 1, false)),
            r2: in_vec.as_ptr() as usize,
            r3: out_vec.as_mut_ptr() as usize,
            r12: 0,
            lr: 0,
            pc: 0,
            xpsr: 0,
        };

        assert!(handle_svc(SVC_PSA_CALL, &mut frame));
        assert_eq!(frame.r0, StatusCode::_Success as PsaStatus as usize);

        let connection = TEST_SPM.last_connection().unwrap_or_else(empty_connection);
        assert_eq!(connection.msg.handle as u32, ServiceHandle::Crypto as u32);
        assert_eq!(connection.msg.msg_type, 7);
        assert_eq!(connection.msg.caller, CallerAttributes::SECURE_UNPRIVILEGED);
        assert_eq!(connection.msg.in_size[0], Some(input.len()));
        assert_eq!(connection.msg.out_size[0], Some(output.len()));
        assert_eq!(connection.invec_base[0], input.as_ptr());
        assert_eq!(connection.outvec_base[0], output.as_mut_ptr());
    }

    #[test]
    fn handle_svc_psa_call_propagates_status_code() {
        install_test_spm();
        TEST_SPM.reset(Err(StatusCode::BufferTooSmall));

        let mut frame = SvcStackFrame {
            r0: ServiceHandle::Crypto as usize,
            r1: ctrl_param_bits(CtrlParam::new(1, 0, false, 0, false)),
            r2: ptr::null::<FFInVec>() as usize,
            r3: ptr::null_mut::<FFOutVec>() as usize,
            r12: 0,
            lr: 0,
            pc: 0,
            xpsr: 0,
        };

        assert!(handle_svc(SVC_PSA_CALL, &mut frame));
        assert_eq!(frame.r0, StatusCode::BufferTooSmall as PsaStatus as usize);
    }

    #[test]
    fn handle_svc_psa_call_rejects_invalid_handle() {
        install_test_spm();
        TEST_SPM.reset(Ok(()));

        let mut frame = SvcStackFrame {
            r0: 0xDEAD_BEEFu32 as usize,
            r1: ctrl_param_bits(CtrlParam::new(1, 0, false, 0, false)),
            r2: 0,
            r3: 0,
            r12: 0,
            lr: 0,
            pc: 0,
            xpsr: 0,
        };

        assert!(handle_svc(SVC_PSA_CALL, &mut frame));
        assert_eq!(frame.r0, StatusCode::InvalidHandle as PsaStatus as usize);
        assert!(TEST_SPM.last_connection().is_none());
    }

    #[test]
    fn handle_svc_psa_call_requires_spm() {
        let mut frame = SvcStackFrame {
            r0: ServiceHandle::Crypto as usize,
            r1: ctrl_param_bits(CtrlParam::new(1, 0, false, 0, false)),
            r2: 0,
            r3: 0,
            r12: 0,
            lr: 0,
            pc: 0,
            xpsr: 0,
        };

        assert!(handle_svc_with_spm(SVC_PSA_CALL, &mut frame, None));
        assert_eq!(frame.r0, StatusCode::CommunicationFailure as PsaStatus as usize);
    }
}
