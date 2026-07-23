// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use core::{mem, slice};

use psa_interface::PsaApiCallInterface;
use psa_interface::status::{StatusCode, into_psa_status};
use psa_interface::types::{
    CtrlParam, FFInVec, FFOutVec, PSA_FRAMEWORK_VERSION, PsaStatus, ServiceHandle,
};

use crate::spm::spm::SpmCall;
use crate::spm_api::{
    CallerAttributes, RawVec, SpmApi, finish_invec_raw, finish_outvec_raw, prepare_invec_raw,
    prepare_outvec_raw,
};
pub const SVC_PROCESS_EXIT: u8 = 0;
pub const SVC_PSA_ACCESS_VEC: u8 = 1;
pub const SVC_PSA_RELEASE_VEC: u8 = 2;
pub const SVC_START_PROCESS: u8 = 3;
pub const SVC_PSA_CALL: u8 = 4;
pub const SVC_PSA_VERSION: u8 = 5;
pub const SVC_PSA_CALL_RETURN: u8 = 7;

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

const fn service_handle_from_raw(raw: usize) -> Result<ServiceHandle, StatusCode> {
    match raw as u32 {
        x if x == ServiceHandle::InternalTrustedStorageService as u32 => {
            Ok(ServiceHandle::InternalTrustedStorageService)
        }
        x if x == ServiceHandle::Crypto as u32 => Ok(ServiceHandle::Crypto),
        x if x == ServiceHandle::AttestationService as u32 => Ok(ServiceHandle::AttestationService),
        _ => Err(StatusCode::InvalidHandle),
    }
}

const fn set_status(frame: &mut SvcStackFrame, status: StatusCode) {
    frame.r0 = (status as PsaStatus).cast_unsigned();
}

const fn set_success(frame: &mut SvcStackFrame) {
    set_status(frame, StatusCode::_Success);
}

const fn set_error(frame: &mut SvcStackFrame, status: StatusCode) {
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
    // SAFETY: Transmuting a u32 from the register frame into CtrlParam is safe
    // because CtrlParam is a repr(transparent) or repr(C) representation of u32
    // parameters.
    unsafe { mem::transmute::<u32, CtrlParam>(raw as u32) }
}

pub fn handle_svc_with_spm<S: SpmCall, A: SpmApi>(
    svc_num: u8,
    frame: &mut SvcStackFrame,
    spm: &S,
    sfn_api: &A,
) -> bool {
    let handle = match service_handle_from_raw(frame.r0) {
        Ok(handle) => handle,
        Err(status) => {
            set_error(frame, status);
            return true;
        }
    };

    match svc_num {
        SVC_PSA_ACCESS_VEC => {
            let is_outvec = frame.r2 != 0;
            let result = if is_outvec {
                prepare_outvec_raw(spm, handle, frame.r1 as u32)
            } else {
                prepare_invec_raw(spm, handle, frame.r1 as u32)
            };
            match result {
                Ok(raw) => {
                    spm.map_vec(is_outvec, frame.r1 as u32, raw.base, raw.len);
                    set_raw_vec(frame, raw);
                }
                Err(status) => set_error(frame, status),
            }
        }
        SVC_PSA_RELEASE_VEC => {
            let is_outvec = frame.r2 != 0;
            let result = if is_outvec {
                finish_outvec_raw(spm, handle, frame.r1 as u32, frame.r3)
            } else {
                finish_invec_raw(spm, handle, frame.r1 as u32)
            };
            match result {
                Ok(()) => {
                    spm.unmap_vec(is_outvec, frame.r1 as u32);
                    set_success(frame);
                }
                Err(status) => set_error(frame, status),
            }
        }
        SVC_PSA_CALL => {
            // SAFETY: The raw pointers for in_vec and out_vec inside the stack frame are
            // verified and processed by the SFN api handler within proper
            // memory bounds.
            let result = unsafe {
                sfn_api.call(
                    handle,
                    ctrl_param_from_raw(frame.r1),
                    frame.r2 as *const FFInVec,
                    frame.r3 as *mut FFOutVec,
                    CallerAttributes::SECURE_UNPRIVILEGED,
                )
            };

            match result {
                Ok(()) => set_success(frame),
                Err(status) => set_error(frame, status),
            }
        }
        SVC_PSA_VERSION => {
            frame.r0 = spm.version(handle).unwrap_or(0) as usize;
        }
        _ => return false,
    }

    true
}

/// Interpret a raw register value as a PSA status code, returning `Ok(())`
/// on success or the corresponding `StatusCode` error.
fn check_svc_result(raw: usize) -> Result<(), StatusCode> {
    let status_val = PsaStatus::from_ne_bytes(raw.to_ne_bytes());
    match StatusCode::try_from(status_val) {
        Ok(StatusCode::_Success) => Ok(()),
        Ok(status) => Err(status),
        Err(_) => Err(StatusCode::CommunicationFailure),
    }
}

/// Issue an `ACCESS_VEC` SVC and return the input vector as a read-only slice.
///
/// # Safety
/// The SPM guarantees the returned pointer/length describe valid readable memory.
unsafe fn svc_access_invec(handle: usize, idx: usize) -> Result<&'static [u8], StatusCode> {
    // SAFETY: The SVC transfers control to the SPM which validates arguments.
    let (status, base, len, _) = unsafe { svc_call::<SVC_PSA_ACCESS_VEC>(handle, idx, 0, 0) };
    check_svc_result(status)?;
    if len == 0 {
        Ok(&[])
    } else {
        // SAFETY: The SPM guarantees base/len describe valid readable memory.
        Ok(unsafe { slice::from_raw_parts(base as *const u8, len) })
    }
}

/// Issue an `ACCESS_VEC` SVC and return the output vector as a mutable slice.
///
/// # Safety
/// The SPM guarantees the returned pointer/length describe valid writable memory.
unsafe fn svc_access_outvec(handle: usize, idx: usize) -> Result<&'static mut [u8], StatusCode> {
    // SAFETY: The SVC transfers control to the SPM which validates arguments.
    let (status, base, len, _) = unsafe { svc_call::<SVC_PSA_ACCESS_VEC>(handle, idx, 1, 0) };
    check_svc_result(status)?;
    if len == 0 {
        Ok(&mut [])
    } else {
        // SAFETY: The SPM guarantees base/len describe valid writable memory.
        Ok(unsafe { slice::from_raw_parts_mut(base as *mut u8, len) })
    }
}

/// Issue a `RELEASE_VEC` SVC for an input vector.
fn svc_release_invec(handle: usize, idx: usize) -> Result<(), StatusCode> {
    // SAFETY: Releasing a previously accessed input vector ends the access.
    let (status, _, _, _) = unsafe { svc_call::<SVC_PSA_RELEASE_VEC>(handle, idx, 0, 0) };
    check_svc_result(status)
}

/// Issue a `RELEASE_VEC` SVC for an output vector, committing `written_len` bytes.
fn svc_release_outvec(handle: usize, idx: usize, written_len: usize) -> Result<(), StatusCode> {
    // SAFETY: Releasing a previously accessed output vector commits the written data.
    let (status, _, _, _) = unsafe { svc_call::<SVC_PSA_RELEASE_VEC>(handle, idx, 1, written_len) };
    check_svc_result(status)
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

    let out0: usize;
    let out1: usize;
    let out2: usize;
    let out3: usize;

    // SAFETY: Executing the supervisor call (SVC) is safe because it only transfers
    // control to the secure handler with the specified arguments in registers.
    unsafe {
        asm!("dmb sy", options(nostack, preserves_flags));
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
        asm!("dmb sy", options(nostack, preserves_flags));
    }

    (out0, out1, out2, out3)
}

/// Exit the service process and return `status` to the caller.
///
/// This function encapsulates the `svc {SVC_PROCESS_EXIT}` instruction so
/// callers in service code don't need to use inline assembly themselves.
#[cfg(all(target_arch = "arm", target_os = "none"))]
pub fn process_exit(status: PsaStatus) -> ! {
    use core::arch::asm;

    // SAFETY: Exiting the process by issuing an SVC call is safe because it never
    // returns and terminates the current execution context.
    unsafe {
        asm!(
            "svc {SVC_PROCESS_EXIT}",
            SVC_PROCESS_EXIT = const SVC_PROCESS_EXIT,
            in("r0") status,
            options(noreturn),
        )
    }
}

/// # Panics
///
/// Panics on invalid state.
#[cfg(not(all(target_arch = "arm", target_os = "none")))]
pub fn process_exit(_status: PsaStatus) -> ! {
    panic!("process_exit is only available on ARM bare-metal targets");
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

pub struct SvcApi;
impl SpmApi for SvcApi {
    fn access_invec<R>(
        &self,
        msg_handle: ServiceHandle,
        invec_idx: u32,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, StatusCode> {
        let handle = msg_handle as usize;
        let idx = invec_idx as usize;

        // SAFETY: SPM guarantees the accessed memory is valid and readable.
        let invec = unsafe { svc_access_invec(handle, idx)? };
        let result = f(invec);
        svc_release_invec(handle, idx)?;

        Ok(result)
    }

    fn access_outvec<R>(
        &self,
        msg_handle: ServiceHandle,
        outvec_idx: u32,
        f: impl FnOnce(&mut [u8]) -> (R, usize),
    ) -> Result<R, StatusCode> {
        let handle = msg_handle as usize;
        let idx = outvec_idx as usize;

        // SAFETY: SPM guarantees the accessed memory is valid and writable.
        let outvec = unsafe { svc_access_outvec(handle, idx)? };
        let (result, written_len) = f(outvec);
        svc_release_outvec(handle, idx, written_len)?;

        Ok(result)
    }

    fn access_invec_outvec<R>(
        &self,
        msg_handle: ServiceHandle,
        invec_idx: u32,
        outvec_idx: u32,
        f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
    ) -> Result<R, StatusCode> {
        let handle = msg_handle as usize;
        let in_idx = invec_idx as usize;
        let out_idx = outvec_idx as usize;

        // SAFETY: SPM guarantees the accessed memory regions are valid.
        let invec = unsafe { svc_access_invec(handle, in_idx)? };
        // SAFETY: SPM guarantees the accessed memory regions are valid.
        let outvec = unsafe { svc_access_outvec(handle, out_idx)? };

        let (result, written_len) = f(invec, outvec);

        svc_release_outvec(handle, out_idx, written_len)?;
        svc_release_invec(handle, in_idx)?;

        Ok(result)
    }

    unsafe fn call(
        &self,
        handle: ServiceHandle,
        ctrl_param: CtrlParam,
        in_vec: *const FFInVec,
        out_vec: *mut FFOutVec,
        _caller: CallerAttributes,
    ) -> Result<(), StatusCode> {
        // SAFETY: Parameters are verified by the SPM upon handler invocation.
        let (status, _, _, _) = unsafe {
            svc_call::<SVC_PSA_CALL>(
                handle as usize,
                mem::transmute::<CtrlParam, u32>(ctrl_param) as usize,
                in_vec as usize,
                out_vec as usize,
            )
        };
        check_svc_result(status)
    }
}

pub struct IpcPsaClient;

impl PsaApiCallInterface for IpcPsaClient {
    fn psa_framework_version() -> u32 {
        PSA_FRAMEWORK_VERSION
    }

    fn psa_version(service_id: u32) -> u32 {
        let Ok(handle) = ServiceHandle::try_from(service_id.cast_signed()) else {
            return 0;
        };
        // SAFETY: Querying the service version is a read-only operation.
        let (version, _, _, _) = unsafe { svc_call::<SVC_PSA_VERSION>(handle as usize, 0, 0, 0) };
        version as u32
    }

    fn psa_call(
        handle: ServiceHandle,
        ctrl_param: CtrlParam,
        in_vec: &[FFInVec],
        out_vec: &mut [FFOutVec],
    ) -> PsaStatus {
        let in_vec_ptr = if in_vec.is_empty() {
            core::ptr::null()
        } else {
            in_vec.as_ptr()
        };

        let out_vec_ptr = if out_vec.is_empty() {
            core::ptr::null_mut()
        } else {
            out_vec.as_mut_ptr()
        };

        // SAFETY: Calling SpmApi::call with valid vector pointers is safe.
        into_psa_status(unsafe {
            SpmApi::call(
                &SvcApi,
                handle,
                ctrl_param,
                in_vec_ptr,
                out_vec_ptr,
                CallerAttributes::SECURE_UNPRIVILEGED,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use psa_interface::status::StatusCode;
    use psa_interface::types::{CtrlParam, FFInVec, FFOutVec, ServiceHandle};

    use crate::spm::spm::{Connection, SpmCall, SpmError};
    use crate::spm_api::{CallerAttributes, RawVec, SpmApi};

    use super::*;

    // --- check_svc_result tests ---

    #[test]
    fn test_check_svc_result_success() {
        // StatusCode::_Success is 0
        assert_eq!(check_svc_result(0), Ok(()));
    }

    #[test]
    fn test_check_svc_result_known_error() {
        // ProgrammerError is a known negative status code
        let raw = (StatusCode::ProgrammerError as PsaStatus).cast_unsigned();
        assert_eq!(check_svc_result(raw), Err(StatusCode::ProgrammerError));
    }

    #[test]
    fn test_check_svc_result_unknown_code() {
        // An arbitrary value not matching any StatusCode
        let raw = 0x7FFF_ABCD_usize;
        assert_eq!(check_svc_result(raw), Err(StatusCode::CommunicationFailure));
    }

    // --- service_handle_from_raw tests ---

    #[test]
    fn test_service_handle_from_raw_crypto() {
        let raw = ServiceHandle::Crypto as usize;
        assert_eq!(service_handle_from_raw(raw), Ok(ServiceHandle::Crypto));
    }

    #[test]
    fn test_service_handle_from_raw_its() {
        let raw = ServiceHandle::InternalTrustedStorageService as usize;
        assert_eq!(
            service_handle_from_raw(raw),
            Ok(ServiceHandle::InternalTrustedStorageService)
        );
    }

    #[test]
    fn test_service_handle_from_raw_attestation() {
        let raw = ServiceHandle::AttestationService as usize;
        assert_eq!(
            service_handle_from_raw(raw),
            Ok(ServiceHandle::AttestationService)
        );
    }

    #[test]
    fn test_service_handle_from_raw_invalid() {
        assert_eq!(
            service_handle_from_raw(0xDEAD_BEEF),
            Err(StatusCode::InvalidHandle)
        );
    }

    // --- Mock SPM for handle_svc_with_spm tests ---

    struct MockSpm {
        version_val: Option<u32>,
    }

    impl MockSpm {
        const fn new() -> Self {
            Self {
                version_val: Some(1),
            }
        }
    }

    // SAFETY: Test-only mock, single-threaded.
    unsafe impl Sync for MockSpm {}

    impl SpmCall for MockSpm {
        fn call(&self, _connection: Connection) -> Result<(), StatusCode> {
            Ok(())
        }

        fn with_active_connection<F: FnMut(&mut Connection)>(
            &self,
            _f: F,
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

        fn map_vec(&self, _is_outvec: bool, _vec_idx: u32, _base: *const u8, _size: usize) {}
        fn unmap_vec(&self, _is_outvec: bool, _vec_idx: u32) {}

        fn version(&self, _handle: ServiceHandle) -> Option<u32> {
            self.version_val
        }
    }

    struct MockSfnApi;

    impl SpmApi for MockSfnApi {
        fn access_invec<R>(
            &self,
            _msg_handle: ServiceHandle,
            _invec_idx: u32,
            _f: impl FnOnce(&[u8]) -> R,
        ) -> Result<R, StatusCode> {
            Err(StatusCode::CommunicationFailure)
        }

        fn access_outvec<R>(
            &self,
            _msg_handle: ServiceHandle,
            _outvec_idx: u32,
            _f: impl FnOnce(&mut [u8]) -> (R, usize),
        ) -> Result<R, StatusCode> {
            Err(StatusCode::CommunicationFailure)
        }

        fn access_invec_outvec<R>(
            &self,
            _msg_handle: ServiceHandle,
            _invec_idx: u32,
            _outvec_idx: u32,
            _f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
        ) -> Result<R, StatusCode> {
            Err(StatusCode::CommunicationFailure)
        }

        unsafe fn call(
            &self,
            _handle: ServiceHandle,
            _ctrl_param: CtrlParam,
            _in_vec: *const FFInVec,
            _out_vec: *mut FFOutVec,
            _caller: CallerAttributes,
        ) -> Result<(), StatusCode> {
            Ok(())
        }
    }

    fn make_frame(r0: usize, r1: usize, r2: usize, r3: usize) -> SvcStackFrame {
        SvcStackFrame {
            r0,
            r1,
            r2,
            r3,
            r12: 0,
            lr: 0,
            pc: 0,
            xpsr: 0,
        }
    }

    // --- handle_svc_with_spm tests ---

    #[test]
    fn test_handle_svc_invalid_handle_returns_error() {
        let spm = MockSpm::new();
        let sfn = MockSfnApi;
        let mut frame = make_frame(0xDEAD_BEEF, 0, 0, 0);

        let handled = handle_svc_with_spm(SVC_PSA_VERSION, &mut frame, &spm, &sfn);

        assert!(handled);
        // Invalid handle sets error status in r0
        let status = frame.r0 as i32;
        assert_eq!(status, StatusCode::InvalidHandle as i32);
    }

    #[test]
    fn test_handle_svc_version_returns_version() {
        let spm = MockSpm::new();
        let sfn = MockSfnApi;
        let mut frame = make_frame(ServiceHandle::Crypto as usize, 0, 0, 0);

        let handled = handle_svc_with_spm(SVC_PSA_VERSION, &mut frame, &spm, &sfn);

        assert!(handled);
        assert_eq!(frame.r0, 1); // version_val = Some(1)
    }

    #[test]
    fn test_handle_svc_unknown_svc_returns_false() {
        let spm = MockSpm::new();
        let sfn = MockSfnApi;
        let mut frame = make_frame(ServiceHandle::Crypto as usize, 0, 0, 0);

        let handled = handle_svc_with_spm(0xFF, &mut frame, &spm, &sfn);

        assert!(!handled);
    }

    #[test]
    fn test_handle_svc_call_success() {
        let spm = MockSpm::new();
        let sfn = MockSfnApi;
        let ctrl = CtrlParam::new(1, 0, false, 0, false);
        let ctrl_raw = unsafe { mem::transmute::<CtrlParam, u32>(ctrl) } as usize;
        let mut frame = make_frame(ServiceHandle::Crypto as usize, ctrl_raw, 0, 0);

        let handled = handle_svc_with_spm(SVC_PSA_CALL, &mut frame, &spm, &sfn);

        assert!(handled);
        // Success = 0
        assert_eq!(frame.r0 as i32, 0);
    }

    // --- SvcStackFrame helper tests ---

    #[test]
    fn test_set_error_clears_registers() {
        let mut frame = make_frame(0, 0x11, 0x22, 0x33);
        set_error(&mut frame, StatusCode::ProgrammerError);
        assert_eq!(frame.r1, 0);
        assert_eq!(frame.r2, 0);
        assert_eq!(frame.r3, 0);
        assert_eq!(frame.r0 as i32, StatusCode::ProgrammerError as i32);
    }

    #[test]
    fn test_set_raw_vec_populates_frame() {
        let mut buf = [0u8; 16];
        let raw = RawVec {
            base: buf.as_mut_ptr(),
            len: 16,
        };
        let mut frame = make_frame(0xFF, 0xFF, 0xFF, 0xFF);
        set_raw_vec(&mut frame, raw);

        assert_eq!(frame.r0 as i32, 0); // success
        assert_eq!(frame.r1, buf.as_ptr() as usize);
        assert_eq!(frame.r2, 16);
        assert_eq!(frame.r3, 0);
    }
}
