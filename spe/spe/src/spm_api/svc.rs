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
pub const SVC_PSA_MAP_VEC: u8 = 1;
pub const SVC_PSA_UNMAP_VEC: u8 = 2;
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
        SVC_PSA_MAP_VEC => {
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
        SVC_PSA_UNMAP_VEC => {
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

fn status_from_raw(raw: usize) -> Result<(), StatusCode> {
    let status_val = PsaStatus::from_ne_bytes(raw.to_ne_bytes());
    match StatusCode::try_from(status_val) {
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
        // SAFETY: Making an SVC call to map the input vector is safe as it doesn't
        // violate memory safety, and returns a verified memory range.
        let (status, base, len, _) =
            unsafe { svc_call::<SVC_PSA_MAP_VEC>(msg_handle as usize, invec_idx as usize, 0, 0) };
        status_from_raw(status)?;

        let invec = if len == 0 {
            &[]
        } else {
            // SAFETY: The base pointer and length returned by the mapping SVC are
            // guaranteed by the SPM to point to valid, read-accessible memory.
            unsafe { slice::from_raw_parts(base as *const u8, len) }
        };
        let result = f(invec);

        // SAFETY: Unmapping a previously mapped input vector is safe and releases the
        // mapped state.
        let (status, _, _, _) =
            unsafe { svc_call::<SVC_PSA_UNMAP_VEC>(msg_handle as usize, invec_idx as usize, 0, 0) };
        status_from_raw(status)?;

        Ok(result)
    }

    fn access_outvec<R>(
        &self,
        msg_handle: ServiceHandle,
        outvec_idx: u32,
        f: impl FnOnce(&mut [u8]) -> (R, usize),
    ) -> Result<R, StatusCode> {
        // SAFETY: Mapping the output vector via SVC is safe and returns a valid memory
        // range.
        let (status, base, len, _) =
            unsafe { svc_call::<SVC_PSA_MAP_VEC>(msg_handle as usize, outvec_idx as usize, 1, 0) };
        status_from_raw(status)?;

        let outvec = if len == 0 {
            &mut []
        } else {
            // SAFETY: The base pointer and length returned by the mapping SVC are
            // guaranteed by the SPM to point to valid, write-accessible memory.
            unsafe { slice::from_raw_parts_mut(base as *mut u8, len) }
        };
        let (result, written_len) = f(outvec);

        // SAFETY: Unmapping and writing back the output vector via SVC is safe.
        let (status, _, _, _) = unsafe {
            svc_call::<SVC_PSA_UNMAP_VEC>(msg_handle as usize, outvec_idx as usize, 1, written_len)
        };
        status_from_raw(status)?;

        Ok(result)
    }

    fn access_invec_outvec<R>(
        &self,
        msg_handle: ServiceHandle,
        invec_idx: u32,
        outvec_idx: u32,
        f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
    ) -> Result<R, StatusCode> {
        // SAFETY: Mapping the input vector via SVC is safe.
        let (in_status, in_base, in_len, _) =
            unsafe { svc_call::<SVC_PSA_MAP_VEC>(msg_handle as usize, invec_idx as usize, 0, 0) };
        status_from_raw(in_status)?;

        // SAFETY: Mapping the output vector via SVC is safe.
        let (out_status, out_base, out_len, _) =
            unsafe { svc_call::<SVC_PSA_MAP_VEC>(msg_handle as usize, outvec_idx as usize, 1, 0) };
        status_from_raw(out_status)?;

        let invec = if in_len == 0 {
            &[]
        } else {
            // SAFETY: The input base and length returned by the SVC are guaranteed valid by
            // the SPM.
            unsafe { slice::from_raw_parts(in_base as *const u8, in_len) }
        };
        let outvec = if out_len == 0 {
            &mut []
        } else {
            // SAFETY: The output base and length returned by the SVC are guaranteed valid
            // by the SPM.
            unsafe { slice::from_raw_parts_mut(out_base as *mut u8, out_len) }
        };

        let (result, written_len) = f(invec, outvec);

        // SAFETY: Unmapping the output vector via SVC is safe.
        let (out_status, _, _, _) = unsafe {
            svc_call::<SVC_PSA_UNMAP_VEC>(msg_handle as usize, outvec_idx as usize, 1, written_len)
        };
        status_from_raw(out_status)?;

        // SAFETY: Unmapping the input vector via SVC is safe.
        let (in_status, _, _, _) =
            unsafe { svc_call::<SVC_PSA_UNMAP_VEC>(msg_handle as usize, invec_idx as usize, 0, 0) };
        status_from_raw(in_status)?;

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
        // SAFETY: Issuing an SVC call for PSA service execution is safe as parameters
        // are verified by the SPM upon handler invocation.
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
        // SAFETY: Querying the service version via SVC is safe.
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
