use core::slice;

use psa_interface::{
    status::StatusCode,
    types::{PsaStatus, ServiceHandle},
};

use crate::psa::{psa_api, psa_iovec_api::RawVec};

pub const SVC_ELEVATE: u8 = 0;
pub const SVC_PSA_PREPARE_INVEC: u8 = 1;
pub const SVC_PSA_FINISH_INVEC: u8 = 2;
pub const SVC_PSA_PREPARE_OUTVEC: u8 = 3;
pub const SVC_PSA_FINISH_OUTVEC: u8 = 4;
pub const SVC_CALL_UNPRIV: u8 = 5;

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
    set_status(frame, status);
}

fn set_raw_vec(frame: &mut SvcStackFrame, raw: RawVec) {
    frame.r1 = raw.base as usize;
    frame.r2 = raw.len;
    set_success(frame);
}

pub fn handle_svc(svc_num: u8, frame: &mut SvcStackFrame) -> bool {
    let Some(spm) = psa_api::try_get_spm() else {
        return match svc_num {
            SVC_PSA_PREPARE_INVEC
            | SVC_PSA_FINISH_INVEC
            | SVC_PSA_PREPARE_OUTVEC
            | SVC_PSA_FINISH_OUTVEC => {
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
        SVC_PSA_PREPARE_INVEC => match crate::psa::psa_iovec_api::psa_prepare_invec(
            spm,
            handle,
            frame.r1 as u32,
        ) {
            Ok(raw) => set_raw_vec(frame, raw),
            Err(status) => set_error(frame, status),
        },
        SVC_PSA_FINISH_INVEC => {
            match crate::psa::psa_iovec_api::psa_finish_invec(spm, handle, frame.r1 as u32) {
                Ok(()) => set_success(frame),
                Err(status) => set_error(frame, status),
            }
        }
        SVC_PSA_PREPARE_OUTVEC => match crate::psa::psa_iovec_api::psa_prepare_outvec(
            spm,
            handle,
            frame.r1 as u32,
        ) {
            Ok(raw) => set_raw_vec(frame, raw),
            Err(status) => set_error(frame, status),
        },
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
        _ => return false,
    }

    true
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
unsafe fn svc_call<const SVC_NUM: u8>(arg0: usize, arg1: usize, arg2: usize) -> (usize, usize, usize) {
    use core::arch::asm;
    use cortexm33::support;

    let out0: usize;
    let out1: usize;
    let out2: usize;

    support::dmb();
    unsafe {
        asm!(
            "svc {svc_num}",
            svc_num = const SVC_NUM,
            inlateout("r0") arg0 => out0,
            inlateout("r1") arg1 => out1,
            inlateout("r2") arg2 => out2,
            lateout("r3") _,
            lateout("r12") _,
            options(nostack),
        );
    }
    support::dmb();

    (out0, out1, out2)
}

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
unsafe fn svc_call<const SVC_NUM: u8>(_: usize, _: usize, _: usize) -> (usize, usize, usize) {
    let _ = SVC_NUM;
    panic!("SVC PSA bridge is only available on ARM bare-metal targets")
}

pub fn psa_map_invec<R>(
    msg_handle: ServiceHandle,
    invec_idx: u32,
    f: impl FnOnce(&[u8]) -> R,
) -> R {
    let (status, base, len) = unsafe {
        svc_call::<SVC_PSA_PREPARE_INVEC>(msg_handle as usize, invec_idx as usize, 0)
    };
    status_from_raw(status).unwrap_or_else(|err| panic!("failed to map input vector: {:?}", err));

    let invec = if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(base as *const u8, len) }
    };
    let result = f(invec);

    let (status, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_INVEC>(msg_handle as usize, invec_idx as usize, 0)
    };
    status_from_raw(status)
        .unwrap_or_else(|err| panic!("failed to unmap input vector: {:?}", err));

    result
}

pub fn psa_map_outvec<R>(
    msg_handle: ServiceHandle,
    outvec_idx: u32,
    f: impl FnOnce(&mut [u8]) -> (R, usize),
) -> R {
    let (status, base, len) = unsafe {
        svc_call::<SVC_PSA_PREPARE_OUTVEC>(msg_handle as usize, outvec_idx as usize, 0)
    };
    status_from_raw(status)
        .unwrap_or_else(|err| panic!("failed to map output vector: {:?}", err));

    let outvec = if len == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(base as *mut u8, len) }
    };
    let (result, written_len) = f(outvec);

    let (status, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_OUTVEC>(msg_handle as usize, outvec_idx as usize, written_len)
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
    let (in_status, in_base, in_len) = unsafe {
        svc_call::<SVC_PSA_PREPARE_INVEC>(msg_handle as usize, invec_idx as usize, 0)
    };
    status_from_raw(in_status)
        .unwrap_or_else(|err| panic!("failed to map input vector: {:?}", err));

    let (out_status, out_base, out_len) = unsafe {
        svc_call::<SVC_PSA_PREPARE_OUTVEC>(msg_handle as usize, outvec_idx as usize, 0)
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

    let (out_status, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_OUTVEC>(msg_handle as usize, outvec_idx as usize, written_len)
    };
    status_from_raw(out_status)
        .unwrap_or_else(|err| panic!("failed to commit output vector: {:?}", err));

    let (in_status, _, _) = unsafe {
        svc_call::<SVC_PSA_FINISH_INVEC>(msg_handle as usize, invec_idx as usize, 0)
    };
    status_from_raw(in_status)
        .unwrap_or_else(|err| panic!("failed to unmap input vector: {:?}", err));

    result
}
