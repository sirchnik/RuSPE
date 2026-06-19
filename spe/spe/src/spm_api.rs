// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use core::{mem, panic, ptr, slice};
use psa_interface::{
    status::StatusCode,
    types::{CtrlParam, FFInVec, FFOutVec, PsaStatus, ServiceHandle},
};
use cortexm::support;
use crate::{
    libs::once_lock::OnceLock,
    spm::{Connection, SpmCall, SpmError, PSA_MAX_IOVEC},
};

static SPM: OnceLock<&'static dyn SpmCall> = OnceLock::new();

pub fn get_spm() -> &'static dyn SpmCall {
    *SPM.try_get()
        .expect("SPM must be initialized with set_spm() before SPM API use")
}

pub fn try_get_spm() -> Option<&'static dyn SpmCall> {
    match SPM.try_get() {
        Ok(spm) => Some(*spm),
        Err(_) => None,
    }
}

pub fn set_spm(spm: &'static dyn SpmCall) {
    if SPM.try_set(spm).is_err() {
        panic!("SPM already initialized");
    }
}

pub trait SpmApi {
    fn map_invec<R>(&self, msg_handle: ServiceHandle, invec_idx: u32, f: impl FnOnce(&[u8]) -> R) -> R;
    fn map_outvec<R>(&self, msg_handle: ServiceHandle, outvec_idx: u32, f: impl FnOnce(&mut [u8]) -> (R, usize)) -> R;
    fn map_invec_outvec<R>(&self, msg_handle: ServiceHandle, invec_idx: u32, outvec_idx: u32, f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize)) -> R;
    // We also expose the call function for internal use. Services themselves may not need it.
    unsafe fn call(&self, handle: ServiceHandle, ctrl_param: CtrlParam, in_vec: *const FFInVec, out_vec: *mut FFOutVec) -> Result<(), StatusCode>;
}

pub struct InternalPsaClient;

impl psa_interface::PsaApiCallInterface for InternalPsaClient {
    fn psa_framework_version() -> u32 {
        todo!();
    }

    fn psa_version(_service_id: u32) -> u32 {
        todo!();
    }

    fn psa_call(
        handle: ServiceHandle,
        ctrl_param: CtrlParam,
        in_vec: &[FFInVec],
        out_vec: &mut [FFOutVec],
    ) -> psa_interface::types::PsaStatus {
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

        #[cfg(not(feature = "spm-ipc"))]
        {
            psa_interface::status::into_psa_status(unsafe {
                crate::spm_api::call(handle, ctrl_param, in_vec_ptr, out_vec_ptr)
            })
        }
        #[cfg(feature = "spm-ipc")]
        {
            psa_interface::status::into_psa_status(unsafe {
                crate::spm_api::SvcApi.call(handle, ctrl_param, in_vec_ptr, out_vec_ptr)
            })
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerAttributes {
    /// Caller is from the Non-Secure world.
    pub ns: bool,
    /// Caller is privileged (handler mode or nPRIV=0).
    pub privileged: bool,
}

impl CallerAttributes {
    pub const NS_UNPRIVILEGED: Self = Self {
        ns: true,
        privileged: false,
    };
    pub const NS_PRIVILEGED: Self = Self {
        ns: true,
        privileged: true,
    };
    pub const SECURE_UNPRIVILEGED: Self = Self {
        ns: false,
        privileged: false,
    };
    pub const SECURE_PRIVILEGED: Self = Self {
        ns: false,
        privileged: true,
    };
}

#[derive(Clone, Copy, Debug)]
pub struct PsaMsg {
    pub handle: ServiceHandle,
    pub msg_type: i32,
    pub caller: CallerAttributes,
    pub in_size: [Option<usize>; PSA_MAX_IOVEC],
    pub out_size: [Option<usize>; PSA_MAX_IOVEC],
}

impl PsaMsg {
    const fn new(handle: ServiceHandle, msg_type: i32, caller: CallerAttributes) -> Self {
        Self {
            handle,
            msg_type,
            caller,
            in_size: [None; PSA_MAX_IOVEC],
            out_size: [None; PSA_MAX_IOVEC],
        }
    }
}

fn validate_call_params(ctrl_param: CtrlParam) -> Result<(i32, usize, usize), StatusCode> {
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

fn validate_vec_pointer_shape(
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

fn validate_invec_payload_nonoverlap(in_vecs: &[FFInVec]) -> Result<(), StatusCode> {
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

pub fn prepare_invec_raw(
    spm: &dyn SpmCall,
    msg_handle: ServiceHandle,
    invec_idx: u32,
) -> Result<RawVec, StatusCode> {
    let mut raw = None;
    match spm.with_active_connection(&mut |connection| {
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

pub fn finish_invec_raw(
    spm: &dyn SpmCall,
    msg_handle: ServiceHandle,
    invec_idx: u32,
) -> Result<(), StatusCode> {
    match spm.with_active_connection(&mut |connection| {
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

pub fn prepare_outvec_raw(
    spm: &dyn SpmCall,
    msg_handle: ServiceHandle,
    outvec_idx: u32,
) -> Result<RawVec, StatusCode> {
    let mut raw = None;
    match spm.with_active_connection(&mut |connection| {
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

pub fn finish_outvec_raw(
    spm: &dyn SpmCall,
    msg_handle: ServiceHandle,
    outvec_idx: u32,
    written_len: usize,
) -> Result<(), StatusCode> {
    match spm.with_active_connection(&mut |connection| {
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


pub struct SfnApi;
impl SpmApi for SfnApi {
    fn map_invec<R>(&self, msg_handle: ServiceHandle, invec_idx: u32, f: impl FnOnce(&[u8]) -> R) -> R {
        let spm = get_spm();
        with_connection_for_handle(spm, msg_handle, |connection| {
            with_mapped_invec(spm, connection, invec_idx, f)
        })
    }

    fn map_outvec<R>(&self, msg_handle: ServiceHandle, outvec_idx: u32, f: impl FnOnce(&mut [u8]) -> (R, usize)) -> R {
        let spm = get_spm();
        with_connection_for_handle(spm, msg_handle, |connection| {
            with_mapped_outvec(spm, connection, outvec_idx, f)
        })
    }

    fn map_invec_outvec<R>(&self, msg_handle: ServiceHandle, invec_idx: u32, outvec_idx: u32, f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize)) -> R {
        let spm = get_spm();
        with_connection_for_handle(spm, msg_handle, |connection| {
            let (in_index, in_len, in_base) = prepare_invec(spm, connection, invec_idx);
            let (out_index, out_len, out_base) = prepare_outvec(spm, connection, outvec_idx);

            let invec = if in_len == 0 {
                &[]
            } else {
                unsafe { slice::from_raw_parts(in_base, in_len) }
            };
            let outvec = if out_len == 0 {
                &mut []
            } else {
                unsafe { slice::from_raw_parts_mut(out_base, out_len) }
            };

            let (result, written_len) = f(invec, outvec);

            commit_outvec_write(connection, out_index, out_len, written_len);
            mark_invec_unmapped(connection, in_index);

            result
        })
    }

    unsafe fn call(&self, handle: ServiceHandle, ctrl_param: CtrlParam, in_vec: *const FFInVec, out_vec: *mut FFOutVec) -> Result<(), StatusCode> {
        let spm = get_spm();
        let (_msg_type, ivec_num, ovec_num) = validate_call_params(ctrl_param)?;
        validate_vec_pointer_shape(ctrl_param.has_iovec(), ivec_num, ovec_num, in_vec, out_vec)?;

        let in_vecs: &[FFInVec] = if ivec_num == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(in_vec, ivec_num) }
        };

        let out_vecs: &mut [FFOutVec] = if ovec_num == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(out_vec, ovec_num) }
        };

        let caller = CallerAttributes::SECURE_PRIVILEGED; // Default for direct SFN call
        let connection = call_from_slices(handle, ctrl_param, in_vecs, out_vecs, caller)?;

        spm.call(connection)
    }
}
pub const SVC_ELEVATE: u8 = 0;
pub const SVC_PSA_MAP_VEC: u8 = 1;
pub const SVC_PSA_UNMAP_VEC: u8 = 2;
pub const SVC_CALL_UNPRIV: u8 = 3;
pub const SVC_PSA_CALL: u8 = 4;
pub const SVC_PSA_RETURN: u8 = 7;

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
            SVC_PSA_MAP_VEC | SVC_PSA_UNMAP_VEC | SVC_PSA_CALL => {
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
                    set_raw_vec(frame, raw)
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
                    set_success(frame)
                }
                Err(status) => set_error(frame, status),
            }
        }
        SVC_PSA_CALL => {
            let result = unsafe {
                SfnApi.call(
                    handle,
                    ctrl_param_from_raw(frame.r1),
                    frame.r2 as *const FFInVec,
                    frame.r3 as *mut FFOutVec,
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
    handle_svc_with_spm(svc_num, frame, try_get_spm())
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn psa_call_thunk(
    _handle: usize,
    _ctrl_param: usize,
    _in_vec: usize,
    _out_vec: usize,
) -> ! {
    core::arch::naked_asm!(
        "sub sp, sp, #32",
        "str r0, [sp, #0]",
        "str r1, [sp, #4]",
        "str r2, [sp, #8]",
        "str r3, [sp, #12]",
        "movs r0, #0",
        "str r0, [sp, #16]",
        "str r0, [sp, #20]",
        "str r0, [sp, #24]",
        "str r0, [sp, #28]",
        "movs r0, #{SVC_PSA_CALL}",
        "mov r1, sp",
        "bl {handle_svc}",
        "ldr r0, [sp, #0]",
        "ldr r1, [sp, #4]",
        "ldr r2, [sp, #8]",
        "ldr r3, [sp, #12]",
        "add sp, sp, #32",
        "svc {SVC_PSA_RETURN}",
        SVC_PSA_CALL = const SVC_PSA_CALL,
        SVC_PSA_RETURN = const SVC_PSA_RETURN,
        handle_svc = sym handle_svc,
    )
}

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn psa_call_thunk(
    _handle: usize,
    _ctrl_param: usize,
    _in_vec: usize,
    _out_vec: usize,
) -> ! {
    panic!("psa_call_thunk only available on ARM");
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


pub struct SvcApi;
impl SpmApi for SvcApi {
    fn map_invec<R>(&self, msg_handle: ServiceHandle, invec_idx: u32, f: impl FnOnce(&[u8]) -> R) -> R {
        let (status, base, len, _) =
            unsafe { svc_call::<SVC_PSA_MAP_VEC>(msg_handle as usize, invec_idx as usize, 0, 0) };
        status_from_raw(status).unwrap_or_else(|err| panic!("failed to map input vector: {:?}", err));

        let invec = if len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(base as *const u8, len) }
        };
        let result = f(invec);

        let (status, _, _, _) =
            unsafe { svc_call::<SVC_PSA_UNMAP_VEC>(msg_handle as usize, invec_idx as usize, 0, 0) };
        status_from_raw(status).unwrap_or_else(|err| panic!("failed to unmap input vector: {:?}", err));

        result
    }

    fn map_outvec<R>(&self, msg_handle: ServiceHandle, outvec_idx: u32, f: impl FnOnce(&mut [u8]) -> (R, usize)) -> R {
        let (status, base, len, _) =
            unsafe { svc_call::<SVC_PSA_MAP_VEC>(msg_handle as usize, outvec_idx as usize, 1, 0) };
        status_from_raw(status).unwrap_or_else(|err| panic!("failed to map output vector: {:?}", err));

        let outvec = if len == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(base as *mut u8, len) }
        };
        let (result, written_len) = f(outvec);

        let (status, _, _, _) = unsafe {
            svc_call::<SVC_PSA_UNMAP_VEC>(msg_handle as usize, outvec_idx as usize, 1, written_len)
        };
        status_from_raw(status)
            .unwrap_or_else(|err| panic!("failed to commit output vector: {:?}", err));

        result
    }

    fn map_invec_outvec<R>(&self, msg_handle: ServiceHandle, invec_idx: u32, outvec_idx: u32, f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize)) -> R {
        let (in_status, in_base, in_len, _) =
            unsafe { svc_call::<SVC_PSA_MAP_VEC>(msg_handle as usize, invec_idx as usize, 0, 0) };
        status_from_raw(in_status)
            .unwrap_or_else(|err| panic!("failed to map input vector: {:?}", err));

        let (out_status, out_base, out_len, _) =
            unsafe { svc_call::<SVC_PSA_MAP_VEC>(msg_handle as usize, outvec_idx as usize, 1, 0) };
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
            svc_call::<SVC_PSA_UNMAP_VEC>(msg_handle as usize, outvec_idx as usize, 1, written_len)
        };
        status_from_raw(out_status)
            .unwrap_or_else(|err| panic!("failed to commit output vector: {:?}", err));

        let (in_status, _, _, _) =
            unsafe { svc_call::<SVC_PSA_UNMAP_VEC>(msg_handle as usize, invec_idx as usize, 0, 0) };
        status_from_raw(in_status)
            .unwrap_or_else(|err| panic!("failed to unmap input vector: {:?}", err));

        result
    }

    unsafe fn call(&self, handle: ServiceHandle, ctrl_param: CtrlParam, in_vec: *const FFInVec, out_vec: *mut FFOutVec) -> Result<(), StatusCode> {
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

// Exported global call function for internal backward compatibility with veneers
pub unsafe fn call(
    handle: ServiceHandle,
    ctrl_param: CtrlParam,
    in_vec: *const FFInVec,
    out_vec: *mut FFOutVec,
) -> Result<(), StatusCode> {
    if support::is_interrupt_context() {
        panic!("call cannot be called from an interrupt context");
    }

    let privileged = !support::is_ns_unprivileged();
    let caller = CallerAttributes {
        ns: true,
        privileged,
    };

    let (_msg_type, ivec_num, ovec_num) = validate_call_params(ctrl_param)?;
    validate_vec_pointer_shape(ctrl_param.has_iovec(), ivec_num, ovec_num, in_vec, out_vec)?;
    
    let in_vecs: &[FFInVec] = if ivec_num == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(in_vec, ivec_num) }
    };

    let out_vecs: &mut [FFOutVec] = if ovec_num == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(out_vec, ovec_num) }
    };

    let connection = call_from_slices(handle, ctrl_param, in_vecs, out_vecs, caller)?;
    get_spm().call(connection)
}
