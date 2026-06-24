// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#[macro_export]
macro_rules! define_spm_api {
    ($SpmType:ty) => {
        pub static SPM: $crate::libs::once_lock::OnceLock<&'static $SpmType> = $crate::libs::once_lock::OnceLock::new();

        pub fn get_spm() -> &'static $SpmType {
            *SPM.try_get()
                .expect("SPM must be initialized with set_spm() before SPM API use")
        }

        pub struct SfnApi;
        impl $crate::spm_api::SpmApi for SfnApi {
            fn map_invec<R>(&self, msg_handle: psa_interface::types::ServiceHandle, invec_idx: u32, f: impl FnOnce(&[u8]) -> R) -> R {
                let spm = get_spm();
                $crate::spm_api::with_connection_for_handle(spm, msg_handle, |connection| {
                    $crate::spm_api::with_mapped_invec(spm, connection, invec_idx, f)
                })
            }

            fn map_outvec<R>(&self, msg_handle: psa_interface::types::ServiceHandle, outvec_idx: u32, f: impl FnOnce(&mut [u8]) -> (R, usize)) -> R {
                let spm = get_spm();
                $crate::spm_api::with_connection_for_handle(spm, msg_handle, |connection| {
                    $crate::spm_api::with_mapped_outvec(spm, connection, outvec_idx, f)
                })
            }

            fn map_invec_outvec<R>(&self, msg_handle: psa_interface::types::ServiceHandle, invec_idx: u32, outvec_idx: u32, f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize)) -> R {
                let spm = get_spm();
                $crate::spm_api::with_connection_for_handle(spm, msg_handle, |connection| {
                    let (in_index, in_len, in_base) = $crate::spm_api::prepare_invec(spm, connection, invec_idx);
                    let (out_index, out_len, out_base) = $crate::spm_api::prepare_outvec(spm, connection, outvec_idx);

                    let invec = if in_len == 0 {
                        &[]
                    } else {
                        unsafe { core::slice::from_raw_parts(in_base, in_len) }
                    };
                    let outvec = if out_len == 0 {
                        &mut []
                    } else {
                        unsafe { core::slice::from_raw_parts_mut(out_base, out_len) }
                    };

                    let (result, written_len) = f(invec, outvec);

                    $crate::spm_api::commit_outvec_write(connection, out_index, out_len, written_len);
                    $crate::spm_api::mark_invec_unmapped(connection, in_index);

                    result
                })
            }

            unsafe fn call(&self, handle: psa_interface::types::ServiceHandle, ctrl_param: psa_interface::types::CtrlParam, in_vec: *const psa_interface::types::FFInVec, out_vec: *mut psa_interface::types::FFOutVec) -> Result<(), psa_interface::status::StatusCode> {
                let spm = get_spm();
                let (_msg_type, ivec_num, ovec_num) = $crate::spm_api::validate_call_params(ctrl_param)?;
                $crate::spm_api::validate_vec_pointer_shape(ctrl_param.has_iovec(), ivec_num, ovec_num, in_vec, out_vec)?;

                let in_vecs: &[psa_interface::types::FFInVec] = if ivec_num == 0 {
                    &[]
                } else {
                    unsafe { core::slice::from_raw_parts(in_vec, ivec_num) }
                };

                let out_vecs: &mut [psa_interface::types::FFOutVec] = if ovec_num == 0 {
                    &mut []
                } else {
                    unsafe { core::slice::from_raw_parts_mut(out_vec, ovec_num) }
                };

                let caller = $crate::spm_api::CallerAttributes::SECURE_PRIVILEGED;
                let connection = $crate::spm_api::call_from_slices(handle, ctrl_param, in_vecs, out_vecs, caller)?;

                $crate::spm::SpmCall::call(spm, connection)
            }
        }


        #[unsafe(no_mangle)]
        pub extern "cmse-nonsecure-entry" fn psa_call_veneer(
            handle: psa_interface::types::ServiceHandle,
            ctrl_param: psa_interface::types::CtrlParam,
            in_vec: *const psa_interface::types::FFInVec,
            out_vec: *mut psa_interface::types::FFOutVec,
        ) -> psa_interface::types::PsaStatus {
            #[cfg(not(feature = "spm-ipc"))]
            {
                psa_interface::status::into_psa_status(unsafe {
                    $crate::spm_api::SpmApi::call(&SfnApi, handle, ctrl_param, in_vec, out_vec)
                })
            }
            #[cfg(feature = "spm-ipc")]
            {
                psa_interface::status::into_psa_status(unsafe {
                    $crate::spm_api::SpmApi::call(&$crate::spm_api::SvcApi, handle, ctrl_param, in_vec, out_vec)
                })
            }
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
                handle: psa_interface::types::ServiceHandle,
                ctrl_param: psa_interface::types::CtrlParam,
                in_vec: &[psa_interface::types::FFInVec],
                out_vec: &mut [psa_interface::types::FFOutVec],
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
                        $crate::spm_api::SpmApi::call(&SfnApi, handle, ctrl_param, in_vec_ptr, out_vec_ptr)
                    })
                }
                #[cfg(feature = "spm-ipc")]
                {
                    psa_interface::status::into_psa_status(unsafe {
                        $crate::spm_api::SpmApi::call(&$crate::spm_api::SvcApi, handle, ctrl_param, in_vec_ptr, out_vec_ptr)
                    })
                }
            }
        }

        pub fn handle_svc(svc_num: u8, frame: &mut $crate::spm_api::SvcStackFrame) -> bool {
            $crate::spm_api::handle_svc_with_spm(svc_num, frame, get_spm(), &SfnApi)
        }

        // This function must use `no_mangle` because it is generated by the `define_spm_api!` macro
        // inside a downstream board crate (e.g., `boards/.../secure/src/main.rs`). The `svc.rs` module
        // in the `spe` crate calls it via an `extern "Rust"` block. The `no_mangle` attribute prevents
        // the compiler from mangling the name so that `svc.rs` can link against it at link time,
        // successfully crossing the crate boundary.
        #[unsafe(no_mangle)]
        pub fn __spm_api_handle_svc_dispatch(frame: *mut $crate::spm_api::SvcStackFrame, svc_num: u32) -> bool {
            let frame_ref = unsafe { &mut *frame };
            $crate::spm_api::handle_svc_with_spm(svc_num as u8, frame_ref, get_spm(), &SfnApi)
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
                "svc {SVC_PSA_CALL_RETURN}",
                SVC_PSA_CALL = const $crate::spm_api::SVC_PSA_CALL,
                SVC_PSA_CALL_RETURN = const $crate::spm_api::SVC_PSA_CALL_RETURN,
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
    };
}

use crate::spm::PSA_MAX_IOVEC;
use psa_interface::{
    status::StatusCode,
    types::{CtrlParam, FFInVec, FFOutVec, ServiceHandle},
};

pub trait SpmApi {
    fn map_invec<R>(
        &self,
        msg_handle: ServiceHandle,
        invec_idx: u32,
        f: impl FnOnce(&[u8]) -> R,
    ) -> R;
    fn map_outvec<R>(
        &self,
        msg_handle: ServiceHandle,
        outvec_idx: u32,
        f: impl FnOnce(&mut [u8]) -> (R, usize),
    ) -> R;
    fn map_invec_outvec<R>(
        &self,
        msg_handle: ServiceHandle,
        invec_idx: u32,
        outvec_idx: u32,
        f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
    ) -> R;
    // We also expose the call function for internal use. Services themselves may not need it.
    unsafe fn call(
        &self,
        handle: ServiceHandle,
        ctrl_param: CtrlParam,
        in_vec: *const FFInVec,
        out_vec: *mut FFOutVec,
    ) -> Result<(), StatusCode>;
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
    pub const fn new(handle: ServiceHandle, msg_type: i32, caller: CallerAttributes) -> Self {
        Self {
            handle,
            msg_type,
            caller,
            in_size: [None; PSA_MAX_IOVEC],
            out_size: [None; PSA_MAX_IOVEC],
        }
    }
}
