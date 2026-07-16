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
            fn access_invec<R>(&self, msg_handle: psa_interface::types::ServiceHandle, invec_idx: u32, f: impl FnOnce(&[u8]) -> R) -> R {
                let spm = get_spm();
                $crate::spm_api::with_connection_for_handle(spm, msg_handle, |connection| {
                    $crate::spm_api::with_mapped_invec(spm, connection, invec_idx, f)
                })
            }

            fn access_outvec<R>(&self, msg_handle: psa_interface::types::ServiceHandle, outvec_idx: u32, f: impl FnOnce(&mut [u8]) -> (R, usize)) -> R {
                let spm = get_spm();
                $crate::spm_api::with_connection_for_handle(spm, msg_handle, |connection| {
                    $crate::spm_api::with_mapped_outvec(spm, connection, outvec_idx, f)
                })
            }

            fn access_invec_outvec<R>(&self, msg_handle: psa_interface::types::ServiceHandle, invec_idx: u32, outvec_idx: u32, f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize)) -> R {
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

                $crate::spm::spm::SpmCall::call(spm, connection)
            }
        }


        #[unsafe(no_mangle)]
        pub extern "cmse-nonsecure-entry" fn psa_version_veneer(service_id: u32) -> u32 {
            psa_version(service_id)
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

        fn psa_version(service_id: u32) -> u32 {
            let handle = match psa_interface::types::ServiceHandle::try_from(service_id as i32) {
                Ok(h) => h,
                Err(_) => return 0,
            };
            $crate::spm::spm::SpmCall::version(get_spm(), handle).unwrap_or(0)
        }

        pub struct InternalPsaClient;

        impl psa_interface::PsaApiCallInterface for InternalPsaClient {
            fn psa_framework_version() -> u32 {
                psa_interface::types::PSA_FRAMEWORK_VERSION
            }

            fn psa_version(service_id: u32) -> u32 {
                psa_version(service_id)
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

        unsafe extern "C" fn svc_handler_dispatch(frame: *mut $crate::spm_api::SvcStackFrame, svc_num: u32) {
            let frame_ref = unsafe { &mut *frame };
            if $crate::spm_api::handle_svc_with_spm(svc_num as u8, frame_ref, get_spm(), &SfnApi) {
                return;
            }
            panic!("unhandled svc {svc_num}");
        }

        #[cfg(target_arch = "arm")]
        #[unsafe(naked)]
        pub unsafe extern "C" fn svc_handler() {
            use core::arch::naked_asm;
            naked_asm!(
                "
            // Determine which stack the exception frame is on (EXC_RETURN bit 2).
            tst lr, #4
            ite eq
            mrseq r0, msp
            mrsne r0, psp

            // Extract SVC number from the instruction preceding stacked PC.
            ldr r1, [r0, #24]          // r1 = stacked PC
            ldrh r1, [r1, #-2]         // r1 = SVC instruction halfword
            uxtb r1, r1                // r1 = SVC number

            // --- SVC_START_PROCESS: switch to unprivileged Thread + PSP ----------
            cmp r1, {SVC_START_PROCESS}
            beq 200f

            // --- SVC_PROCESS_EXIT: return to privileged Thread + MSP ----------------
            cmp r1, {SVC_PROCESS_EXIT}
            beq 201f

            // --- SVC_PSA_CALL: execute psa_call in privileged Thread + MSP ---
            cmp r1, {SVC_PSA_CALL}
            beq 202f

            // --- SVC_PSA_CALL_RETURN: return from psa_call ---
            cmp r1, {SVC_PSA_CALL_RETURN}
            beq 203f

            // --- PSA SVCs and any fallback handling --------------------------------
            b {svc_handler_dispatch}

        200: // svc_call_unpriv
            // The caller prepared PSP with a fake exception frame before issuing this
            // SVC. We just flip CONTROL and EXC_RETURN to return via PSP unprivileged.
            mov r0, #1
            msr CONTROL, r0             // nPRIV=1
            isb
            orr lr, lr, #4              // EXC_RETURN bit2=1 -> unstack from PSP
            bx lr                       // exception return -> service runs

        201: // svc_process_exit
            // Service finished: PSP frame has return value in R0.
            // Copy it to the orphaned MSP frame so the original caller gets it.
            ldr r2, [r0, #0]           // r2 = PSP_frame.R0 (service return value)
            mrs r1, msp                // r1 = MSP (orphaned frame from SVC_START_PROCESS)
            str r2, [r1, #0]          // MSP_frame.R0 = return value

            // Restore privileged Thread mode using MSP.
            mov r0, #0
            msr CONTROL, r0            // nPRIV=0, SPSEL=0
            isb
            bic lr, lr, #4             // EXC_RETURN bit2=0 -> unstack from MSP
            bx lr                      // exception return -> back in privileged caller

        202: // svc_psa_call
            mrs r2, msp
            mrs r3, CONTROL
            mrs r12, PSPLIM
            stmdb r2!, {{r0, r3, r12, lr}}

            sub r2, r2, #32

            ldr r3, [r0, #0]
            str r3, [r2, #0]
            ldr r3, [r0, #4]
            str r3, [r2, #4]
            ldr r3, [r0, #8]
            str r3, [r2, #8]
            ldr r3, [r0, #12]
            str r3, [r2, #12]

            mov r3, #0
            str r3, [r2, #16]
            str r3, [r2, #20]

            ldr r3, 300f
            str r3, [r2, #24]

            mov r3, #1
            lsl r3, r3, #24
            str r3, [r2, #28]

            msr msp, r2

            mov r3, #0
            msr CONTROL, r3
            isb

            ldr lr, 301f
            bx lr

            .align 2
        300: .word {psa_call_thunk}
        301: .word 0xFFFFFFF9

        203: // svc_psa_return
            mrs r2, msp

            // Load the original r0 (caller's exception frame pointer) into r0.
            // It is located at offset 32 from the current msp.
            ldr r0, [r2, #32]

            // Copy the return values r0-r3 from the current exception frame to the caller's exception frame.
            // We use r1 as a scratch register.
            ldr r1, [r2, #0]
            str r1, [r0, #0]
            ldr r1, [r2, #4]
            str r1, [r0, #4]
            ldr r1, [r2, #8]
            str r1, [r0, #8]
            ldr r1, [r2, #12]
            str r1, [r0, #12]

            // Load the original CONTROL, PSPLIM, and EXC_RETURN.
            ldr r3, [r2, #36]
            ldr r1, [r2, #40]
            ldr lr, [r2, #44]

            // Adjust MSP (pop the exception frame + saved state).
            add r2, r2, #48
            msr msp, r2

            // Restore PSPLIM.
            msr PSPLIM, r1

            // If returning to Thread using PSP, set PSP to the caller's exception frame pointer.
            tst lr, #4
            beq 204f
            msr psp, r0
        204:

            // Restore CONTROL.
            msr CONTROL, r3
            isb

            bx lr
                ",
                svc_handler_dispatch = sym svc_handler_dispatch,
                psa_call_thunk = sym psa_call_thunk,
                SVC_START_PROCESS = const $crate::spm_api::SVC_START_PROCESS,
                SVC_PROCESS_EXIT = const $crate::spm_api::SVC_PROCESS_EXIT,
                SVC_PSA_CALL = const $crate::spm_api::SVC_PSA_CALL,
                SVC_PSA_CALL_RETURN = const $crate::spm_api::SVC_PSA_CALL_RETURN,
            );
        }

        #[cfg(not(target_arch = "arm"))]
        pub unsafe extern "C" fn svc_handler() {
            unimplemented!("svc_handler is only available on ARM targets")
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

use psa_interface::status::StatusCode;
use psa_interface::types::{CtrlParam, FFInVec, FFOutVec, ServiceHandle};

use crate::spm::spm::PSA_MAX_IOVEC;

pub trait SpmApi {
    /// Executes a closure with read-only access to the specified input vector
    /// (`invec`).
    ///
    /// The closure `f` is called with a slice containing the data of the input
    /// vector. This provides direct memory access to the input vector
    /// without requiring a copy.
    fn access_invec<R>(
        &self,
        msg_handle: ServiceHandle,
        invec_idx: u32,
        f: impl FnOnce(&[u8]) -> R,
    ) -> R;

    /// Executes a closure with write-only access to the specified output vector
    /// (`outvec`).
    ///
    /// The closure `f` is called with a mutable slice for the output vector.
    /// The closure must return a tuple `(R, usize)`, where the `usize`
    /// represents the number of bytes written to the vector. The SPM will
    /// update the vector's length based on this value.
    fn access_outvec<R>(
        &self,
        msg_handle: ServiceHandle,
        outvec_idx: u32,
        f: impl FnOnce(&mut [u8]) -> (R, usize),
    ) -> R;

    /// Executes a closure with simultaneous access to an input vector and an
    /// output vector.
    ///
    /// The closure `f` receives both a read-only slice for the input vector
    /// and a mutable slice for the output vector. It must return a tuple `(R,
    /// usize)`, where the `usize` indicates the number of bytes written to
    /// the output vector.
    fn access_invec_outvec<R>(
        &self,
        msg_handle: ServiceHandle,
        invec_idx: u32,
        outvec_idx: u32,
        f: impl FnOnce(&[u8], &mut [u8]) -> (R, usize),
    ) -> R;

    /// Calls a service via the Secure Partition Manager (SPM).
    ///
    /// This function handles crossing the security boundary or IPC boundaries
    /// to deliver a request to the specified `handle`.
    ///
    /// # Safety
    ///
    /// The `in_vec` and `out_vec` pointers must be valid and the buffers they
    /// point to must outlive the duration of the call. The memory must not
    /// be mutated concurrently while the SPM or the target service accesses
    /// it.
    unsafe fn call(
        &self,
        handle: ServiceHandle,
        ctrl_param: CtrlParam,
        in_vec: *const FFInVec,
        out_vec: *mut FFOutVec,
    ) -> Result<(), StatusCode>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::CheckedBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct CallerAttributes {
    /// Caller is from the Non-Secure world.
    pub ns: bool,
    /// Caller is privileged (handler mode or nPRIV=0).
    pub privileged: bool,
}

impl CallerAttributes {
    pub const NS_PRIVILEGED: Self = Self {
        ns: true,
        privileged: true,
    };
    pub const NS_UNPRIVILEGED: Self = Self {
        ns: true,
        privileged: false,
    };
    pub const SECURE_PRIVILEGED: Self = Self {
        ns: false,
        privileged: true,
    };
    pub const SECURE_UNPRIVILEGED: Self = Self {
        ns: false,
        privileged: false,
    };
}

#[derive(Clone, Copy, Debug, bytemuck::CheckedBitPattern)]
#[repr(C)]
pub struct PsaMsg {
    pub handle: ServiceHandle,
    pub msg_type: i32,
    pub caller: CallerAttributes,
    pub in_size: [MaybeUsize; PSA_MAX_IOVEC],
    pub out_size: [MaybeUsize; PSA_MAX_IOVEC],
}

impl PsaMsg {
    pub const fn new(handle: ServiceHandle, msg_type: i32, caller: CallerAttributes) -> Self {
        Self {
            handle,
            msg_type,
            caller,
            in_size: [MaybeUsize::none(); PSA_MAX_IOVEC],
            out_size: [MaybeUsize::none(); PSA_MAX_IOVEC],
        }
    }
}

/// FFI-safe replacement for `Option<usize>` used inside `PsaMsg`.
///
/// We represent `None` as `usize::MAX` and `Some(v)` as `v`. Marked
/// `#[repr(transparent)]` so the layout is identical to `usize`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct MaybeUsize(pub usize);

impl MaybeUsize {
    pub const NONE_SENTINEL: usize = usize::MAX;

    pub const fn none() -> Self {
        Self(Self::NONE_SENTINEL)
    }

    pub const fn some(v: usize) -> Self {
        Self(v)
    }

    pub const fn is_some(&self) -> bool {
        self.0 != Self::NONE_SENTINEL
    }

    pub const fn is_none(&self) -> bool {
        self.0 == Self::NONE_SENTINEL
    }

    pub const fn as_option(&self) -> Option<usize> {
        if self.is_some() { Some(self.0) } else { None }
    }

    pub const fn unwrap_or(&self, default: usize) -> usize {
        if self.is_some() { self.0 } else { default }
    }

    /// # Panics
    ///
    /// Panics on invalid state.
    pub fn unwrap(&self) -> usize {
        if self.is_some() {
            self.0
        } else {
            panic!("called `MaybeUsize::unwrap()` on a None value")
        }
    }
}

impl From<Option<usize>> for MaybeUsize {
    fn from(opt: Option<usize>) -> Self {
        opt.map_or_else(Self::none, Self::some)
    }
}
