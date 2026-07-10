// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use core::mem::{align_of, size_of};

use psa_interface::types::{PsaStatus, ServiceHandle};

use super::ipc_platform::IpcProcessPlatform;
use super::svc_call::{EXCEPTION_FRAME_WORDS, svc_call_unpriv};
use crate::service::Service;
use crate::spm::spm::SpmCall;
use crate::spm_api::PsaMsg;

// ---------------------------------------------------------------------------
// ServiceProcess - service loaded as a separate binary in flash
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug)]
pub struct ServiceVectors {
    pub version: u32,
    pub init_entry: unsafe extern "C" fn(),
    pub call_entry: unsafe extern "C" fn(*const PsaMsg) -> !,
    /// Start of the service ROM window containing executable code and rodata.
    pub rom_start: *const u8,
    /// Exclusive end of the service ROM window.
    pub rom_limit: *const u8,
    /// Start of the service RAM window containing data, bss, and stack.
    pub ram_start: *const u8,
    /// Exclusive end of the service RAM window.
    pub ram_limit: *const u8,
    /// Lowest permitted PSP value for the service's dedicated stack window.
    /// The SPM programs PSPLIM to this address before entering the service.
    pub stack_limit: *const u8,
    /// Top of the service's stack in RAM (8-byte aligned).
    /// Used to place the PSP exception frame before each unprivileged call.
    pub stack_top: *const u8,
}

// # Safety
// ServiceVectors contains raw pointers to fixed ROM/RAM addresses that are
// immutable for the lifetime of the program.
unsafe impl Sync for ServiceVectors {}

/// A process that can be managed and dispatched by the SPM IPC mechanism.
///
/// Implementors represent either a flash-resident service binary
/// (`ServiceProcess`) or a service compiled directly into the SPM binary
/// (`EmbeddedProcess`).
///
/// # Safety
///
/// Implementors must ensure that `init()` and `call()` are safe to invoke
/// in the unprivileged execution context provided by the SPM.
pub unsafe trait IpcProcess: Sync {
    fn handle(&self) -> ServiceHandle;
    fn get_vectors(&self) -> Option<&'static ServiceVectors>;
    fn version(&self) -> u32;

    /// One-time initialization, called before the first `call()`.
    ///
    /// # Safety
    /// For flash processes, the entry point vectors must be valid.
    unsafe fn init_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
        &self,
        platform: &P,
        spm: &S,
    );

    /// Dispatch a service call. The connection is already on the SPM stack.
    ///
    /// # Safety
    /// For flash processes, the entry point vectors must be valid.
    unsafe fn call_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
        &self,
        platform: &P,
        spm: &S,
        msg: PsaMsg,
    ) -> Result<(), crate::StatusCode>;
}

#[derive(Clone, Copy, Debug)]
pub struct ServiceProcess {
    pub handle: ServiceHandle,
    pub vectors: &'static ServiceVectors,
}

impl ServiceProcess {
    pub const fn new(handle: ServiceHandle, vectors: &'static ServiceVectors) -> Self {
        Self { handle, vectors }
    }

    fn align_down(addr: usize, align: usize) -> usize {
        debug_assert!(align.is_power_of_two());
        addr & !(align - 1)
    }

    fn stage_msg_mailbox(vectors: &ServiceVectors, msg: PsaMsg) -> (*const PsaMsg, usize) {
        let stack_top = vectors.stack_top as usize;
        let stack_limit = vectors.stack_limit as usize;
        let msg_align = core::cmp::max(align_of::<PsaMsg>(), 8);
        let msg_size = size_of::<PsaMsg>();
        let frame_size = EXCEPTION_FRAME_WORDS * size_of::<usize>();

        let mailbox_addr = Self::align_down(
            stack_top
                .checked_sub(msg_size)
                .expect("service stack too small for staged message"),
            msg_align,
        );

        let frame_base = mailbox_addr
            .checked_sub(frame_size)
            .expect("service stack too small for staged message frame");
        assert!(
            frame_base >= stack_limit,
            "service stack limit overlaps staged message and exception frame"
        );

        let ram_start = vectors.ram_start as usize;
        let ram_limit = vectors.ram_limit as usize;
        assert!(
            mailbox_addr >= ram_start && mailbox_addr + msg_size <= ram_limit,
            "staged message mailbox must remain within service RAM"
        );

        let offset = stack_top - mailbox_addr;
        let mailbox = vectors
            .stack_top
            .wrapping_sub(offset)
            .cast_mut()
            .cast::<PsaMsg>();
        unsafe {
            mailbox.write(msg);
        }

        (mailbox.cast_const(), mailbox_addr)
    }
}

// # Safety
// ServiceProcess vectors are assumed valid and immutable in flash for the
// lifetime of the program. The caller of SpmIpc ensures correct flash layout.
unsafe impl IpcProcess for ServiceProcess {
    fn handle(&self) -> ServiceHandle {
        self.handle
    }

    fn get_vectors(&self) -> Option<&'static ServiceVectors> {
        Some(self.vectors)
    }

    fn version(&self) -> u32 {
        self.vectors.version
    }

    unsafe fn init_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
        &self,
        _platform: &P,
        _spm: &S,
    ) {
        let vectors = self.vectors;
        unsafe {
            svc_call_unpriv(
                vectors.init_entry as usize,
                0,
                vectors.stack_limit as usize,
                vectors.stack_top as usize,
            );
        }
    }

    unsafe fn call_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
        &self,
        _platform: &P,
        _spm: &S,
        msg: PsaMsg,
    ) -> Result<(), crate::StatusCode> {
        let vectors = self.vectors;
        let (staged_msg, stack_top) = Self::stage_msg_mailbox(vectors, msg);
        let status = unsafe {
            svc_call_unpriv(
                vectors.call_entry as usize,
                staged_msg as usize,
                vectors.stack_limit as usize,
                stack_top,
            )
        } as PsaStatus;
        match crate::StatusCode::try_from(status) {
            Ok(crate::StatusCode::_Success) => Ok(()),
            Ok(err) => Err(err),
            Err(_) => Err(crate::StatusCode::CommunicationFailure),
        }
    }
}

// ---------------------------------------------------------------------------
// EmbeddedProcess - service compiled into the SPM binary
// ---------------------------------------------------------------------------

pub struct EmbeddedProcess<A: crate::spm_api::SpmApi + Sync + 'static> {
    pub handle: ServiceHandle,
    pub version: u32,
    service: &'static (dyn Service<A> + Sync),
    api: &'static A,
}

// # Safety
unsafe impl<A: crate::spm_api::SpmApi + Sync + 'static> Sync for EmbeddedProcess<A> {}

impl<A: crate::spm_api::SpmApi + Sync + 'static> EmbeddedProcess<A> {
    pub const fn new(
        handle: ServiceHandle,
        version: u32,
        service: &'static (dyn Service<A> + Sync),
        api: &'static A,
    ) -> Self {
        Self {
            handle,
            version,
            service,
            api,
        }
    }
}

// # Safety
// The embedded service runs in the same binary; its call() only accesses the
unsafe impl<A: crate::spm_api::SpmApi + Sync + 'static> IpcProcess for EmbeddedProcess<A> {
    fn handle(&self) -> ServiceHandle {
        self.handle
    }

    fn get_vectors(&self) -> Option<&'static ServiceVectors> {
        None
    }

    fn version(&self) -> u32 {
        self.version
    }

    unsafe fn init_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
        &self,
        _platform: &P,
        _spm: &S,
    ) {
        // Embedded services are fully initialized at construction time.
    }

    unsafe fn call_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
        &self,
        _platform: &P,
        _spm: &S,
        msg: PsaMsg,
    ) -> Result<(), crate::StatusCode> {
        self.service.call(msg, self.api)
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn test_align_down() {
        assert_eq!(ServiceProcess::align_down(100, 8), 96);
        assert_eq!(ServiceProcess::align_down(100, 16), 96);
        assert_eq!(ServiceProcess::align_down(100, 32), 96);
        assert_eq!(ServiceProcess::align_down(64, 8), 64);
        assert_eq!(ServiceProcess::align_down(0, 8), 0);
    }

    #[test]
    fn test_stage_msg_mailbox() {
        // Create a dummy RAM buffer
        let mut ram = [0u8; 1024];
        let ram_start = ram.as_mut_ptr();
        let ram_limit = unsafe { ram_start.add(ram.len()) };

        let stack_top = unsafe { ram_limit.sub(16) }; // 16 bytes for padding
        let stack_limit = ram_start;

        let msg = PsaMsg {
            handle: ServiceHandle::Crypto,
            msg_type: 0,
            caller: crate::spm_api::CallerAttributes::SECURE_UNPRIVILEGED,
            in_size: [None; 4],
            out_size: [None; 4],
        };

        unsafe extern "C" fn dummy_init() {}
        unsafe extern "C" fn dummy_call(_: *const PsaMsg) -> ! {
            loop {}
        }

        // Create a dummy ServiceVectors
        let vectors = ServiceVectors {
            version: 1,
            init_entry: dummy_init,
            call_entry: dummy_call,
            rom_start: core::ptr::null(),
            rom_limit: core::ptr::null(),
            ram_start,
            ram_limit,
            stack_limit,
            stack_top,
        };

        let (msg_ptr, msg_addr) = ServiceProcess::stage_msg_mailbox(&vectors, msg);

        // Assertions
        assert_eq!(msg_addr, msg_ptr as usize);
        assert!(msg_addr >= ram_start as usize);
        assert!(msg_addr + size_of::<PsaMsg>() <= stack_top as usize);
        assert_eq!(
            msg_addr % core::cmp::max(core::mem::align_of::<PsaMsg>(), 8),
            0
        );

        // Ensure message was written
        let read_msg = unsafe { &*msg_ptr };
        assert_eq!(read_msg.handle, ServiceHandle::Crypto);
    }
}
