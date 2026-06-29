// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use crate::service::Service;
use crate::spm::spm_fn::ConnectionArray;
use crate::spm::{Connection, SpmCall, SpmError, SpmPlatform};
use crate::spm_api::PsaMsg;
use crate::{libs::mutex::Mutex, spm::svc_call_unpriv, spm_api::CallerAttributes};
use core::mem::{align_of, size_of};
use psa_interface::types::{PsaStatus, ServiceHandle};

const EXCEPTION_FRAME_WORDS: usize = 8;

// ---------------------------------------------------------------------------
// FlashProcess - service loaded as a separate binary in flash
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug)]
pub struct FlashProcessVectors {
    pub version: u32,
    pub init_entry: unsafe extern "C" fn(),
    pub call_entry: unsafe extern "C" fn(*const PsaMsg) -> PsaStatus,
    /// Start of the service ROM window containing executable code and rodata.
    pub rom_start: *const u8,
    /// Exclusive end of the service ROM window.
    pub rom_limit: *const u8,
    /// Start of the service RAM window containing data, bss, and stack.
    pub ram_start: *const u8,
    /// Exclusive end of the service RAM window.
    pub ram_limit: *const u8,
    /// A minimal thunk in the service's flash region that executes `svc {SVC_PROCESS_EXIT}`
    /// to re-elevate after the unprivileged service function returns.
    pub svc_return: unsafe extern "C" fn(),
    /// Lowest permitted PSP value for the service's dedicated stack window.
    /// The SPM programs PSPLIM to this address before entering the service.
    pub stack_limit: *const u8,
    /// Top of the service's stack in RAM (8-byte aligned).
    /// Used to place the PSP exception frame before each unprivileged call.
    pub stack_top: *const u8,
}

pub trait IpcProcessPlatform: SpmPlatform {
    fn prepare_process(&self, _vectors: &FlashProcessVectors) {}
}

/// A process that can be managed and dispatched by the SPM IPC mechanism.
///
/// Implementors represent either a flash-resident service binary (`FlashProcess`)
/// or a service compiled directly into the SPM binary (`EmbeddedProcess`).
///
/// # Safety
///
/// Implementors must ensure that `init()` and `call()` are safe to invoke
/// in the unprivileged execution context provided by the SPM.
pub unsafe trait IpcProcess: Sync {
    fn handle(&self) -> ServiceHandle;
    fn get_vectors(&self) -> Option<&'static FlashProcessVectors>;
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

// # Safety
// FlashProcessVectors contains raw pointers to fixed ROM/RAM addresses that are
// immutable for the lifetime of the program.
unsafe impl Sync for FlashProcessVectors {}

#[derive(Clone, Copy, Debug)]
pub struct FlashProcess {
    pub handle: ServiceHandle,
    pub vectors: &'static FlashProcessVectors,
}

impl FlashProcess {
    pub const fn new(handle: ServiceHandle, vectors: &'static FlashProcessVectors) -> Self {
        Self { handle, vectors }
    }

    fn align_down(addr: usize, align: usize) -> usize {
        debug_assert!(align.is_power_of_two());
        addr & !(align - 1)
    }

    fn stage_msg_mailbox(vectors: &FlashProcessVectors, msg: PsaMsg) -> (*const PsaMsg, usize) {
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

        let mailbox = mailbox_addr as *mut PsaMsg;
        unsafe {
            mailbox.write(msg);
        }

        (mailbox.cast_const(), mailbox_addr)
    }
}

// # Safety
// FlashProcess vectors are assumed valid and immutable in flash for the lifetime
// of the program. The caller of SpmIpc ensures correct flash layout.
unsafe impl IpcProcess for FlashProcess {
    fn handle(&self) -> ServiceHandle {
        self.handle
    }

    fn get_vectors(&self) -> Option<&'static FlashProcessVectors> {
        Some(self.vectors)
    }

    fn version(&self) -> u32 {
        unsafe { (*self.vectors).version }
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
                vectors.svc_return as usize,
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
                vectors.svc_return as usize,
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

    fn get_vectors(&self) -> Option<&'static FlashProcessVectors> {
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

// ---------------------------------------------------------------------------
// SpmIpc - IPC-style SPM dispatcher, generic over process type
// ---------------------------------------------------------------------------

struct SpmIpcState<const N: usize> {
    connections: ConnectionArray,
    init_done: [bool; N],
}

impl<const N: usize> SpmIpcState<N> {
    pub const fn new() -> Self {
        Self {
            connections: ConnectionArray::new(),
            init_done: [false; N],
        }
    }

    fn mark_init_done(&mut self, index: usize) -> Result<bool, SpmError> {
        if index >= N {
            return Err(SpmError::CorruptedConnectionStack);
        }

        if self.init_done[index] {
            Ok(false)
        } else {
            self.init_done[index] = true;
            Ok(true)
        }
    }
}

pub struct SpmIpc<P: IpcProcessPlatform + 'static, const N: usize, Proc: IpcProcess = FlashProcess>
{
    state: Mutex<SpmIpcState<N>>,
    platform: &'static P,
    processes: [Proc; N],
}

impl<P: IpcProcessPlatform + 'static, const N: usize, Proc: IpcProcess> SpmIpc<P, N, Proc> {
    pub const fn new(platform: &'static P, processes: [Proc; N]) -> Self {
        Self {
            state: Mutex::new(SpmIpcState::new()),
            platform,
            processes,
        }
    }

    fn find_process_index(&self, handle: ServiceHandle) -> Option<usize> {
        self.processes
            .iter()
            .position(|process| (process.handle() as isize) == (handle as isize))
    }

    fn with_active_connection<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> R,
    ) -> Result<R, SpmError> {
        let (index, mut connection) = match self
            .state
            .try_lock(|state| state.connections.take_active_connection())
        {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => return Err(err),
            Err(()) => return Err(SpmError::MutexBusy),
        };

        let result = f(&mut connection);

        match self.state.try_lock(|state| {
            state
                .connections
                .restore_active_connection(index, connection)
        }) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(()) => return Err(SpmError::MutexBusy),
        }
        Ok(result)
    }

    fn apply_mpu_config(&self, process_index: usize) {
        use cortex_m::mpu::{MPU, Permissions};

        let vectors = self.processes[process_index].get_vectors();
        let Some(vectors) = vectors else {
            return;
        };

        let mpu = unsafe { MPU::<8>::new() };

        let mut config = mpu.new_config().expect("MPU config slots exhausted");

        let service_rom_start = vectors.rom_start;
        let service_rom_size = (vectors.rom_limit as usize)
            .checked_sub(vectors.rom_start as usize)
            .unwrap();
        let service_ram_start = vectors.ram_start;
        let service_ram_size = (vectors.ram_limit as usize)
            .checked_sub(vectors.ram_start as usize)
            .unwrap();
        mpu.allocate_region(
            service_rom_start,
            service_rom_size,
            Permissions::ReadExecuteOnly,
            &mut config,
        )
        .unwrap();
        mpu.allocate_region(
            service_ram_start,
            service_ram_size,
            Permissions::ReadWriteOnly,
            &mut config,
        )
        .unwrap();

        let handle = self.processes[process_index].handle();
        for region in self.platform.custom_mpu_regions(handle) {
            mpu.allocate_region(region.base, region.size, region.permissions, &mut config)
                .unwrap();
        }

        self.state
            .try_lock(|state| {
                if let Ok(conn) = state.connections.peek_active_connection() {
                    if self.find_process_index(conn.msg.handle) == Some(process_index) {
                        for (i, &is_mapped) in conn.invec_mapped.iter().enumerate() {
                            if is_mapped && !conn.invec_unmapped[i] {
                                if let Some(size) = conn.msg.in_size[i] {
                                    if size > 0 {
                                        let base_addr = conn.invec_base[i] as usize;
                                        let aligned_base = base_addr & !0x1F;
                                        let aligned_end = (base_addr + size + 0x1F) & !0x1F;
                                        let aligned_size = aligned_end - aligned_base;
                                        mpu.allocate_region(
                                            aligned_base as *const u8,
                                            aligned_size,
                                            Permissions::ReadOnly,
                                            &mut config,
                                        )
                                        .unwrap();
                                    }
                                }
                            }
                        }
                        for (i, &is_mapped) in conn.outvec_mapped.iter().enumerate() {
                            if is_mapped && !conn.outvec_unmapped[i] {
                                if let Some(size) = conn.msg.out_size[i] {
                                    if size > 0 {
                                        let base_addr = conn.outvec_base[i] as usize;
                                        let aligned_base = base_addr & !0x1F;
                                        let aligned_end = (base_addr + size + 0x1F) & !0x1F;
                                        let aligned_size = aligned_end - aligned_base;
                                        mpu.allocate_region(
                                            aligned_base as *const u8,
                                            aligned_size,
                                            Permissions::ReadWriteOnly,
                                            &mut config,
                                        )
                                        .unwrap();
                                    }
                                }
                            }
                        }
                    }
                }
            })
            .unwrap();

        unsafe {
            mpu.configure_mpu(&config);
        }
        mpu.enable_app_mpu();
    }
}

impl<P: IpcProcessPlatform + 'static, const N: usize, Proc: IpcProcess> SpmCall
    for SpmIpc<P, N, Proc>
{
    fn call(&self, connection: Connection) -> Result<(), crate::StatusCode> {
        let process_index = match self.find_process_index(connection.msg.handle) {
            Some(index) => index,
            None => return Err(crate::StatusCode::NotSupported),
        };

        let msg = connection.msg;

        let should_init = match self.state.try_lock(|state| {
            state.connections.add_connection(connection)?;
            state.mark_init_done(process_index)
        }) {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => panic!("SPM connection stack exhausted"),
            Err(()) => panic!("SPM connection stack busy"),
        };

        self.apply_mpu_config(process_index);

        if should_init {
            // # Safety:
            // Process init is safe per the IpcProcess safety contract.
            unsafe { self.processes[process_index].init_process(self.platform, self) };
        }

        // # Safety:
        // Process call is safe per the IpcProcess safety contract.
        let result =
            unsafe { self.processes[process_index].call_process(self.platform, self, msg) };

        // Restore MPU of previous process, if any
        let prev_process_index = self
            .state
            .try_lock(|state| {
                state.connections.pop_connection();
                match state.connections.take_active_connection() {
                    Ok((idx, conn)) => {
                        let process_index = self.find_process_index(conn.msg.handle).unwrap();
                        state
                            .connections
                            .restore_active_connection(idx, conn)
                            .unwrap();
                        Some(process_index)
                    }
                    Err(_) => None,
                }
            })
            .unwrap();

        if let Some(prev) = prev_process_index {
            self.apply_mpu_config(prev);
        }

        result
    }

    fn with_active_connection<F: FnMut(&mut Connection)>(&self, mut f: F) -> Result<(), SpmError> {
        self.with_active_connection(|conn| f(conn))
    }

    fn has_real_permission(
        &self,
        base: *const u8,
        len: usize,
        is_write: bool,
        caller: CallerAttributes,
    ) -> bool {
        self.platform
            .has_permission_on_memory(base, len, is_write, caller)
    }

    fn map_vec(&self, is_outvec: bool, vec_idx: u32, _base: *const u8, _size: usize) {
        let mut process_index = 0;
        self.state
            .try_lock(|state| {
                let (conn_idx, mut conn) = state.connections.take_active_connection().unwrap();
                process_index = self.find_process_index(conn.msg.handle).unwrap();

                if is_outvec {
                    conn.outvec_mapped[vec_idx as usize] = true;
                    conn.outvec_unmapped[vec_idx as usize] = false;
                } else {
                    conn.invec_mapped[vec_idx as usize] = true;
                    conn.invec_unmapped[vec_idx as usize] = false;
                }

                state
                    .connections
                    .restore_active_connection(conn_idx, conn)
                    .unwrap();
            })
            .unwrap();

        self.apply_mpu_config(process_index);
    }

    fn unmap_vec(&self, is_outvec: bool, vec_idx: u32) {
        let mut process_index = 0;
        self.state
            .try_lock(|state| {
                let (conn_idx, mut conn) = state.connections.take_active_connection().unwrap();
                process_index = self.find_process_index(conn.msg.handle).unwrap();

                if is_outvec {
                    conn.outvec_mapped[vec_idx as usize] = false;
                    conn.outvec_unmapped[vec_idx as usize] = true;
                } else {
                    conn.invec_mapped[vec_idx as usize] = false;
                    conn.invec_unmapped[vec_idx as usize] = true;
                }

                state
                    .connections
                    .restore_active_connection(conn_idx, conn)
                    .unwrap();
            })
            .unwrap();

        self.apply_mpu_config(process_index);
    }

    fn version(&self, handle: ServiceHandle) -> Option<u32> {
        self.find_process_index(handle)
            .map(|i| self.processes[i].version())
    }
}
