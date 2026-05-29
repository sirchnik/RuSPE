use crate::psa::psa_call::PsaMsg;
use crate::service::Service;
use crate::spm::spm_fn::ConnectionArray;
use crate::spm::{Connection, SpmCall, SpmError, SpmPlatform};
use crate::{libs::mutex::Mutex, psa::psa_call::CallerAttributes, spm::svc_call_unpriv};
use core::mem::{align_of, size_of};
use psa_interface::types::{PsaStatus, ServiceHandle};

const EXCEPTION_FRAME_WORDS: usize = 8;

// ---------------------------------------------------------------------------
// FlashProcess – service loaded as a separate binary in flash
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct FlashProcessVectors {
    pub init: unsafe extern "C" fn(),
    pub call: unsafe extern "C" fn(*const PsaMsg) -> PsaStatus,
    /// Start of the service ROM window containing executable code and rodata.
    pub rom_start: *const u8,
    /// Exclusive end of the service ROM window.
    pub rom_limit: *const u8,
    /// Start of the service RAM window containing data, bss, and stack.
    pub ram_start: *const u8,
    /// Exclusive end of the service RAM window.
    pub ram_limit: *const u8,
    /// A minimal thunk in the service's flash region that executes `svc #0`
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

    /// One-time initialization, called before the first `call()`.
    ///
    /// # Safety
    /// For flash processes, the entry point vectors must be valid.
    unsafe fn init(&self, platform: &dyn IpcProcessPlatform);

    /// Dispatch a service call. The connection is already on the SPM stack.
    ///
    /// # Safety
    /// For flash processes, the entry point vectors must be valid.
    unsafe fn call(
        &self,
        platform: &dyn IpcProcessPlatform,
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
    pub vectors: *const FlashProcessVectors,
}

// # Safety
// FlashProcess is Sync because it only contains a raw pointer to flash-resident
// vectors that are assumed immutable for the lifetime of the program.
unsafe impl Sync for FlashProcess {}

// # Safety
// FlashProcess is Send because the entry point pointers are immutable and can be
// invoked from any context that upholds the platform's execution constraints.
unsafe impl Send for FlashProcess {}

impl FlashProcess {
    pub const fn new(handle: ServiceHandle, vectors: *const FlashProcessVectors) -> Self {
        Self { handle, vectors }
    }

    fn align_down(addr: usize, align: usize) -> usize {
        debug_assert!(align.is_power_of_two());
        addr & !(align - 1)
    }

    fn stage_msg_mailbox(vectors: &FlashProcessVectors, msg: PsaMsg) -> (*const PsaMsg, usize) {
        let stack_top = vectors.stack_top as usize;
        let stack_limit = vectors.stack_limit as usize;
        let msg_align = align_of::<PsaMsg>();
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

        (mailbox as *const PsaMsg, mailbox_addr)
    }
}

// # Safety
// FlashProcess vectors are assumed valid and immutable in flash for the lifetime
// of the program. The caller of SpmIpc ensures correct flash layout.
unsafe impl IpcProcess for FlashProcess {
    fn handle(&self) -> ServiceHandle {
        self.handle
    }

    unsafe fn init(&self, platform: &dyn IpcProcessPlatform) {
        let vectors = unsafe { &*self.vectors };
        platform.prepare_process(vectors);
        unsafe {
            svc_call_unpriv(
                vectors.init as usize,
                0,
                vectors.svc_return as usize,
                vectors.stack_limit as usize,
                vectors.stack_top as usize,
            );
        }
    }

    unsafe fn call(
        &self,
        platform: &dyn IpcProcessPlatform,
        msg: PsaMsg,
    ) -> Result<(), crate::StatusCode> {
        let vectors = unsafe { &*self.vectors };
        platform.prepare_process(vectors);
        let (staged_msg, stack_top) = Self::stage_msg_mailbox(vectors, msg);
        let status = unsafe {
            svc_call_unpriv(
                vectors.call as usize,
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
// EmbeddedProcess – service compiled into the SPM binary
// ---------------------------------------------------------------------------

pub struct EmbeddedProcess {
    pub handle: ServiceHandle,
    service: &'static (dyn Service + Sync),
}

// # Safety
// EmbeddedProcess holds a &'static reference to a Sync service.
unsafe impl Sync for EmbeddedProcess {}

impl EmbeddedProcess {
    pub fn new(handle: ServiceHandle, service: &'static (dyn Service + Sync)) -> Self {
        Self { handle, service }
    }
}

// # Safety
// The embedded service runs in the same binary; its call() only accesses the
// SPM connection stack through the safe PSA API. Safe to invoke unprivileged.
unsafe impl IpcProcess for EmbeddedProcess {
    fn handle(&self) -> ServiceHandle {
        self.handle
    }

    unsafe fn init(&self, _platform: &dyn IpcProcessPlatform) {
        // Embedded services are fully initialized at construction time.
    }

    unsafe fn call(
        &self,
        _platform: &dyn IpcProcessPlatform,
        msg: PsaMsg,
    ) -> Result<(), crate::StatusCode> {
        self.service.call(msg)
    }
}

// ---------------------------------------------------------------------------
// SpmIpc – IPC-style SPM dispatcher, generic over process type
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

        if should_init {
            // # Safety:
            // Process init is safe per the IpcProcess safety contract.
            unsafe { self.processes[process_index].init(self.platform) };
        }

        // # Safety:
        // Process call is safe per the IpcProcess safety contract.
        unsafe { self.processes[process_index].call(self.platform, msg) }
    }

    fn with_active_connection(&self, f: &mut dyn FnMut(&mut Connection)) -> Result<(), SpmError> {
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
}
