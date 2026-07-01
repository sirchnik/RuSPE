// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

pub mod ipc_platform;
pub mod process;
pub(crate) mod svc_call;

pub use ipc_platform::{CustomMpuRegion, IpcPlatform, IpcProcessPlatform};
pub use process::{EmbeddedProcess, IpcProcess, ServiceProcess, ServiceVectors};

use crate::libs::mutex::Mutex;
use crate::spm::spm::{Connection, ConnectionArray, SpmCall, SpmError};
use crate::spm_api::CallerAttributes;
use psa_interface::types::ServiceHandle;

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

pub struct SpmIpc<
    P: IpcProcessPlatform + 'static,
    const N: usize,
    Proc: IpcProcess = ServiceProcess,
> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spm_api::{CallerAttributes, PsaMsg};
    use psa_interface::types::ServiceHandle;

    #[test]
    fn test_spm_ipc_state_init() {
        let mut state = SpmIpcState::<2>::new();
        assert_eq!(state.mark_init_done(0), Ok(true));
        assert_eq!(state.mark_init_done(0), Ok(false)); // already done

        assert_eq!(state.mark_init_done(1), Ok(true));

        // Out of bounds
        assert_eq!(
            state.mark_init_done(2),
            Err(SpmError::CorruptedConnectionStack)
        );
    }

    struct MockPlatform;
    impl IpcPlatform for MockPlatform {
        fn has_permission_on_memory(
            &self,
            _base: *const u8,
            _len: usize,
            _is_write: bool,
            _caller: CallerAttributes,
        ) -> bool {
            true
        }

        fn custom_mpu_regions(&self, _handle: ServiceHandle) -> &[CustomMpuRegion] {
            &[]
        }
    }
    impl IpcProcessPlatform for MockPlatform {}

    struct MockProcess {
        handle: ServiceHandle,
    }

    // # Safety: test stub
    unsafe impl IpcProcess for MockProcess {
        fn handle(&self) -> ServiceHandle {
            self.handle
        }
        fn get_vectors(&self) -> Option<&'static ServiceVectors> {
            None
        }
        fn version(&self) -> u32 {
            1
        }
        unsafe fn init_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
            &self,
            _platform: &P,
            _spm: &S,
        ) {
        }
        unsafe fn call_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
            &self,
            _platform: &P,
            _spm: &S,
            _msg: PsaMsg,
        ) -> Result<(), crate::StatusCode> {
            Ok(())
        }
    }

    #[test]
    fn test_spm_ipc_find_process() {
        static PLATFORM: MockPlatform = MockPlatform;
        let processes = [
            MockProcess {
                handle: ServiceHandle::Crypto,
            },
            MockProcess {
                handle: ServiceHandle::AttestationService,
            },
        ];
        let spm = SpmIpc::new(&PLATFORM, processes);

        assert_eq!(spm.find_process_index(ServiceHandle::Crypto), Some(0));
        assert_eq!(
            spm.find_process_index(ServiceHandle::AttestationService),
            Some(1)
        );
        assert_eq!(
            spm.find_process_index(ServiceHandle::InternalTrustedStorageService),
            None
        );
    }

    #[test]
    fn test_spm_ipc_version() {
        static PLATFORM: MockPlatform = MockPlatform;
        let processes = [MockProcess {
            handle: ServiceHandle::Crypto,
        }];
        let spm = SpmIpc::new(&PLATFORM, processes);

        assert_eq!(spm.version(ServiceHandle::Crypto), Some(1));
        assert_eq!(spm.version(ServiceHandle::AttestationService), None);
    }
}
