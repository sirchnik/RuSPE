// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use cortex_m::mpu::MpuConfig;
use psa_interface::types::ServiceHandle;

use crate::libs::mutex::Mutex;
use crate::spm::spm::{Connection, ConnectionArray, SpmCall, SpmError};
use crate::spm::spm_ipc::ipc_platform::IpcProcessPlatform;
use crate::spm::spm_ipc::process::{IpcProcess, ServiceProcess};
use crate::spm_api::CallerAttributes;

// ---------------------------------------------------------------------------
// SpmIpc - IPC-style SPM dispatcher
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

    fn update_vec_mapping(&self, is_outvec: bool, vec_idx: u32, mapped: bool) {
        let mut process_index = 0;
        self.with_active_connection(|conn| {
            process_index = self.find_process_index(conn.msg.handle).unwrap();
            let idx = vec_idx as usize;
            if is_outvec {
                conn.outvec_mapped[idx] = mapped;
                conn.outvec_unmapped[idx] = !mapped;
            } else {
                conn.invec_mapped[idx] = mapped;
                conn.invec_unmapped[idx] = !mapped;
            }
        })
        .unwrap();

        self.apply_mpu_config(process_index);
    }

    fn apply_mpu_config(&self, process_index: usize) {
        use cortex_m::mpu::{Mpu, Permissions};

        let vectors = self.processes[process_index].get_vectors();
        let Some(vectors) = vectors else {
            return;
        };

        let mpu = Mpu::<8>::new();

        let mut config = MpuConfig::default();

        let rom = vectors.rom_region();
        let ram = vectors.ram_region();
        mpu.allocate_region(rom.base, rom.size, Permissions::ReadExecute, &mut config)
            .unwrap();
        mpu.allocate_region(ram.base, ram.size, Permissions::ReadWriteXN, &mut config)
            .unwrap();

        let handle = self.processes[process_index].handle();
        for region in self.platform.custom_mpu_regions(handle) {
            mpu.allocate_region(region.base, region.size, region.permissions, &mut config)
                .unwrap();
        }

        let mut allocate_vec = |base_addr: usize, size: usize, permissions| {
            if size > 0 {
                let aligned_base = base_addr & !0x1F;
                let aligned_end = (base_addr + size + 0x1F) & !0x1F;
                let aligned_size = aligned_end - aligned_base;
                mpu.allocate_region(
                    aligned_base as *const u8,
                    aligned_size,
                    permissions,
                    &mut config,
                )
                .unwrap();
            }
        };

        self.state
            .try_lock(|state| {
                if let Ok(conn) = state.connections.peek_active_connection() {
                    if self.find_process_index(conn.msg.handle) == Some(process_index) {
                        for i in 0..conn.invec_mapped.len() {
                            if conn.invec_mapped[i] && !conn.invec_unmapped[i] {
                                if let Some(size) = conn.msg.in_size[i].as_option() {
                                    allocate_vec(
                                        conn.invec_base[i] as usize,
                                        size,
                                        Permissions::ReadXN,
                                    );
                                }
                            }
                        }
                        for i in 0..conn.outvec_mapped.len() {
                            if conn.outvec_mapped[i] && !conn.outvec_unmapped[i] {
                                if let Some(size) = conn.msg.out_size[i].as_option() {
                                    allocate_vec(
                                        conn.outvec_base[i] as usize,
                                        size,
                                        Permissions::ReadWriteXN,
                                    );
                                }
                            }
                        }
                    }
                }
            })
            .unwrap();

        unsafe {
            mpu.configure_mpu(&config);
            mpu.enable_mpu();
        }
    }

    #[inline(never)]
    fn fun_name(&self) -> Option<usize> {
        let prev_process_index = self
            .state
            .try_lock(|state| {
                state.connections.pop_connection();
                state
                    .connections
                    .peek_active_connection()
                    .ok()
                    .and_then(|conn| self.find_process_index(conn.msg.handle))
            })
            .unwrap();
        prev_process_index
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
            self.processes[process_index].init_process(self.platform, self);
        }

        let result = self.processes[process_index].call_process(self.platform, self, msg);

        // Restore MPU of previous process, if any
        let prev_process_index = self.fun_name();

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
        self.update_vec_mapping(is_outvec, vec_idx, true);
    }

    fn unmap_vec(&self, is_outvec: bool, vec_idx: u32) {
        self.update_vec_mapping(is_outvec, vec_idx, false);
    }

    fn version(&self, handle: ServiceHandle) -> Option<u32> {
        self.find_process_index(handle)
            .map(|i| self.processes[i].version())
    }
}

#[cfg(test)]
mod tests {
    use psa_interface::types::ServiceHandle;

    use super::*;
    use crate::spm::spm_ipc::{
        CustomMpuRegion, IpcPlatform, IpcProcess, IpcProcessPlatform, ServiceVectors,
    };
    use crate::spm_api::{CallerAttributes, PsaMsg};

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

    impl IpcProcess for MockProcess {
        fn handle(&self) -> ServiceHandle {
            self.handle
        }

        fn get_vectors(&self) -> Option<&'static ServiceVectors> {
            None
        }

        fn version(&self) -> u32 {
            1
        }

        fn init_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
            &self,
            _platform: &P,
            _spm: &S,
        ) {
        }

        fn call_process<P: IpcProcessPlatform + ?Sized, S: SpmCall>(
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
