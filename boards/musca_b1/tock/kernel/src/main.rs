// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributers 2026.

//! Tock kernel for the Musca B1 (Non-Secure)

#![no_std]
#![no_main]

use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
use kernel::component::Component;
use kernel::debug::PanicResources;
use kernel::platform::chip::Chip;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::syscall::SyscallDriver;
use kernel::utilities::single_thread_value::SingleThreadValue;
use kernel::{Kernel, capabilities, create_capability, static_init};
use musca_b1::BASE_VECTORS;
use musca_b1::chip::{MuscaB1, MuscaB1DefaultPeripherals};
use musca_b1::timer::CMSDKTimer;

mod io;

// Allocate memory for the stack
kernel::stack_size! {0x3000}

// State for loading and holding applications.
// How should the kernel respond when a process faults.
const FAULT_RESPONSE: capsules_system::process_policies::PanicFaultPolicy =
    capsules_system::process_policies::PanicFaultPolicy {};

// Number of concurrent processes this platform supports.
const NUM_PROCS: usize = 4;
#[unsafe(link_section = ".apps")]
#[used]
static DUMMY_APPS: [u8; 24576] = [0; 24576];

type ChipHw = MuscaB1<'static, MuscaB1DefaultPeripherals<'static>>;
type ProcessPrinterInUse = capsules_system::process_printer::ProcessPrinterText;

/// Resources for when a board panics used by io.rs.
static PANIC_RESOURCES: SingleThreadValue<PanicResources<ChipHw, ProcessPrinterInUse>> =
    SingleThreadValue::new();

type SchedulerInUse = components::sched::round_robin::RoundRobinComponentType;

/// Supported drivers by the platform
pub struct MuscaB1Plattform {
    ipc: kernel::ipc::IPC<{ NUM_PROCS as u8 }>,
    console: &'static capsules_core::console::Console<'static>,
    scheduler: &'static SchedulerInUse,
    systick: cortexm33::systick::SysTick,
    alarm: &'static capsules_core::alarm::AlarmDriver<
        'static,
        VirtualMuxAlarm<'static, CMSDKTimer<'static>>,
    >,
    #[cfg(feature = "non_secure_tz")]
    spe_client: &'static tock_spe_adapter::SpeAdapter,
}

impl SyscallDriverLookup for MuscaB1Plattform {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn SyscallDriver>) -> R,
    {
        match driver_num {
            capsules_core::console::DRIVER_NUM => f(Some(self.console)),
            capsules_core::alarm::DRIVER_NUM => f(Some(self.alarm)),
            kernel::ipc::DRIVER_NUM => f(Some(&self.ipc)),
            #[cfg(feature = "non_secure_tz")]
            tock_spe_adapter::DRIVER_NUM => f(Some(self.spe_client)),
            _ => f(None),
        }
    }
}

impl KernelResources<MuscaB1<'static, MuscaB1DefaultPeripherals<'static>>> for MuscaB1Plattform {
    type ContextSwitchCallback = ();
    type ProcessFault = ();
    type Scheduler = SchedulerInUse;
    type SchedulerTimer = cortexm33::systick::SysTick;
    type SyscallDriverLookup = Self;
    type SyscallFilter = ();
    type WatchDog = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        self
    }

    fn syscall_filter(&self) -> &Self::SyscallFilter {
        &()
    }

    fn process_fault(&self) -> &Self::ProcessFault {
        &()
    }

    fn scheduler(&self) -> &Self::Scheduler {
        self.scheduler
    }

    fn scheduler_timer(&self) -> &Self::SchedulerTimer {
        &self.systick
    }

    fn watchdog(&self) -> &Self::WatchDog {
        &()
    }

    fn context_switch_callback(&self) -> &Self::ContextSwitchCallback {
        &()
    }
}

// These symbols are defined in the linker script.
unsafe extern "C" {
    /// Beginning of the ROM region containing app images.
    static _sapps: u8;
    /// End of the ROM region containing app images.
    static _eapps: u8;
    /// Beginning of the RAM region for app memory.
    static mut _sappmem: u8;
    /// End of the RAM region for app memory.
    static _eappmem: u8;
    /// Beginning of the stack region.
    static _sstack: u8;
}

#[inline(never)]
pub unsafe fn start() -> (
    &'static kernel::Kernel,
    MuscaB1Plattform,
    &'static MuscaB1<'static, MuscaB1DefaultPeripherals<'static>>,
) {
    // set vector-table when coming from secure world
    unsafe {
        cortexm33::scb::set_vector_table_offset(BASE_VECTORS.as_ptr().cast::<()>());
    }

    unsafe { cortex_m::register::set_msplim(core::ptr::addr_of!(_sstack) as u32) };

    ChipHw::init();

    // Initialize deferred calls very early.
    kernel::deferred_call::initialize_deferred_call_state::<
        <ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider,
    >();

    // Bind global variables to this thread.
    let _ = PANIC_RESOURCES
        .bind_to_thread::<<ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider>(
            PanicResources::new(),
        );

    let peripherals = unsafe {
        static_init!(
            MuscaB1DefaultPeripherals,
            MuscaB1DefaultPeripherals::new_uart1_non_secure()
        )
    };
    peripherals.init();

    // Set the UART used for panic

    let chip = unsafe {
        static_init!(
            MuscaB1<MuscaB1DefaultPeripherals>,
            MuscaB1::new(peripherals)
        )
    };
    PANIC_RESOURCES.get().map(|resources| {
        resources.chip.put(chip);
    });

    // Create an array to hold process references.
    let processes = components::process_array::ProcessArrayComponent::new()
        .finalize(components::process_array_component_static!(NUM_PROCS));
    PANIC_RESOURCES.get().map(|resources| {
        resources.processes.put(processes.as_slice());
    });

    let board_kernel = static_init!(Kernel, Kernel::new(processes.as_slice()));

    let process_management_capability =
        create_capability!(capabilities::ProcessManagementCapability);
    let memory_allocation_capability = create_capability!(capabilities::MemoryAllocationCapability);

    let mux_alarm = components::alarm::AlarmMuxComponent::new(&peripherals.timer0)
        .finalize(components::alarm_mux_component_static!(CMSDKTimer));

    let alarm = components::alarm::AlarmDriverComponent::new(
        board_kernel,
        capsules_core::alarm::DRIVER_NUM,
        mux_alarm,
    )
    .finalize(components::alarm_component_static!(CMSDKTimer));

    let uart_mux = components::console::UartMuxComponent::new(&peripherals.uart, 115200)
        .finalize(components::uart_mux_component_static!());

    // Setup the console.
    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::console_component_static!());

    // Create the debugger object that handles calls to `debug!()`.
    components::debug_writer::DebugWriterComponent::new::<
        <ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider,
    >(
        uart_mux,
        create_capability!(capabilities::SetDebugWriterCapability),
    )
    .finalize(components::debug_writer_component_static!());

    // PROCESS CONSOLE
    let process_printer = components::process_printer::ProcessPrinterTextComponent::new()
        .finalize(components::process_printer_text_component_static!());
    PANIC_RESOURCES.get().map(|resources| {
        resources.printer.put(process_printer);
    });

    let process_console = components::process_console::ProcessConsoleComponent::new(
        board_kernel,
        uart_mux,
        mux_alarm,
        process_printer,
        Some(cortexm33::support::reset),
    )
    .finalize(components::process_console_component_static!(CMSDKTimer));
    let _ = process_console.start();

    let scheduler = components::sched::round_robin::RoundRobinComponent::new(processes)
        .finalize(components::round_robin_component_static!(NUM_PROCS));

    #[cfg(feature = "non_secure_tz")]
    let spe_client = unsafe {
        static_init!(
            tock_spe_adapter::SpeAdapter,
            tock_spe_adapter::SpeAdapter::new(
                board_kernel
                    .create_grant(tock_spe_adapter::DRIVER_NUM, &memory_allocation_capability,),
            )
        )
    };

    let musca_b1_platform = MuscaB1Plattform {
        ipc: kernel::ipc::IPC::new(
            board_kernel,
            kernel::ipc::DRIVER_NUM,
            &memory_allocation_capability,
        ),
        console,
        alarm,
        scheduler,
        systick: unsafe { cortexm33::systick::SysTick::new_with_calibration(40_096_000) },
        #[cfg(feature = "non_secure_tz")]
        spe_client,
    };

    kernel::debug!("Initialization complete. Enter main loop");

    kernel::process::load_processes(
        board_kernel,
        chip,
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::addr_of!(_sapps),
                core::ptr::addr_of!(_eapps) as usize - core::ptr::addr_of!(_sapps) as usize,
            )
        },
        unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::addr_of_mut!(_sappmem),
                core::ptr::addr_of!(_eappmem) as usize - core::ptr::addr_of!(_sappmem) as usize,
            )
        },
        &FAULT_RESPONSE,
        &process_management_capability,
    )
    .unwrap_or_else(|err| {
        kernel::debug!("Error loading processes!");
        kernel::debug!("{:?}", err);
    });

    (board_kernel, musca_b1_platform, chip)
}

/// Main function called after RAM initialized.
#[unsafe(no_mangle)]
pub unsafe fn main() {
    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);

    let (board_kernel, platform, chip) = unsafe { start() };
    board_kernel.kernel_loop(&platform, chip, Some(&platform.ipc), &main_loop_capability);
}
