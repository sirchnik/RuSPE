import gdb
import os


class DwtTracer:
    """Provides access to ARM Cortex-M DWT (Data Watchpoint and Trace) registers."""

    # DWT and DEMCR register addresses
    DWT_CTRL = 0xE0001000
    DWT_CYCCNT = 0xE0001004
    DWT_CPICNT = 0xE0001008
    DWT_EXCCNT = 0xE000100C
    DWT_SLEEPCNT = 0xE0001010
    DWT_LSUCNT = 0xE0001014
    DWT_FOLDCNT = 0xE0001018
    DEMCR = 0xE000EDFC

    def __init__(self):
        self.baselines = {}

    def read_reg(self, addr: int, size: int) -> int:
        """Reads a memory-mapped register."""
        try:
            inferior = gdb.selected_inferior()
            mem = inferior.read_memory(addr, size)
            return int.from_bytes(mem, "little")
        except gdb.MemoryError:
            print(f"Warning: Failed to read memory at {hex(addr)}")
            return 0

    def write_reg(self, addr: int, val: int, size: int):
        """Writes to a memory-mapped register."""
        try:
            inferior = gdb.selected_inferior()
            inferior.write_memory(addr, val.to_bytes(size, "little"))
        except gdb.MemoryError:
            print(f"Warning: Failed to write memory at {hex(addr)}")

    def enable_dwt(self):
        """Enables the DWT cycle counter and other profiling counters."""
        demcr = self.read_reg(self.DEMCR, 4)
        self.write_reg(self.DEMCR, demcr | (1 << 24), 4)  # Enable TRCENA
        self.write_reg(self.DWT_CYCCNT, 0, 4)  # Reset cycle count

        ctrl = self.read_reg(self.DWT_CTRL, 4)
        # Enable CYCCNT, CPICNT, EXCCNT, SLEEPCNT, LSUCNT, FOLDCNT
        self.write_reg(
            self.DWT_CTRL,
            ctrl | 1 | (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21),
            4,
        )
        print("DWT TRCENA and Counters enabled.")

    def snapshot(self) -> dict:
        """Captures a snapshot of the current DWT counter values."""
        return {
            "CYCCNT": self.read_reg(self.DWT_CYCCNT, 4),
            "CPICNT": self.read_reg(self.DWT_CPICNT, 1),
            "EXCCNT": self.read_reg(self.DWT_EXCCNT, 1),
            "SLEEPCNT": self.read_reg(self.DWT_SLEEPCNT, 1),
            "LSUCNT": self.read_reg(self.DWT_LSUCNT, 1),
            "FOLDCNT": self.read_reg(self.DWT_FOLDCNT, 1),
        }


class TraceAggregator:
    """Aggregates and categorizes trace events to calculate performance metrics."""

    def __init__(self):
        self.transitions = {}  # dict of (from_event, to_event, category) -> stats
        self.last_event = None
        self.last_cycles = 0
        self.active_service = "Client"  # Start in Client logic (NSPE)

    def _categorize_transition(self, frm: str, to: str, active_service: str) -> str:
        """Determines the category of a transition between two events."""
        frm_lower, to_lower = frm.lower(), to.lower()

        # 0. Hashing / Signing
        if "crypto_hash" in frm_lower:
            return "Crypto Hashing"
        if "crypto_sign" in frm_lower:
            return "Crypto Signing"

        # 1. From a Service Entry to SVC
        if "attest_srv" in frm_lower:
            return "Attestation"
        if "crypto" in frm_lower:
            return "Crypto"

        # 2. From SVC to a Service Entry
        if "attest_srv" in to_lower:
            return "Attestation"
        if "crypto" in to_lower:
            return "Crypto"

        # 3. From SVC or Partition to psa_call_thunk (Client Entry)
        if "psa_call_thunk" in to_lower:
            return "Client"

        # 4. From Partition to SVC or SVC to SVC
        # This represents the thread running before calling SVC
        if (("partition_mpu" in frm_lower) and ("svc_handler" in to_lower)) or (
            ("svc_handler" in frm_lower) and ("svc_handler" in to_lower)
        ):
            return (
                active_service
                if active_service in ["Attestation", "Crypto", "Client"]
                else "Other Service"
            )

        # 5. Process Switching
        if (("svc_handler" in frm_lower) and ("partition_mpu" in to_lower)) or (
            "unhandled" in frm_lower or "unhandled" in to_lower
        ):
            return "Process Switching"

        # 6. Validation overhead
        if "validate" in frm_lower or "validate" in to_lower:
            return "Validation"

        # 7. Uncategorized (Default for SPM transitions)
        return "Uncategorized"

    def record_event(self, event_name: str, current_cycles: int):
        """Records a new trace event and updates transition statistics."""
        event_lower = event_name.lower()
        if "attest" in event_lower:
            self.active_service = "Attestation"
        elif "crypto" in event_lower:
            self.active_service = "Crypto"
        elif "psa_call_thunk" in event_lower:
            self.active_service = "Client"

        if self.last_event is not None:
            delta = (current_cycles - self.last_cycles) & 0xFFFFFFFF
            category = self._categorize_transition(
                self.last_event, event_name, self.active_service
            )
            transition = (self.last_event, event_name, category)

            stats = self.transitions.setdefault(
                transition,
                {
                    "count": 0,
                    "total_cycles": 0,
                    "max_cycles": 0,
                    "min_cycles": 0xFFFFFFFF,
                },
            )

            stats["count"] += 1
            stats["total_cycles"] += delta
            stats["max_cycles"] = max(stats["max_cycles"], delta)
            stats["min_cycles"] = min(stats["min_cycles"], delta)

        self.last_event = event_name
        self.last_cycles = current_cycles

    def print_summary(self):
        """Prints a formatted summary of all recorded transitions and categorized cycle counts."""
        print("\n" + "=" * 85)
        print("Performance Trace Summary")
        print("=" * 85)
        print(
            f"{'Transition (From -> To)':<55} | {'Count':<6} | {'Total Cycles':<12} | {'Avg Cycles':<10} | {'Category'}"
        )
        print("-" * 85)

        categories = {
            "Validation": 0,
            "Process Switching": 0,
            "Crypto": 0,
            "Crypto Hashing": 0,
            "Crypto Signing": 0,
            "Attestation": 0,
            "Other Service": 0,
            "Client": 0,
        }

        for (frm, to, cat), stats in self.transitions.items():
            name = f"{frm} -> {to}"
            avg = stats["total_cycles"] // stats["count"]
            print(
                f"{name:<55} | {stats['count']:<6} | {stats['total_cycles']:<12} | {avg:<10} | {cat}"
            )

            if cat in categories:
                categories[cat] += stats["total_cycles"]

        total_target_cycles = sum(
            stats["total_cycles"] for stats in self.transitions.values()
        )

        print("-" * 85)
        print("Estimated Category Breakdown:")
        print("-" * 85)
        print("  [ Core SPM & System Overhead ]")
        print(
            f"  Process Switching:                 {categories['Process Switching']} cycles"
        )
        print(f"  Validation (SPM):                  {categories['Validation']} cycles")
        print("")
        print("  [ Secure Services Execution ]")
        print(f"  Crypto Service:                    {categories['Crypto']} cycles")
        print(
            f"  Crypto Hashing:                    {categories['Crypto Hashing']} cycles"
        )
        print(
            f"  Crypto Signing:                    {categories['Crypto Signing']} cycles"
        )
        print(
            f"  Attestation Service:               {categories['Attestation']} cycles"
        )
        if categories["Other Service"] > 0:
            print(
                f"  Other Service Execution:           {categories['Other Service']} cycles"
            )
        print("")
        print("  [ Client Execution ]")
        print(f"  Client Execution (Test Logic):     {categories['Client']} cycles")
        print("-" * 85)
        print("  [ Totals ]")
        print(f"  Total CPU Cycles Measured:         {total_target_cycles} cycles")
        print("=" * 85 + "\n")


tracer = DwtTracer()
aggregator = TraceAggregator()


class DwtBreakpoint(gdb.Breakpoint):
    """A GDB breakpoint that captures DWT counter snapshots upon being hit."""

    def __init__(self, spec: str, name: str, is_start: bool = False):
        super().__init__(spec, internal=False)
        self.name = name
        self.is_start = is_start
        self.silent = True

    def stop(self):
        current = tracer.snapshot()

        if self.is_start:
            print(f"\n--- [TRACE START] {self.name} ---")
            tracer.baselines = current
            aggregator.record_event(self.name, current["CYCCNT"])
        else:
            print(f"\n--- [TRACE CHECKPOINT] {self.name} ---")
            aggregator.record_event(self.name, current["CYCCNT"])

        if not self.is_start and not tracer.baselines:
            print("  Warning: No baseline recorded yet. Showing absolute values.")
            for k, v in current.items():
                print(f"  {k}: {v}")
        elif not self.is_start:
            for k, current_val in current.items():
                baseline_val = tracer.baselines.get(k, 0)
                mask = 0xFFFFFFFF if k == "CYCCNT" else 0xFF
                diff = (current_val - baseline_val) & mask
                print(f"  {k}: {diff} (Total: {current_val})")

        tracer.baselines = current
        return False  # Continue execution automatically


class EndTraceBreakpoint(gdb.Breakpoint):
    """A breakpoint to stop tracing and print the final summary."""

    def __init__(self, addr: str):
        super().__init__(f"*{addr}", internal=False)
        self.silent = True

    def stop(self):
        print("\n--- Trace target function returned! Tracing complete. ---")
        aggregator.print_summary()
        gdb.execute("set confirm off")
        gdb.execute("quit")
        return True


class StartTraceBreakpoint(gdb.Breakpoint):
    """A breakpoint that initializes tracing when the target function is reached."""

    def __init__(self, spec: str):
        super().__init__(spec, internal=False)
        self.silent = True

    def stop(self):
        if not self.enabled:
            return False

        print("\n--- Target function reached! Starting DWT Tracing ---")
        tracer.enable_dwt()

        try:
            frame = gdb.newest_frame()
            lr = frame.read_register("lr")
            ret_addr = int(lr) & ~1  # clear thumb bit

            # GDB has bugs when modifying breakpoints inside stop(). Defer it safely:
            gdb.post_event(lambda: self.setup_tracepoints(ret_addr))
        except Exception as e:
            print(
                f"Warning: Could not set finish breakpoint. Trace will run indefinitely. Error: {e}"
            )

        self.enabled = False
        return True

    def setup_tracepoints(self, ret_addr: int):
        """Sets up all intermediate tracepoints for profiling."""
        try:
            self.delete()
        except Exception:
            pass

        DwtBreakpoint("psa_call_thunk", "psa_call_thunk Entry", is_start=True)
        DwtBreakpoint(
            "psc3m5_evk_secure_ipc::global_spm_api::svc_handler", "svc_handler Entry"
        )
        DwtBreakpoint(
            "<spe::spm::spm_ipc::spm_ipc::SpmIpc<psc3m5_evk_secure_ipc::Psc3IpcPlatform, 2>>::apply_mpu_config",
            "partition_mpu_config Entry",
        )
        DwtBreakpoint(
            "<spe::spm::spm_ipc::spm_ipc::SpmIpc<psc3m5_evk_secure_ipc::Psc3IpcPlatform, 2> as spe::spm::spm::SpmCall>::has_real_permission",
            "validate_permission Entry",
        )
        DwtBreakpoint("psc3m5_evk_attest_srv::call", "attest_srv call Entry")
        DwtBreakpoint(
            "spe_services::crypto::crypto_service::CryptoService::compute_hash",
            "crypto_hash Entry",
        )
        DwtBreakpoint(
            "spe_services::crypto::crypto_service::CryptoService::sign_hash",
            "crypto_sign Entry",
        )

        print(f"Setting end trace breakpoint at return address: {hex(ret_addr)}")
        EndTraceBreakpoint(hex(ret_addr))

        gdb.execute("continue")


def get_release_dir() -> str:
    """Helper to dynamically resolve the build target directory."""
    progspace = gdb.current_progspace()
    if progspace.filename:  # ty:ignore[unresolved-attribute]
        # Expected: <workspace>/target/thumbv8m.main-none-eabi/release/<binary>
        return os.path.dirname(progspace.filename)  # ty:ignore[unresolved-attribute]
    # Fallback to current working directory if not available
    return os.getcwd()


def run_automated_trace():
    """Main routine to connect to the target, flash, setup symbols, and start tracing."""
    print("Connecting to target...")
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")

    try:
        gdb.execute("target extended-remote localhost:3333")
    except Exception as e:
        print(f"Warning: Could not connect to remote target: {e}")

    release_dir = get_release_dir()
    merged_hex = os.path.join(release_dir, "psc3m5_evk_test_nspe_merged.hex")
    from tools.build.naming import get_merged_hex_filename

    merged_hex = os.path.join(
        release_dir,
        get_merged_hex_filename("psc3m5_evk_secure_ipc", "psc3m5_evk_test_nspe"),
    )
    if not os.path.exists(merged_hex):
        merged_hex = os.path.join(
            release_dir,
            get_merged_hex_filename("psc3m5_evk_secure", "psc3m5_evk_test_nspe"),
        )

    print("Resetting and halting target...")
    try:
        gdb.execute("monitor reset halt")
        if os.path.exists(merged_hex):
            gdb.execute(f"monitor program {merged_hex} verify")
        else:
            print(f"Warning: Merged hex not found at {merged_hex}")
        gdb.execute("monitor reset halt")
    except Exception as e:
        print(f"Warning: Could not monitor reset halt: {e}")

    try:
        # Load symbol files dynamically
        nspe_elf = os.path.join(release_dir, "psc3m5_evk_test_nspe")
        attest_elf = os.path.join(release_dir, "psc3m5_evk_attest_srv")
        crypto_elf = os.path.join(release_dir, "psc3m5_evk_crypto_srv")

        for elf in [nspe_elf, attest_elf, crypto_elf]:
            if os.path.exists(elf):
                gdb.execute(f"add-symbol-file {elf}")
            else:
                print(f"Warning: Symbol file not found at {elf}")
    except Exception as e:
        print(f"Warning: Could not add symbol files: {e}")

    print("Waiting for run_attest to start...")
    StartTraceBreakpoint("shared_test_nspe::run_attest")

    print("\nStarting execution! Trace will start and stop automatically.")
    gdb.execute("continue")


if __name__ == "__main__":
    # Automatically execute tracing on startup
    run_automated_trace()
