# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

import os
import socket
import struct
import sys
from pathlib import Path

import gdb

WATERMARK_VAL = 0xDEADBEEF


def setup_sys_path() -> tuple[Path, Path]:
    progspace = gdb.current_progspace()
    if progspace.filename:
        target_dir = Path(os.path.dirname(progspace.filename))
        repo_root = target_dir.parents[2]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        return repo_root, target_dir
    cwd = Path(os.getcwd())
    return cwd, cwd


class StackTracker:
    def __init__(self):
        self.stacks = {}

    def discover_stacks(self, target_dir: Path):
        print("\n" + "=" * 85)
        print("Discovering RuSPE SPM and Service Stack Memory Regions...")
        print("=" * 85)

        tracked_targets = [
            (
                "Secure IPC Kernel (SPM)",
                "psc3m5_evk_secure_ipc",
                "psc3m5_evk_secure_ipc::global_spm_api::svc_handler",
            ),
            (
                "Attestation Service",
                "psc3m5_evk_attest_srv",
                "psc3m5_evk_attest_srv::call",
            ),
            (
                "Crypto Service",
                "psc3m5_evk_crypto_srv",
                "spe_services::crypto::crypto_service::CryptoService::compute_hash",
            ),
        ]

        from tools.analyze.stats import get_stack_stats

        for name, elf_name, sfn_func in tracked_targets:
            elf_path = target_dir / elf_name
            if not elf_path.exists():
                for p in target_dir.glob(f"*{elf_name}*"):
                    if p.is_file() and not p.name.endswith(
                        (".hex", ".bin", ".d", ".tbf", ".tab")
                    ):
                        elf_path = p
                        break

            stats = get_stack_stats(elf_path) if elf_path.exists() else None
            if stats:
                stack_bottom = stats.stack_start
                stack_top = stats.stack_end
                size = stats.stack_left
                self.stacks[name] = {
                    "elf": elf_name,
                    "sfn": sfn_func,
                    "bottom": stack_bottom,
                    "top": stack_top,
                    "size": size,
                    "calls": 0,
                }
                print(
                    f"  [FOUND] {name:<26} ({elf_name:<26}): "
                    f"Base=0x{stack_bottom:08x}, Size={size:5d} B, Top=0x{stack_top:08x}"
                )
            else:
                print(f"  [MISSING] {name:<26} ({elf_name}) - Stack symbols not found.")
        print("=" * 85 + "\n")

    def watermark_stack(self, name: str):
        if name not in self.stacks:
            return
        info = self.stacks[name]
        if info.get("watermarked_words", 0) > 0:
            return

        size = info["size"]
        bottom = info["bottom"]
        top = info["top"]

        words_count = size // 4
        if words_count <= 0:
            return

        pattern_bytes = WATERMARK_VAL.to_bytes(4, "little") * words_count
        inferior = gdb.selected_inferior()
        try:
            inferior.write_memory(bottom, pattern_bytes)

            # Check if the watermarks are written everywhere
            read_back = inferior.read_memory(bottom, words_count * 4)
            read_words = struct.unpack(f"<{words_count}I", read_back)
            assert all(
                w == WATERMARK_VAL for w in read_words
            ), f"Watermark check failed for {name}: watermarks were not written everywhere in region 0x{bottom:08x}-0x{top:08x}!"

            info["watermarked_words"] = words_count
            print(
                f"  Watermarked {name}: {words_count * 4} bytes (0x{bottom:08x} - 0x{bottom + words_count * 4:08x}) [Verified]"
            )
        except Exception as e:
            if isinstance(e, AssertionError):
                raise
            print(f"  Error: Failed to watermark {name} at 0x{bottom:08x}: {e}")
            raise

    def watermark_all(self):
        print("\n--- Watermarking Stack Memory Regions with 0xDEADBEEF ---")
        for name in self.stacks.keys():
            self.watermark_stack(name)

    def record_entry(self, name):
        if name not in self.stacks:
            return
        info = self.stacks[name]
        info["calls"] += 1

        # Fallback watermarking on service entry if not watermarked yet
        if info.get("watermarked_words", 0) == 0:
            self.watermark_stack(name)

        bottom = info["bottom"]
        top = info["top"]
        print(
            f"  [ENTRY] {name} call #{info['calls']} (stack: 0x{bottom:08x}-0x{top:08x})"
        )

    def generate_report(self):
        print("\n" + "=" * 108)
        print("                                RuSPE SERVICE & SPM STACK USAGE REPORT")
        print("=" * 108)
        print(
            f"{'Service / SPM Target':<26} | {'Allocated':<10} | {'Peak Usage':<15} | {'Margin':<10} | {'Usage %':<8} | {'Calls':<6} | Status"
        )
        print("-" * 108)

        inferior = gdb.selected_inferior()

        for name in self.stacks.keys():
            info = self.stacks[name]
            size = info["size"]
            bottom = info["bottom"]
            top = info["top"]
            calls = info["calls"]
            wm_words = info.get("watermarked_words", 0)

            assert (
                wm_words > 0
            ), f"Watermark assertion failed: {name} was never watermarked!"

            try:
                mem = inferior.read_memory(bottom, wm_words * 4)
                words = struct.unpack(f"<{wm_words}I", mem)
            except Exception as e:
                raise RuntimeError(f"Error reading stack memory for {name}: {e}")

            unused_words = 0
            for w in words:
                if w == WATERMARK_VAL:
                    unused_words += 1
                else:
                    break

            # Assertion for not finding a watermark
            assert (
                unused_words > 0
            ), f"Watermark assertion failed for {name} (0x{bottom:08x}-0x{top:08x}): No watermark found! (Possible stack overflow or unwatermarked region)"

            used_bytes = (wm_words - unused_words) * 4
            margin_bytes = size - used_bytes
            pct = (used_bytes / size) * 100.0 if size > 0 else 0.0

            if pct >= 90.0:
                status = "CRITICAL (>90%)"
            elif pct >= 80.0:
                status = "WARNING (>80%)"
            else:
                status = "OK"

            calls_str = str(calls) if calls > 0 else "N/A"
            print(
                f"{name:<26} | {size:7d} B | {used_bytes:7d} B ({pct:5.1f}%) | {margin_bytes:7d} B | {pct:7.2f}% | {calls_str:<6} | {status}"
            )

        print("-" * 108)
        print("Note: Peak usage calculated purely via 0xDEADBEEF watermark scanning.")
        print("=" * 108 + "\n")


tracker = StackTracker()


def exit_gdb():
    print("Exiting GDB session...")
    try:
        gdb.execute("set confirm off")
        gdb.execute("quit 0")
    except Exception:
        pass
    os._exit(0)


class ServiceEntryBreakpoint(gdb.Breakpoint):
    def __init__(self, spec, service_name):
        super().__init__(spec, internal=False)
        self.service_name = service_name
        self.silent = True

    def stop(self):
        tracker.record_entry(self.service_name)
        return False  # Continue execution automatically


class EndStackMeasurementBreakpoint(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec, internal=False)
        self.silent = True

    def stop(self):
        print("\n--- Test Suite Execution Completed! Scanning Stacks... ---")
        try:
            gdb.execute("monitor halt")
            # Force CPU to Secure World so that we can read Secure SRAM
            gdb.execute("monitor reset halt")
        except Exception:
            pass
        tracker.generate_report()
        exit_gdb()
        return True





class StartStackMeasurementBreakpoint(gdb.Breakpoint):
    def __init__(self, spec="shared_test_nspe::run_test"):
        super().__init__(spec, internal=False)
        self.spec = spec
        self.silent = True

    def stop(self):
        if not self.enabled:
            return False
        print(
            f"\n--- {self.spec} Reached! Arming Secure World Watermarking & Completion Breakpoint... ---"
        )

        try:
            frame = gdb.newest_frame()
            lr = frame.read_register("lr")
            ret_addr = int(lr) & ~1
            gdb.post_event(lambda: self.setup_measurement(ret_addr))
        except Exception as e:
            print(f"Warning: Could not read LR: {e}")

        self.enabled = False
        return True

    def setup_measurement(self, ret_addr: int):
        try:
            self.delete()
        except Exception:
            pass

        for secure_entry_sym in [
            "__acle_se_psa_call_veneer",
            "__acle_se_psa_version_veneer",
            "psc3m5_evk_secure_ipc::global_spm_api::svc_handler",
        ]:
            try:
                PsaSecureEntryBreakpoint(secure_entry_sym)
                break
            except Exception:
                pass

        for name, info in tracker.stacks.items():
            sfn = info.get("sfn")
            if sfn:
                try:
                    ServiceEntryBreakpoint(sfn, name)
                except Exception:
                    pass

        print(f"Setting end measurement breakpoint at return address: {hex(ret_addr)}")
        EndStackMeasurementBreakpoint(f"*{hex(ret_addr)}")
        gdb.execute("continue")



def is_openocd_running(host="localhost", port=3333) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2.0):
            return True
    except OSError:
        return False


def run_automated_stack_measurement():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")

    repo_root, target_dir = setup_sys_path()

    if not is_openocd_running():
        print(
            "\n[Notice] OpenOCD target is not running on localhost:3333.\n"
            "         Running dry-run symbol discovery on target ELF...\n"
        )
        tracker.discover_stacks(target_dir)
        print("To measure active hardware execution, run via 'inv stack-usage'\n")
        return

    print("Connecting to OpenOCD...")
    try:
        gdb.execute("target extended-remote localhost:3333")
    except gdb.error as e:
        print(f"Connection to OpenOCD failed: {e}")
        tracker.discover_stacks(target_dir)
        return

    from tools.build.naming import get_merged_hex_filename

    merged_hex = target_dir / get_merged_hex_filename(
        "psc3m5_evk_secure_ipc", "psc3m5_evk_test_nspe"
    )
    if not merged_hex.exists():
        merged_hex = target_dir / get_merged_hex_filename(
            "psc3m5_evk_secure", "psc3m5_evk_test_nspe"
        )

    print("Resetting and halting target...")
    try:
        gdb.execute("monitor reset halt")
        if merged_hex.exists():
            gdb.execute(f"monitor program {merged_hex} verify")
        else:
            print(f"Warning: Merged hex not found at {merged_hex}")
        gdb.execute("monitor reset halt")
    except Exception as e:
        print(f"Warning: Could not reset or program target: {e}")

    try:
        nspe_elf = target_dir / "psc3m5_evk_test_nspe"
        attest_elf = target_dir / "psc3m5_evk_attest_srv"
        crypto_elf = target_dir / "psc3m5_evk_crypto_srv"

        for elf in [nspe_elf, attest_elf, crypto_elf]:
            if elf.exists():
                gdb.execute(f"add-symbol-file {elf}")
            else:
                print(f"Warning: Symbol file not found at {elf}")
    except Exception as e:
        print(f"Warning: Could not add symbol files: {e}")

    tracker.discover_stacks(target_dir)

    print("\n--- Watermarking all stacks immediately after reset ---")
    try:
        tracker.watermark_all()
    except Exception as e:
        print(f"Warning: Could not watermark stacks: {e}")

    print("Waiting for test routine to start stack measurement...")
    try:
        StartStackMeasurementBreakpoint("shared_test_nspe::run_attest")
    except Exception:
        try:
            StartStackMeasurementBreakpoint("shared_test_nspe::run_test")
        except Exception as e:
            print(f"Warning: Could not set start breakpoint: {e}")


    print("\nStarting execution! Monitoring target until test routine completes...")
    gdb.execute("continue")


if __name__ == "__main__":
    run_automated_stack_measurement()
