# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

import os
import signal
import struct
import sys
import threading
from pathlib import Path

import gdb

WATERMARK_VAL = 0xDEADBEEF


def read_memory_words(bottom: int, count: int) -> list[int]:
    inferior = gdb.selected_inferior()
    mem = inferior.read_memory(bottom, count * 4)
    return list(struct.unpack(f"<{count}I", mem))


def write_memory(addr: int, data: bytes) -> None:
    inferior = gdb.selected_inferior()
    inferior.write_memory(addr, data)


def setup_sys_path() -> tuple[Path, Path]:
    progspace = gdb.current_progspace()
    if progspace.filename:
        target_dir = Path(os.path.dirname(progspace.filename))
        repo_root = target_dir.parents[2]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        return repo_root, target_dir
    raise RuntimeError("GDB progspace has no filename; cannot resolve target directory")


def get_current_pc_info() -> str:
    frame = gdb.newest_frame()
    pc = frame.pc()
    sal = frame.find_sal()
    if sal and sal.symtab and sal.symtab.filename and sal.line:
        return f"PC=0x{pc:08x} ({sal.symtab.filename}:{sal.line})"
    return f"PC=0x{pc:08x}"


class StackTracker:
    def __init__(self):
        self.stacks: dict[str, dict] = {}
        self.sample_count = 0
        self.target_dir: Path | None = None

    def discover_stacks(self, target_dir: Path):
        self.target_dir = target_dir
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
            if not stats:
                raise RuntimeError(
                    f"Stack symbols not found for {name} ({elf_name}). "
                    f"ELF path: {elf_path}"
                )

            stack_bottom = stats.stack_start
            stack_top = stats.stack_end
            size = stats.stack_left
            static_ram_used = (
                stats.static_ram_used if stats.static_ram_used is not None else 0
            )
            self.stacks[name] = {
                "elf": elf_name,
                "sfn": sfn_func,
                "bottom": stack_bottom,
                "top": stack_top,
                "size": size,
                "static_ram_used": static_ram_used,
                "calls": 0,
                "max_used_bytes": 0,
                "watermarked_words": 0,
            }
            print(
                f"  [FOUND] {name:<26} ({elf_name:<26}): "
                f"Base=0x{stack_bottom:08x}, Size={size:5d} B, Top=0x{stack_top:08x}"
            )
        print("=" * 85 + "\n")

    def watermark_stack(self, name: str):
        info = self.stacks[name]
        size = info["size"]
        bottom = info["bottom"]
        top = info["top"]

        words_count = size // 4
        assert words_count > 0, f"Stack size for {name} is too small to watermark"

        pattern_bytes = WATERMARK_VAL.to_bytes(4, "little") * words_count
        write_memory(bottom, pattern_bytes)

        read_back = read_memory_words(bottom, words_count)
        assert all(w == WATERMARK_VAL for w in read_back), (
            f"Watermark verification failed for {name}: "
            f"region 0x{bottom:08x}-0x{top:08x}"
        )

        info["watermarked_words"] = words_count
        print(
            f"  Watermarked {name}: {words_count * 4} bytes "
            f"(0x{bottom:08x} - 0x{bottom + words_count * 4:08x}) [Verified]"
        )

    def watermark_all(self):
        print("\n--- Watermarking Stack Memory Regions with 0xDEADBEEF ---")
        for name in self.stacks:
            self.watermark_stack(name)

    def dump_stack_memory(
        self,
        name: str,
        info: dict,
        words: list[int],
        label: str,
        pc_info: str,
        first_break_index: int,
    ):
        elf_name = info["elf"]
        bottom = info["bottom"]
        top = info["top"]
        size = info["size"]

        clean_label = label.lower().replace(" ", "_").replace("#", "")
        dump_filename = f"stack_dump_{elf_name}_{clean_label}.dump"
        latest_filename = f"stack_dump_{elf_name}.dump"

        samples_dir = (
            self.target_dir / "stack_dumps" if self.target_dir else Path("stack_dumps")
        )
        samples_dir.mkdir(parents=True, exist_ok=True)

        dump_path = samples_dir / dump_filename
        latest_path = samples_dir / latest_filename

        lines = [
            f"# Stack Dump: {name} ({elf_name})\n",
            f"# Context: {label} ({pc_info})\n",
            f"# Base: 0x{bottom:08x}, Size: {size} B, Top: 0x{top:08x}\n",
            f"# Watermark Value: 0x{WATERMARK_VAL:08X}\n",
            f"# Unused Continuous Watermark Words: {first_break_index} ({first_break_index * 4} B)\n",
            f"# Watermark First Break Address: 0x{bottom + first_break_index * 4:08x}\n",
            "# " + "-" * 50 + "\n",
        ]

        for i, w in enumerate(words):
            addr = bottom + i * 4
            if i == first_break_index:
                marker = "  <-- WATERMARK BREAK (STACK USAGE BOUNDARY)"
            elif i < first_break_index:
                marker = "  <-- WATERMARK"
            elif w == WATERMARK_VAL:
                marker = "  <-- WATERMARK (STALE/DISCONTINUOUS)"
            else:
                marker = ""
            lines.append(f"0x{addr:08x}: 0x{w:08x}{marker}\n")

        content = "".join(lines)
        dump_path.write_text(content)
        latest_path.write_text(content)
        print(
            f"    [DUMP] Saved memory dump with watermark markers: {dump_path.resolve()}"
        )

    def sample_all_stacks(self, trial: bool = False):
        self.sample_count += 1
        pc_info = get_current_pc_info()
        label = "TRIAL" if trial else f"Sample #{self.sample_count}"
        print(f"\n--- [{label}] {pc_info} ---")

        for name, info in self.stacks.items():
            size = info["size"]
            bottom = info["bottom"]
            top = info["top"]
            wm_words = info["watermarked_words"]
            assert wm_words > 0, f"{name} was never watermarked"

            try:
                words = read_memory_words(bottom, wm_words)
            except gdb.MemoryError:
                print(
                    f"  [INFO] Cannot access {name} memory at 0x{bottom:08x} "
                    f"(target in Non-Secure mode)"
                )
                continue

            unused_words = 0
            for w in words:
                if w == WATERMARK_VAL:
                    unused_words += 1
                else:
                    break

            if unused_words == 0:
                print(
                    f"  WARNING: {name} stack fully consumed "
                    f"(0x{bottom:08x}-0x{top:08x}) at {pc_info}"
                )

            used_bytes = (wm_words - unused_words) * 4

            if not trial:
                if used_bytes > info["max_used_bytes"]:
                    info["max_used_bytes"] = used_bytes
                info["calls"] += 1

            pct = (used_bytes / size) * 100.0 if size > 0 else 0.0
            print(f"  {name:<26}: {used_bytes:5d} B ({pct:5.1f}%)")

            self.dump_stack_memory(name, info, words, label, pc_info, unused_words)

    def generate_report(self):
        # Report uses only accumulated max values from secure-context samples.
        # No memory reads here — this runs from non-secure context (end breakpoint).
        print("\n" + "=" * 114)
        print(
            "                                "
            "RuSPE SERVICE & SPM STACK USAGE REPORT (HIGHEST VALUES)"
        )
        print("=" * 114)
        print(
            f"{'Service / SPM Target':<26} | {'Allocated':<10} | "
            f"{'Highest Usage':<18} | {'Used RAM Size':<13} | "
            f"{'Usage %':<8} | {'Samples':<7} | Status"
        )
        print("-" * 114)

        for name, info in self.stacks.items():
            size = info["size"]
            calls = info["calls"]
            wm_words = info["watermarked_words"]

            assert wm_words > 0, f"{name} was never watermarked"
            assert calls > 0, (
                f"{name} had 0 samples — no secure-context breakpoint was hit"
            )

            max_used_bytes = info["max_used_bytes"]
            static_ram_used = info.get("static_ram_used", 0)
            used_ram_bytes = max_used_bytes + static_ram_used
            pct = (max_used_bytes / size) * 100.0 if size > 0 else 0.0

            if pct >= 90.0:
                status = "CRITICAL (>90%)"
            elif pct >= 80.0:
                status = "WARNING (>80%)"
            else:
                status = "OK"

            print(
                f"{name:<26} | {size:7d} B  | {max_used_bytes:7d} B ({pct:5.1f}%) | "
                f"{used_ram_bytes:7X} B    | {pct:7.2f}% | {calls:<7} | {status}"
            )

        print("-" * 114)
        print(
            "Note: Highest usage calculated across samples taken in "
            "Secure mode via 0xDEADBEEF watermark scanning."
        )
        print("=" * 114 + "\n")

        gdb.execute("monitor reset halt")


tracker = StackTracker()

# Flag set by the timer thread to signal that measurement should stop.
_timed_out = False


def exit_gdb():
    print("Exiting GDB session...")
    gdb.execute("set confirm off")
    gdb.execute("quit 0")
    os._exit(0)


BREAKPOINTS: list[gdb.Breakpoint] = []


class SpmIpcSampleBreakpoint(gdb.Breakpoint):
    def __init__(self, spec: str):
        super().__init__(spec, internal=False)
        self.silent = True

    def stop(self):
        global _timed_out

        if _timed_out:
            # Timeout elapsed — target is halted here (breakpoint context).
            # Delete all breakpoints, generate the report, and exit.
            for bp in BREAKPOINTS:
                bp.delete()
            BREAKPOINTS.clear()
            tracker.generate_report()
            exit_gdb()
            return True  # stay stopped (won't reach here after exit)

        pc_info = get_current_pc_info()
        print(f"\n  [SAMPLE] SpmIpcSampleBreakpoint hit at {pc_info}")
        tracker.sample_all_stacks()
        return False


def setup_spm_ipc_breakpoints():
    candidate_specs = [
        "spm_ipc.rs:240",
        "spm_ipc.rs:249",
        "psc3m5_evk_attest_srv::call",
        "spe_services::crypto::crypto_service::CryptoService::compute_hash",
    ]
    created = 0
    specs_set = []
    for spec in candidate_specs:
        bp = SpmIpcSampleBreakpoint(spec)
        if bp.pending:
            bp.delete()
            continue
        BREAKPOINTS.append(bp)
        specs_set.append(spec)
        print(f"  Set watermark sampling breakpoint at: {spec}")
        created += 1

    assert created > 0, (
        f"Could not set any sampling breakpoints. Tried: {candidate_specs}"
    )
    print(f"Set {created} watermark sampling breakpoint(s): {', '.join(specs_set)}")


def _timeout_interrupt():
    """Set the timeout flag and interrupt the target with SIGINT."""
    global _timed_out
    _timed_out = True
    os.kill(os.getpid(), signal.SIGINT)


def run_automated_stack_measurement():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")

    repo_root, target_dir = setup_sys_path()

    print("Connecting to OpenOCD...")
    gdb.execute("target extended-remote localhost:3333")

    from tools.build.naming import get_merged_hex_filename

    merged_hex = target_dir / get_merged_hex_filename(
        "psc3m5_evk_secure_ipc", "psc3m5_evk_test_nspe", has_services=True
    )
    assert merged_hex.exists(), f"Merged hex not found: {merged_hex}"

    print("Resetting and halting target...")
    gdb.execute("monitor reset halt")
    gdb.execute(f"monitor program {merged_hex} verify")
    gdb.execute("monitor reset halt")

    nspe_elf = target_dir / "psc3m5_evk_test_nspe"
    attest_elf = target_dir / "psc3m5_evk_attest_srv"
    crypto_elf = target_dir / "psc3m5_evk_crypto_srv"

    for elf in [nspe_elf, attest_elf, crypto_elf]:
        assert elf.exists(), f"Symbol file not found: {elf}"
        gdb.execute(f"add-symbol-file {elf}")

    tracker.discover_stacks(target_dir)

    # After reset halt the CPU is in secure state — safe to access secure memory/FPB
    tracker.watermark_all()
    tracker.sample_all_stacks(trial=True)
    setup_spm_ipc_breakpoints()

    print("\nStarting execution! Will sample after 5 seconds...")
    timer = threading.Timer(5.0, _timeout_interrupt)
    timer.start()

    try:
        gdb.execute("continue")
    except (gdb.error, KeyboardInterrupt):
        pass
    finally:
        timer.cancel()

    # Fallback: if the timeout SIGINT stopped `continue` but no breakpoint
    # fired afterwards (e.g. target was in non-secure code), generate the
    # report here while the target is halted.
    if _timed_out and tracker.sample_count > 0:
        for bp in BREAKPOINTS:
            bp.delete()
        BREAKPOINTS.clear()
        tracker.generate_report()
        exit_gdb()


if __name__ == "__main__":
    run_automated_stack_measurement()
