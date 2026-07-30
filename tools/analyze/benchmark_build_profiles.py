# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

"""Benchmark different Cargo release profiles for secure_ipc + test_nspe.

For each profile variant:
  1. Build (release) via invoke, injecting CARGO_PROFILE_RELEASE_* env vars.
  2. Flash to the board with openocd
  3. Read UART output and extract cycles_elapsed from the SysTick measurement.
  4. Report flash section sizes (text+data) and measured cycles.
"""

from __future__ import annotations

import argparse
import contextlib
from datetime import UTC, datetime
from functools import cache
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Generator

if TYPE_CHECKING:
    import serial

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from invoke.context import Context as InvokeContext

from boards.psc3m5_evk.secure_ipc.tasks import BOARD, _build as _ipc_build
from tools.build.board import program_hex
from tools.build.secure_build import FirmwareResult
from tools.debugging.term import get_cypress_port

# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------


@dataclass
class ProfileVariant:
    name: str
    description: str
    opt: str
    lto: str
    cgu: int | str = 1
    debug: bool = True

    @property
    def env(self) -> dict[str, str]:
        return {
            "CARGO_PROFILE_RELEASE_OPT_LEVEL": str(self.opt),
            "CARGO_PROFILE_RELEASE_LTO": str(self.lto),
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": str(self.cgu),
            "CARGO_PROFILE_RELEASE_DEBUG": "true" if self.debug else "false",
        }


# fmt: off
PROFILES: list[ProfileVariant] = [
    ProfileVariant("baseline", 'opt-level="z" lto=fat codegen-units=1 debug=true (current Cargo.toml)', "z", "fat", 1),
    ProfileVariant("size-fat-s", 'opt-level="s" lto=fat codegen-units=1 (size-focused with different inliner heuristics)', "s", "fat", 1),
    ProfileVariant("size-thin-s", 'opt-level="s" lto=thin codegen-units=1', "s", "thin", 1),
    ProfileVariant("size-thin-z", 'opt-level="z" lto=thin codegen-units=1', "z", "thin", 1),
    ProfileVariant("size-thin-z-cgu8", 'opt-level="z" lto=thin codegen-units=8', "z", "thin", 8),
    ProfileVariant("size-thin-z-cgu2", 'opt-level="z" lto=thin codegen-units=2', "z", "thin", 2),
    ProfileVariant("size-thin-z-cgu16", 'opt-level="z" lto=thin codegen-units=16', "z", "thin", 16),
    ProfileVariant("size-thin-z-cgu64", 'opt-level="z" lto=thin codegen-units=64', "z", "thin", 64),
    ProfileVariant("size-thin-z-cgu256", 'opt-level="z" lto=thin codegen-units=256', "z", "thin", 256),
    ProfileVariant("size-fat-z-cgu4", 'opt-level="z" lto=fat codegen-units=4 (sanity-check for fat-LTO cgu impact)', "z", "fat", 4),
    ProfileVariant("size-fat-s-cgu4", 'opt-level="s" lto=fat codegen-units=4', "s", "fat", 4),
    ProfileVariant("balanced-fat-2", 'opt-level=2 lto=fat codegen-units=1 (balanced speed/size)', "2", "fat", 1),
    ProfileVariant("balanced-thin-2", 'opt-level=2 lto=thin codegen-units=1', "2", "thin", 1),
    ProfileVariant("balanced-thin-2-cgu16", 'opt-level=2 lto=thin codegen-units=16', "2", "thin", 16),
    ProfileVariant("balanced-thin-2-cgu2", 'opt-level=2 lto=thin codegen-units=2', "2", "thin", 2),
    ProfileVariant("balanced-thin-2-cgu64", 'opt-level=2 lto=thin codegen-units=64', "2", "thin", 64),
    ProfileVariant("balanced-thin-2-cgu256", 'opt-level=2 lto=thin codegen-units=256', "2", "thin", 256),
    ProfileVariant("speed-fat-3", 'opt-level=3 lto=fat codegen-units=1 (max speed)', "3", "fat", 1),
    ProfileVariant("speed-thin-3", 'opt-level=3 lto=thin codegen-units=1', "3", "thin", 1),
    ProfileVariant("speed-thin-3-cgu16", 'opt-level=3 lto=thin codegen-units=16', "3", "thin", 16),
    ProfileVariant("speed-thin-3-cgu2", 'opt-level=3 lto=thin codegen-units=2', "3", "thin", 2),
    ProfileVariant("speed-thin-3-cgu8", 'opt-level=3 lto=thin codegen-units=8', "3", "thin", 8),
    ProfileVariant("speed-thin-3-cgu64", 'opt-level=3 lto=thin codegen-units=64', "3", "thin", 64),
    ProfileVariant("speed-thin-3-cgu128", 'opt-level=3 lto=thin codegen-units=128', "3", "thin", 128),
    ProfileVariant("speed-fat-3-cgu4", 'opt-level=3 lto=fat codegen-units=4', "3", "fat", 4),
    ProfileVariant("speed-fat-3-cgu16", 'opt-level=3 lto=fat codegen-units=16', "3", "fat", 16),
    ProfileVariant("speed-thin-3-cgu256", 'opt-level=3 lto=thin codegen-units=256', "3", "thin", 256),
    ProfileVariant("speed-fat-z-cgu16", 'opt-level="z" lto=fat codegen-units=16', "z", "fat", 16),
    ProfileVariant("balanced-fat-z-cgu64", 'opt-level="z" lto=fat codegen-units=64', "z", "fat", 64),
]
# fmt: on

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BAUD = 115200
SERIAL_TIMEOUT = 40  # seconds to wait for test output after reset

DEFAULT_RESULTS_JSON = REPO_ROOT / "tests" / "bench_results_ipc.json"
DEFAULT_SUMMARY_MD = REPO_ROOT / "tests" / "bench_size_summary_ipc.md"
LOG_DIR = REPO_ROOT / "tests" / "bench_logs_ipc"
TEST_NSPE_LIB = REPO_ROOT / "boards" / "shared" / "test_nspe" / "src" / "lib.rs"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _patch_test_nspe(profile_name: str) -> Generator[None, None, None]:
    """Temporarily patch profile name in test_nspe/src/lib.rs before build."""
    original_content = TEST_NSPE_LIB.read_text(encoding="utf-8")
    pattern = re.compile(r'let _ = writeln!\(writer, "profile: [^"]*"\);')
    replacement = f'let _ = writeln!(writer, "profile: {profile_name}");'
    patched_content = (
        pattern.sub(replacement, original_content)
        if pattern.search(original_content)
        else original_content
    )

    TEST_NSPE_LIB.write_text(patched_content, encoding="utf-8")
    try:
        yield
    finally:
        TEST_NSPE_LIB.write_text(original_content, encoding="utf-8")


@contextlib.contextmanager
def _profile_env(profile: ProfileVariant) -> Generator[None, None, None]:
    """Temporarily inject profile env vars (+ CARGO_INCREMENTAL=0) into os.environ."""
    injected = {**profile.env, "CARGO_INCREMENTAL": "0"}
    saved = {k: os.environ.get(k) for k in injected}
    os.environ.update(injected)
    try:
        yield
    finally:
        for key, old in saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


@contextlib.contextmanager
def _redirect_to_log(log_path: Path, mode: str = "a") -> Generator[None, None, None]:
    """Redirect all stdout/stderr (Python prints + subprocess) to log_path."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    sys.stdout.flush()
    sys.stderr.flush()

    try:
        saved_1 = os.dup(1)
        saved_2 = os.dup(2)
    except OSError:
        with open(log_path, mode, encoding="utf-8") as lf:
            with contextlib.redirect_stdout(lf), contextlib.redirect_stderr(lf):
                yield
        return

    old_stdout, old_stderr = sys.stdout, sys.stderr
    with open(log_path, mode, encoding="utf-8") as lf:
        os.dup2(lf.fileno(), 1)
        os.dup2(lf.fileno(), 2)
        sys.stdout = lf
        sys.stderr = lf
        try:
            yield
        finally:
            lf.flush()
            sys.stdout, sys.stderr = old_stdout, old_stderr
            os.dup2(saved_1, 1)
            os.dup2(saved_2, 2)
            os.close(saved_1)
            os.close(saved_2)


def build(profile: ProfileVariant) -> FirmwareResult:
    """Build secure_ipc with test_nspe for the given profile, using invoke tasks directly."""
    ctx = InvokeContext()
    with _profile_env(profile):
        return _ipc_build(ctx, nspe="test", app=None, debug=False)


@cache
def _resolve_objsize() -> Path | None:
    """Find llvm-size from PATH or the rustc sysroot (llvm-tools component)."""
    for name in ("rust-size", "llvm-size"):
        found = shutil.which(name)
        if found:
            return Path(found)

    rustc = shutil.which("rustc")
    if rustc:
        with contextlib.suppress(Exception):
            result = subprocess.run(
                [rustc, "--print", "sysroot"],
                capture_output=True,
                text=True,
                check=False,
            )
            sysroot = result.stdout.strip()
            if sysroot:
                for bin_dir in (Path(sysroot) / "lib" / "rustlib").glob("*/bin"):
                    for name in ("llvm-size.exe", "llvm-size"):
                        candidate = bin_dir / name
                        if candidate.exists():
                            return candidate
    return None


def get_elf_sizes(elf_path: Path) -> dict[str, int]:
    """Return text/data/bss bytes for the given ELF via llvm-size."""
    size_tool = _resolve_objsize()
    if size_tool and elf_path.exists():
        try:
            result = subprocess.run(
                [str(size_tool), str(elf_path)],
                capture_output=True,
                text=True,
                check=True,
            )
            lines = result.stdout.strip().splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                return {
                    "text": int(parts[0]),
                    "data": int(parts[1]),
                    "bss": int(parts[2]),
                }
        except Exception as exc:
            print(f"    [warn] llvm-size failed: {exc}")

    size = elf_path.stat().st_size if elf_path.exists() else 0
    return {"file_bytes": size}


def get_all_elf_sizes(firmware: FirmwareResult) -> dict[str, dict[str, int]]:
    """Return section sizes for every ELF produced by the build."""
    from boards.psc3m5_evk.secure_ipc.tasks import SERVICES

    target_dir = REPO_ROOT / "target" / "thumbv8m.main-none-eabi" / "release"
    all_sizes: dict[str, dict[str, int]] = {
        "secure_ipc": get_elf_sizes(firmware.secure_elf),
        "test_nspe": get_elf_sizes(firmware.non_secure_elf),
    }
    for srv in SERVICES:
        module = sys.modules[srv.__module__]
        conf = module.SERVICE_CONF
        all_sizes[conf.service] = get_elf_sizes(target_dir / conf.crate_name)
    return all_sizes


def flash(result: FirmwareResult) -> None:
    """Flash the merged hex via OpenOCD."""
    ctx = InvokeContext()
    program_hex(ctx, BOARD, result.merged_hex)


def read_cycles_from_uart(
    ser: serial.Serial,
    timeout: int,
    expected_profile: str | None = None,
) -> int | None:
    """Read UART output from serial connection ser and extract cycles_elapsed."""
    print(f"  Listening on {ser.port} at {BAUD} baud (timeout={timeout}s) …")
    deadline = time.monotonic() + timeout
    buffer = ""
    cycles_pattern = re.compile(r"cycles_elapsed\s+(\d+)")
    profile_marker = f"profile: {expected_profile}" if expected_profile else None
    start_marker = "--- NSPE TEST START ---"

    try:
        while time.monotonic() < deadline:
            chunk = ser.read(512)
            if chunk:
                text = chunk.decode("utf-8", errors="replace")
                buffer += text
                sys.stdout.write(text)
                sys.stdout.flush()

                if profile_marker and profile_marker in buffer:
                    search_buf = buffer[buffer.find(profile_marker) :]
                    m = cycles_pattern.search(search_buf)
                    if m:
                        return int(m.group(1))
                elif not profile_marker:
                    search_buf = (
                        buffer[buffer.find(start_marker) :]
                        if start_marker in buffer
                        else buffer
                    )
                    m = cycles_pattern.search(search_buf)
                    if m:
                        return int(m.group(1))
    except Exception as exc:
        print(f"  [error] Serial error: {exc}")
        return None

    print("  [warn] Timed out waiting for cycles_elapsed")
    return None


# ---------------------------------------------------------------------------
# Dataclass & JSON persistence
# ---------------------------------------------------------------------------


@dataclass
class BenchResult:
    profile: ProfileVariant
    build_ok: bool
    sizes: dict[str, dict[str, int]]
    cycles: int | None
    build_time_s: float
    modes_done: list[str] = field(default_factory=list)
    log_path: Path | None = None


def _load_json(path: Path) -> dict[str, dict]:
    if path.exists():
        with contextlib.suppress(Exception):
            return json.loads(path.read_text(encoding="utf-8"))
    return {}


def _save_result(path: Path, result: BenchResult) -> None:
    data = _load_json(path)
    existing_entry = data.get(result.profile.name, {})

    entry = {
        "build_ok": result.build_ok,
        "sizes": result.sizes or existing_entry.get("sizes", {}),
        "cycles": result.cycles
        if result.cycles is not None
        else existing_entry.get("cycles"),
        "build_time_s": result.build_time_s or existing_entry.get("build_time_s", 0.0),
        "modes_done": list(
            dict.fromkeys(existing_entry.get("modes_done", []) + result.modes_done)
        ),
        "log_path": str(result.log_path)
        if result.log_path
        else existing_entry.get("log_path"),
    }
    data[result.profile.name] = entry
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _result_from_json(profile: ProfileVariant, entry: dict) -> BenchResult:
    log = entry.get("log_path")
    return BenchResult(
        profile=profile,
        build_ok=entry["build_ok"],
        sizes=entry.get("sizes", {}),
        cycles=entry.get("cycles"),
        build_time_s=entry.get("build_time_s", 0.0),
        modes_done=entry.get("modes_done", []),
        log_path=Path(log) if log else None,
    )


# ---------------------------------------------------------------------------
# Execution Engine
# ---------------------------------------------------------------------------


def run_bench(
    profiles: list[ProfileVariant],
    bench_size: bool,
    bench_perf: bool,
    uart_timeout: int,
    results_json: Path,
) -> list[BenchResult]:
    """Execute benchmark run for given profiles."""
    existing = _load_json(results_json)
    results: list[BenchResult] = []
    total = len(profiles)

    for idx, profile in enumerate(profiles):
        tag = f"[{idx + 1}/{total}] {profile.name}"

        if profile.name in existing:
            entry = existing[profile.name]
            modes_done = set(entry.get("modes_done", []))
            need_size = bench_size and "size" not in modes_done
            need_perf = bench_perf and "perf" not in modes_done
            if not need_size and not need_perf:
                res = _result_from_json(profile, entry)
                results.append(res)
                log_hint = f"  (log: {res.log_path})" if res.log_path else ""
                print(f"{tag}  [skip — already in JSON]{log_hint}")
                continue

        existing_entry = existing.get(profile.name, {})
        log_path = LOG_DIR / f"{profile.name}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")

        build_ok = False
        sizes: dict[str, dict[str, int]] = existing_entry.get("sizes", {})
        cycles: int | None = existing_entry.get("cycles")
        firmware: FirmwareResult | None = None
        modes_done_list: list[str] = list(existing_entry.get("modes_done", []))

        print(f"{tag}  building ...", end="", flush=True)
        t0 = time.monotonic()
        try:
            with _patch_test_nspe(profile.name), _redirect_to_log(log_path, mode="a"):
                print("=== BUILD ===")
                firmware = build(profile)
            build_ok = True
        except Exception as exc:
            build_time = time.monotonic() - t0
            print(f"  FAILED ({exc})  log: {log_path}")
        else:
            build_time = time.monotonic() - t0
            print(f"  done ({build_time:.0f}s)", end="", flush=True)

        if build_ok and firmware is not None:
            if bench_size:
                sizes = get_all_elf_sizes(firmware)
                total_flash = sum(
                    s.get("text", 0) + s.get("data", 0) for s in sizes.values()
                )
                print(f"  total-flash={total_flash:,}B", end="", flush=True)
                if "size" not in modes_done_list:
                    modes_done_list.append("size")

            if bench_perf:
                try:
                    import serial  # type: ignore[import]

                    port = get_cypress_port()
                except (ImportError, RuntimeError) as exc:
                    print(f"  [error] UART setup failed: {exc}", end="", flush=True)
                else:
                    print("  flashing ...", end="", flush=True)
                    try:
                        with serial.Serial(port, BAUD, timeout=1) as ser:
                            with contextlib.suppress(AttributeError, Exception):
                                ser.reset_input_buffer()

                            with _redirect_to_log(log_path, mode="a"):
                                print("\n=== FLASH ===")
                                flash(firmware)

                            print("  reading UART ...", end="", flush=True)
                            with _redirect_to_log(log_path, mode="a"):
                                print("\n=== SERIAL ===")
                                cycles = read_cycles_from_uart(
                                    ser,
                                    uart_timeout,
                                    expected_profile=profile.name,
                                )

                        if cycles is not None:
                            print(f"  cycles={cycles:,}", end="", flush=True)
                            if "perf" not in modes_done_list:
                                modes_done_list.append("perf")
                        else:
                            print("  cycles=N/A", end="", flush=True)
                    except Exception as exc:
                        print(f"  flash FAILED ({exc})", end="", flush=True)

        print(f"  log: {log_path}")

        res = BenchResult(
            profile=profile,
            build_ok=build_ok,
            sizes=sizes,
            cycles=cycles,
            build_time_s=build_time if build_ok else 0.0,
            modes_done=modes_done_list,
            log_path=log_path,
        )
        results.append(res)
        _save_result(results_json, res)

    return results


# ---------------------------------------------------------------------------
# Reporting & Summaries
# ---------------------------------------------------------------------------


def _elf_flash(s: dict[str, int]) -> int:
    return s.get("text", 0) + s.get("data", 0)


def _get_elf_names(results: list[BenchResult]) -> list[str]:
    for r in results:
        if r.sizes:
            return list(r.sizes.keys())
    return []


def _get_baseline_sizes(
    results: list[BenchResult], elf_names: list[str]
) -> dict[str, int]:
    for r in results:
        if r.profile.name == "baseline" and r.build_ok and r.sizes:
            return {name: _elf_flash(r.sizes.get(name, {})) for name in elf_names}
    return {}


def _sort_by_size(
    results: list[BenchResult], elf_names: list[str]
) -> list[BenchResult]:
    """Sort results by total flash size ascending."""

    def _key(r: BenchResult) -> tuple[int, int, str]:
        if not r.build_ok or not r.sizes or not elf_names:
            return (1, 0, r.profile.name)
        total = sum(_elf_flash(r.sizes.get(name, {})) for name in elf_names)
        return (0, total, r.profile.name)

    return sorted(results, key=_key)


def _sort_by_perf(results: list[BenchResult]) -> list[BenchResult]:
    """Sort results by SysTick cycles ascending."""

    def _key(r: BenchResult) -> tuple[int, int, str]:
        if not r.build_ok or r.cycles is None:
            return (1, 0, r.profile.name)
        return (0, r.cycles, r.profile.name)

    return sorted(results, key=_key)


def _print_size_summary(results: list[BenchResult]) -> None:
    elf_names = _get_elf_names(results)
    if not elf_names:
        print("\n[no size data]")
        return

    baseline = _get_baseline_sizes(results, elf_names)
    display_results = _sort_by_size(results, elf_names)

    col_w = 14
    elf_header = "".join(f"{n:>{col_w}}" for n in elf_names)
    header = f"{'Profile':<22} {'St':>2}  {elf_header}  {'total':>{col_w}}"
    print(f"\n{'=' * len(header)}")
    print("SIZE SUMMARY  (flash = text+data bytes per ELF)")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for r in display_results:
        status = "OK" if r.build_ok else "!!"
        if not r.sizes:
            empty = "".join(f"{'N/A':>{col_w}}" for _ in elf_names)
            print(f"{r.profile.name:<22} {status:>2}  {empty}  {'N/A':>{col_w}}")
            continue

        total = 0
        cols = ""
        for name in elf_names:
            fb = _elf_flash(r.sizes.get(name, {}))
            total += fb
            cell = f"{fb:,}"
            base = baseline.get(name)
            if base and fb != base:
                d = fb - base
                cell += f"({'+' if d > 0 else ''}{d:,})"
            cols += f"{cell:>{col_w}}"

        total_str = f"{total:,}"
        base_total = sum(baseline.values())
        if base_total and total != base_total:
            d = total - base_total
            total_str += f"({'+' if d > 0 else ''}{d:,})"
        print(f"{r.profile.name:<22} {status:>2}  {cols}  {total_str:>{col_w}}")


def _print_perf_summary(results: list[BenchResult]) -> None:
    print(f"\n{'=' * 70}\nPERFORMANCE SUMMARY\n{'=' * 70}")
    header = f"{'Profile':<22} {'Status':>6}  {'Cycles':>24}"
    print(header)
    print("-" * len(header))

    baseline_cycles = next(
        (r.cycles for r in results if r.profile.name == "baseline" and r.build_ok), None
    )
    for r in _sort_by_perf(results):
        status = "OK" if r.build_ok else "FAIL"
        if r.cycles is not None:
            cycle_str = f"{r.cycles:,}"
            if baseline_cycles and r.cycles != baseline_cycles:
                delta = r.cycles - baseline_cycles
                cycle_str += f" ({'+' if delta > 0 else ''}{delta:,})"
        else:
            cycle_str = "N/A"
        print(f"{r.profile.name:<22} {status:>6}  {cycle_str:>24}")


def print_summary(
    results: list[BenchResult], bench_size: bool, bench_perf: bool
) -> None:
    """Print console summary table for size and performance benchmarks."""
    if bench_size:
        _print_size_summary(results)
    if bench_perf:
        _print_perf_summary(results)
    print("\nNotes:")
    if bench_size:
        print("  flash (B) = text + data sections of secure_ipc ELF (via llvm-size).")
    if bench_perf:
        print(
            "  Cycles    = SysTick cycles for psa_initial_attest_get_token (24-bit, ~48 MHz)."
        )
    print(
        "  Build times: "
        + ", ".join(f"{r.profile.name}={r.build_time_s:.0f}s" for r in results)
    )


def _size_markdown_table(results: list[BenchResult]) -> str:
    elf_names = _get_elf_names(results)
    if not elf_names:
        return "_No size data available._\n"

    baseline = _get_baseline_sizes(results, elf_names)
    display_results = _sort_by_size(results, elf_names)

    header = ["Profile", "St", *elf_names, "total"]
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join(["---", "---", *("---:" for _ in elf_names), "---:"]) + " |",
    ]

    for r in display_results:
        status = "OK" if r.build_ok else "!!"
        if not r.sizes:
            row = [r.profile.name, status, *("N/A" for _ in elf_names), "N/A"]
            lines.append("| " + " | ".join(row) + " |")
            continue

        total = 0
        cells: list[str] = []
        for name in elf_names:
            fb = _elf_flash(r.sizes.get(name, {}))
            total += fb
            cell = f"{fb:,}"
            base = baseline.get(name)
            if base and fb != base:
                d = fb - base
                cell += f" ({'+' if d > 0 else ''}{d:,})"
            cells.append(cell)

        total_cell = f"{total:,}"
        base_total = sum(baseline.values())
        if base_total and total != base_total:
            d = total - base_total
            total_cell += f" ({'+' if d > 0 else ''}{d:,})"

        row = [r.profile.name, status, *cells, total_cell]
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines) + "\n"


def _perf_markdown_table(results: list[BenchResult]) -> str:
    lines = ["| Profile | Status | Cycles |", "| --- | --- | ---: |"]

    baseline_cycles = next(
        (r.cycles for r in results if r.profile.name == "baseline" and r.build_ok), None
    )

    for r in _sort_by_perf(results):
        status = "OK" if r.build_ok else "FAIL"
        if r.cycles is None:
            cycle_cell = "N/A"
        else:
            cycle_cell = f"{r.cycles:,}"
            if baseline_cycles and r.cycles != baseline_cycles:
                delta = r.cycles - baseline_cycles
                cycle_cell += f" ({'+' if delta > 0 else ''}{delta:,})"
        lines.append(f"| {r.profile.name} | {status} | {cycle_cell} |")

    return "\n".join(lines) + "\n"


def write_summary_markdown(
    results: list[BenchResult],
    output_path: Path,
    results_json: Path,
) -> None:
    """Generate Markdown report summarizing benchmark results."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    lines: list[str] = [
        "# IPC Benchmark Summary",
        "",
        f"Generated: {stamp}",
        f"Results JSON: {results_json}",
        "",
    ]

    if any(r.sizes for r in results):
        lines.extend(
            [
                "## Size Summary",
                "",
                "Flash bytes are computed as text + data for each ELF.",
                "",
                _size_markdown_table(results).rstrip(),
                "",
            ]
        )
    if any(r.cycles is not None for r in results):
        lines.extend(
            [
                "## Performance Summary",
                "",
                "Cycles are SysTick cycles for psa_initial_attest_get_token.",
                "",
                _perf_markdown_table(results).rstrip(),
                "",
            ]
        )

    build_times = ", ".join(f"{r.profile.name}={r.build_time_s:.0f}s" for r in results)
    lines.extend(
        [
            "## Build Times",
            "",
            build_times or "N/A",
            "",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_argument_group(
        "benchmark mode",
        "Select what to measure. Both flags may be combined; default is both.",
    )
    mode.add_argument(
        "--size",
        action="store_true",
        help="Build and report ELF section sizes (text/data/bss). No board needed.",
    )
    mode.add_argument(
        "--perf",
        action="store_true",
        help="Build, flash, and measure SysTick cycles via UART. Board must be connected.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=SERIAL_TIMEOUT,
        help=f"Seconds to wait for UART output after reset (default: {SERIAL_TIMEOUT}). Only used with --perf.",
    )
    parser.add_argument(
        "--profiles",
        nargs="+",
        metavar="NAME",
        help="Run only specific profiles by name (default: all).",
    )
    parser.add_argument(
        "--results",
        default=str(DEFAULT_RESULTS_JSON),
        metavar="PATH",
        help=f"JSON file to store/resume results (default: {DEFAULT_RESULTS_JSON.name}).",
    )
    parser.add_argument(
        "--markdown",
        default=str(DEFAULT_SUMMARY_MD),
        metavar="PATH",
        help=f"Write a Markdown summary report to PATH (default: {DEFAULT_SUMMARY_MD.name}).",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete existing results JSON and start fresh.",
    )
    args = parser.parse_args()

    bench_size = args.size or not args.perf
    bench_perf = args.perf or not args.size

    profiles = PROFILES
    if args.profiles:
        requested = set(args.profiles)
        profiles = [p for p in PROFILES if p.name in requested]
        unknown = requested - {p.name for p in PROFILES}
        if unknown:
            print(
                f"Unknown profile names: {', '.join(sorted(unknown))}",
                file=sys.stderr,
            )
            print(f"Available: {', '.join(p.name for p in PROFILES)}", file=sys.stderr)
            sys.exit(1)

    results_json = Path(args.results)
    if args.reset and results_json.exists():
        results_json.unlink()
        print(f"Cleared existing results: {results_json}")

    modes = []
    if bench_size:
        modes.append("size")
    if bench_perf:
        modes.append(f"perf (UART timeout={args.timeout}s)")
    existing_count = len(_load_json(results_json))
    resume_note = f", {existing_count} already done" if existing_count else ""
    print(
        f"Benchmarking {len(profiles)} profile(s) — mode: {' + '.join(modes)}{resume_note}"
    )
    print(f"Results JSON: {results_json}  Logs: {LOG_DIR}")

    results = run_bench(
        profiles,
        bench_size=bench_size,
        bench_perf=bench_perf,
        uart_timeout=args.timeout,
        results_json=results_json,
    )
    print_summary(results, bench_size=bench_size, bench_perf=bench_perf)

    markdown_path = Path(args.markdown)
    write_summary_markdown(
        results,
        output_path=markdown_path,
        results_json=results_json,
    )
    print(f"Wrote markdown summary: {markdown_path}")


if __name__ == "__main__":
    main()
