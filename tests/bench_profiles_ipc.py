# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

"""Benchmark different Cargo release profiles for secure_ipc + test_nspe.

For each profile variant:
  1. Build (release) via invoke, injecting CARGO_PROFILE_RELEASE_* env vars.
  2. Flash to the board with probe-rs, then reset.
  3. Read UART output and extract cycles_elapsed from the SysTick measurement.
  4. Report flash section sizes (text+data) and measured cycles.

Run from the repo root:
    python tests/bench_profiles_ipc.py [--size] [--perf] [--timeout 40]
"""

from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from invoke import Context as InvokeContext

from boards.psc3m5_evk.secure_ipc.tasks import BOARD, _build as _ipc_build
from tools.build.board import flash_hex
from tools.build.invoke_support import run_command
from tools.build.secure_build import FirmwareResult
from tools.debugging.term import get_cypress_port

# ---------------------------------------------------------------------------
# Profile definitions
# Each dict maps CARGO_PROFILE_RELEASE_<KEY> env var suffixes → values.
# The base profile in Cargo.toml already has panic="abort" and debug=true.
# ---------------------------------------------------------------------------

PROFILE_OPT_KEY = "CARGO_PROFILE_RELEASE_OPT_LEVEL"
PROFILE_LTO_KEY = "CARGO_PROFILE_RELEASE_LTO"
PROFILE_CGU_KEY = "CARGO_PROFILE_RELEASE_CODEGEN_UNITS"
PROFILE_DBG_KEY = "CARGO_PROFILE_RELEASE_DEBUG"


@dataclass
class ProfileVariant:
    name: str
    description: str
    env: dict[str, str] = field(default_factory=dict)


# fmt: off
PROFILES: list[ProfileVariant] = [
    ProfileVariant(
        name="baseline",
        description='opt-level="z" lto=fat codegen-units=1 debug=true (current Cargo.toml)',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "1", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-fat-s",
        description='opt-level="s" lto=fat codegen-units=1 (size-focused with different inliner heuristics)',
        env={PROFILE_OPT_KEY: "s", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "1", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-thin-s",
        description='opt-level="s" lto=thin codegen-units=1',
        env={PROFILE_OPT_KEY: "s", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "1", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-thin-z",
        description='opt-level="z" lto=thin codegen-units=1',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "1", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-thin-z-cgu8",
        description='opt-level="z" lto=thin codegen-units=8',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "8", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-thin-z-cgu2",
        description='opt-level="z" lto=thin codegen-units=2',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "2", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-thin-z-cgu16",
        description='opt-level="z" lto=thin codegen-units=16',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "16", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-thin-z-cgu64",
        description='opt-level="z" lto=thin codegen-units=64',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "64", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-thin-z-cgu256",
        description='opt-level="z" lto=thin codegen-units=256',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "256", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-fat-z-cgu4",
        description='opt-level="z" lto=fat codegen-units=4 (sanity-check for fat-LTO cgu impact)',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "4", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="size-fat-s-cgu4",
        description='opt-level="s" lto=fat codegen-units=4',
        env={PROFILE_OPT_KEY: "s", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "4", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="balanced-fat-2",
        description='opt-level=2 lto=fat codegen-units=1 (balanced speed/size)',
        env={PROFILE_OPT_KEY: "2", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "1", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="balanced-thin-2",
        description='opt-level=2 lto=thin codegen-units=1',
        env={PROFILE_OPT_KEY: "2", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "1", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="balanced-thin-2-cgu16",
        description='opt-level=2 lto=thin codegen-units=16',
        env={PROFILE_OPT_KEY: "2", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "16", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="balanced-thin-2-cgu2",
        description='opt-level=2 lto=thin codegen-units=2',
        env={PROFILE_OPT_KEY: "2", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "2", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="balanced-thin-2-cgu64",
        description='opt-level=2 lto=thin codegen-units=64',
        env={PROFILE_OPT_KEY: "2", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "64", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="balanced-thin-2-cgu256",
        description='opt-level=2 lto=thin codegen-units=256',
        env={PROFILE_OPT_KEY: "2", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "256", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-fat-3",
        description='opt-level=3 lto=fat codegen-units=1 (max speed)',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "1", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-thin-3",
        description='opt-level=3 lto=thin codegen-units=1',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "1", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-thin-3-cgu16",
        description='opt-level=3 lto=thin codegen-units=16',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "16", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-thin-3-cgu2",
        description='opt-level=3 lto=thin codegen-units=2',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "2", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-thin-3-cgu8",
        description='opt-level=3 lto=thin codegen-units=8',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "8", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-thin-3-cgu64",
        description='opt-level=3 lto=thin codegen-units=64',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "64", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-thin-3-cgu128",
        description='opt-level=3 lto=thin codegen-units=128',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "128", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-fat-3-cgu4",
        description='opt-level=3 lto=fat codegen-units=4',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "4", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-fat-3-cgu16",
        description='opt-level=3 lto=fat codegen-units=16',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "16", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-thin-3-cgu256",
        description='opt-level=3 lto=thin codegen-units=256',
        env={PROFILE_OPT_KEY: "3", PROFILE_LTO_KEY: "thin", PROFILE_CGU_KEY: "256", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="speed-fat-z-cgu16",
        description='opt-level="z" lto=fat codegen-units=16',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "16", PROFILE_DBG_KEY: "true"},
    ),
    ProfileVariant(
        name="balanced-fat-z-cgu64",
        description='opt-level="z" lto=fat codegen-units=64',
        env={PROFILE_OPT_KEY: "z", PROFILE_LTO_KEY: "fat", PROFILE_CGU_KEY: "64", PROFILE_DBG_KEY: "true"},
    ),
]
# fmt: on

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SECURE_IPC_DIR = REPO_ROOT / "boards" / "psc3m5_evk" / "secure_ipc"
BAUD = 115200
SERIAL_TIMEOUT = 40  # seconds to wait for test output after reset

DEFAULT_RESULTS_JSON = REPO_ROOT / "tests" / "bench_results_ipc.json"
DEFAULT_SUMMARY_MD = REPO_ROOT / "tests" / "bench_size_summary_ipc.md"
LOG_DIR = REPO_ROOT / "tests" / "bench_logs_ipc"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
def _redirect_to_log(log_path: Path) -> Generator[None, None, None]:
    """Redirect all stdout/stderr (Python prints + subprocess) to log_path."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    sys.stdout.flush()
    sys.stderr.flush()

    try:
        saved_1 = os.dup(1)
        saved_2 = os.dup(2)
    except OSError:
        # fd redirection unavailable (e.g. captured test environment)
        with open(log_path, "w", encoding="utf-8") as lf:
            with contextlib.redirect_stdout(lf), contextlib.redirect_stderr(lf):
                yield
        return

    old_stdout, old_stderr = sys.stdout, sys.stderr
    try:
        lf = open(log_path, "w", encoding="utf-8")
        try:
            os.dup2(lf.fileno(), 1)
            os.dup2(lf.fileno(), 2)
            sys.stdout = lf
            sys.stderr = lf
            try:
                yield
            finally:
                lf.flush()
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                os.dup2(saved_1, 1)
                os.dup2(saved_2, 2)
        finally:
            lf.close()
    finally:
        os.close(saved_1)
        os.close(saved_2)


def build(profile: ProfileVariant) -> FirmwareResult:
    """Build secure_ipc with test_nspe for the given profile, using the invoke tasks directly."""
    ctx = InvokeContext()
    with _profile_env(profile):
        return _ipc_build(ctx, nspe="test", app=None, debug=False)


def _resolve_objsize() -> Path | None:
    """Find llvm-size from PATH or the rustc sysroot (llvm-tools component)."""
    for name in ("rust-size", "llvm-size"):
        found = shutil.which(name)
        if found:
            return Path(found)

    # Mirror resolve_objcopy: look inside the active rustc sysroot
    rustc = shutil.which("rustc")
    if rustc:
        try:
            result = subprocess.run(
                [rustc, "--print", "sysroot"],
                capture_output=True, text=True, check=False,
            )
            sysroot = result.stdout.strip()
            if sysroot:
                for bin_dir in (Path(sysroot) / "lib" / "rustlib").glob("*/bin"):
                    for name in ("llvm-size.exe", "llvm-size"):
                        candidate = bin_dir / name
                        if candidate.exists():
                            return candidate
        except Exception:
            pass
    return None


def get_elf_sizes(elf_path: Path) -> dict[str, int]:
    """Return text/data/bss bytes for the given ELF via llvm-size.

    Falls back to raw file size if llvm-size is not available.
    """
    size_tool = _resolve_objsize()
    if size_tool and elf_path.exists():
        try:
            result = subprocess.run(
                [str(size_tool), str(elf_path)],
                capture_output=True,
                text=True,
                check=True,
            )
            # Output: "   text\t   data\t    bss\t    dec\t    hex\tfilename"
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

    # Fallback: raw file size
    size = elf_path.stat().st_size if elf_path.exists() else 0
    return {"file_bytes": size}


def get_all_elf_sizes(firmware: FirmwareResult) -> dict[str, dict[str, int]]:
    """Return section sizes for every ELF produced by the build.

    Keys: ELF short name (e.g. 'secure_ipc', 'test_nspe', service names).
    Values: dict with 'text', 'data', 'bss' (or 'file_bytes' as fallback).
    """
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
    """Flash the merged hex via the board's flash_hex helper, then hardware-reset."""
    ctx = InvokeContext()
    flash_hex(ctx, BOARD, result.merged_hex)
    run_command(["probe-rs", "reset", "--chip", BOARD.chip], cwd=SECURE_IPC_DIR)


def read_cycles_from_uart(timeout: int) -> int | None:
    """Open the Cypress UART port and wait for cycles_elapsed output.

    Returns the integer cycle count, or None on timeout/error.
    """
    try:
        import serial  # type: ignore[import]
    except ImportError:
        print("  [error] pyserial not installed — cannot read UART output.")
        return None

    try:
        port = get_cypress_port()
    except RuntimeError as exc:
        print(f"  [error] {exc}")
        return None

    print(f"  Listening on {port} at {BAUD} baud (timeout={timeout}s) …")
    deadline = time.monotonic() + timeout
    buffer = ""
    cycles_pattern = re.compile(r"cycles_elapsed\s+(\d+)")

    try:
        with serial.Serial(port, BAUD, timeout=1) as ser:
            while time.monotonic() < deadline:
                chunk = ser.read(512)
                if chunk:
                    buffer += chunk.decode("utf-8", errors="replace")
                    m = cycles_pattern.search(buffer)
                    if m:
                        return int(m.group(1))
    except serial.SerialException as exc:
        print(f"  [error] Serial error: {exc}")
        return None

    print("  [warn] Timed out waiting for cycles_elapsed")
    return None


# ---------------------------------------------------------------------------
# JSON persistence
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> dict[str, dict]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_result(path: Path, result: "BenchResult") -> None:
    data = _load_json(path)
    entry: dict = {
        "build_ok": result.build_ok,
        "sizes": result.sizes,
        "cycles": result.cycles,
        "build_time_s": result.build_time_s,
        "modes_done": result.modes_done,
        "log_path": str(result.log_path) if result.log_path else None,
    }
    data[result.profile.name] = entry
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _result_from_json(
    profile: ProfileVariant, entry: dict
) -> "BenchResult":
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
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class BenchResult:
    profile: ProfileVariant
    build_ok: bool
    sizes: dict[str, dict[str, int]]   # elf_name → {text, data, bss}; populated by --size
    cycles: int | None                 # populated by --perf
    build_time_s: float
    modes_done: list[str] = field(default_factory=list)
    log_path: Path | None = None


def _format_sizes(sizes: dict[str, int]) -> str:
    if "file_bytes" in sizes:
        return f"file={sizes['file_bytes']:,} B"
    flash_bytes = sizes.get("text", 0) + sizes.get("data", 0)
    return (
        f"text={sizes['text']:,}  data={sizes['data']:,}  "
        f"bss={sizes['bss']:,}  → flash={flash_bytes:,} B"
    )


def run_bench(
    profiles: list[ProfileVariant],
    bench_size: bool,
    bench_perf: bool,
    uart_timeout: int,
    results_json: Path,
) -> list[BenchResult]:
    existing = _load_json(results_json)
    results: list[BenchResult] = []
    total = len(profiles)

    for idx, profile in enumerate(profiles):
        tag = f"[{idx + 1}/{total}] {profile.name}"

        # --- resumption: skip if all requested modes already recorded ---
        if profile.name in existing:
            entry = existing[profile.name]
            modes_done = set(entry.get("modes_done", []))
            need_size = bench_size and "size" not in modes_done
            need_perf = bench_perf and "perf" not in modes_done
            if not need_size and not need_perf:
                result = _result_from_json(profile, entry)
                results.append(result)
                log_hint = f"  (log: {result.log_path})" if result.log_path else ""
                print(f"{tag}  [skip — already in JSON]{log_hint}")
                continue

        log_path = LOG_DIR / f"{profile.name}.log"
        build_ok = False
        sizes: dict[str, int] = {}
        cycles: int | None = None
        firmware: FirmwareResult | None = None
        modes_done_list: list[str] = []

        # --- build (output captured to log) ---
        print(f"{tag}  building ...", end="", flush=True)
        t0 = time.monotonic()
        try:
            with _redirect_to_log(log_path):
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
                modes_done_list.append("size")

            if bench_perf:
                print("  flashing ...", end="", flush=True)
                try:
                    with _redirect_to_log(log_path):
                        flash(firmware)
                    print("  reading UART ...", end="", flush=True)
                    cycles = read_cycles_from_uart(uart_timeout)
                    if cycles is not None:
                        print(f"  cycles={cycles:,}", end="", flush=True)
                        modes_done_list.append("perf")
                    else:
                        print("  cycles=N/A", end="", flush=True)
                except Exception as exc:
                    print(f"  flash FAILED ({exc})", end="", flush=True)

        print(f"  log: {log_path}")

        result = BenchResult(
            profile=profile,
            build_ok=build_ok,
            sizes=sizes,
            cycles=cycles,
            build_time_s=build_time if build_ok else 0.0,
            modes_done=modes_done_list,
            log_path=log_path,
        )
        results.append(result)
        _save_result(results_json, result)

    return results


def _elf_flash(s: dict[str, int]) -> int:
    return s.get("text", 0) + s.get("data", 0)


def _print_size_summary(results: list[BenchResult]) -> None:
    # Collect ELF names in stable order from first successful result
    elf_names: list[str] = []
    for r in results:
        if r.sizes:
            elf_names = list(r.sizes.keys())
            break

    if not elf_names:
        print("\n[no size data]")
        return

    # Find baseline totals per ELF for delta display
    baseline: dict[str, int] = {}
    for r in results:
        if r.profile.name == "baseline" and r.build_ok and r.sizes:
            baseline = {name: _elf_flash(r.sizes.get(name, {})) for name in elf_names}
            break

    col_w = 14  # width per ELF column
    elf_header = "".join(f"{n:>{col_w}}" for n in elf_names)
    header = f"{'Profile':<22} {'St':>2}  {elf_header}  {'total':>{col_w}}"
    print(f"\n{'='*len(header)}")
    print("SIZE SUMMARY  (flash = text+data bytes per ELF)")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for r in results:
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
                cell += f"({'+'if d>0 else ''}{d:,})"
            cols += f"{cell:>{col_w}}"

        total_str = f"{total:,}"
        base_total = sum(baseline.values())
        if base_total and total != base_total:
            d = total - base_total
            total_str += f"({'+'if d>0 else ''}{d:,})"
        print(f"{r.profile.name:<22} {status:>2}  {cols}  {total_str:>{col_w}}")


def _print_perf_summary(results: list[BenchResult]) -> None:
    print(f"\n{'='*70}")
    print("PERFORMANCE SUMMARY")
    print(f"{'='*70}")
    header = f"{'Profile':<22} {'Status':>6}  {'Cycles':>24}"
    print(header)
    print("-" * len(header))

    baseline_cycles: int | None = None
    for r in results:
        if r.profile.name == "baseline" and r.build_ok:
            baseline_cycles = r.cycles

    for r in results:
        status = "OK" if r.build_ok else "FAIL"
        if r.cycles is not None:
            cycle_str = f"{r.cycles:,}"
            if baseline_cycles and r.cycles != baseline_cycles:
                delta = r.cycles - baseline_cycles
                sign = "+" if delta > 0 else ""
                cycle_str += f" ({sign}{delta:,})"
        else:
            cycle_str = "N/A"
        print(f"{r.profile.name:<22} {status:>6}  {cycle_str:>24}")


def print_summary(results: list[BenchResult], bench_size: bool, bench_perf: bool) -> None:
    if bench_size:
        _print_size_summary(results)
    if bench_perf:
        _print_perf_summary(results)
    print()
    print("Notes:")
    if bench_size:
        print("  flash (B) = text + data sections of secure_ipc ELF (via llvm-size).")
    if bench_perf:
        print("  Cycles    = SysTick cycles for psa_initial_attest_get_token (24-bit, ~48 MHz).")
    print("  Build times: " + ", ".join(f"{r.profile.name}={r.build_time_s:.0f}s" for r in results))


def _size_markdown_table(results: list[BenchResult]) -> str:
    elf_names: list[str] = []
    for r in results:
        if r.sizes:
            elf_names = list(r.sizes.keys())
            break
    if not elf_names:
        return "_No size data available._\n"

    baseline: dict[str, int] = {}
    for r in results:
        if r.profile.name == "baseline" and r.build_ok and r.sizes:
            baseline = {name: _elf_flash(r.sizes.get(name, {})) for name in elf_names}
            break

    header = ["Profile", "St", *elf_names, "total"]
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join(["---", "---", *("---:" for _ in elf_names), "---:"]) + " |",
    ]

    for r in results:
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
    lines = [
        "| Profile | Status | Cycles |",
        "| --- | --- | ---: |",
    ]

    baseline_cycles: int | None = None
    for r in results:
        if r.profile.name == "baseline" and r.build_ok:
            baseline_cycles = r.cycles
            break

    for r in results:
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
    bench_size: bool,
    bench_perf: bool,
    output_path: Path,
    results_json: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    lines: list[str] = [
        "# IPC Benchmark Summary",
        "",
        f"Generated: {stamp}",
        f"Results JSON: {results_json}",
        "",
    ]

    if bench_size:
        lines.extend([
            "## Size Summary",
            "",
            "Flash bytes are computed as text + data for each ELF.",
            "",
            _size_markdown_table(results).rstrip(),
            "",
        ])
    if bench_perf:
        lines.extend([
            "## Performance Summary",
            "",
            "Cycles are SysTick cycles for psa_initial_attest_get_token.",
            "",
            _perf_markdown_table(results).rstrip(),
            "",
        ])

    build_times = ", ".join(f"{r.profile.name}={r.build_time_s:.0f}s" for r in results)
    lines.extend([
        "## Build Times",
        "",
        build_times if build_times else "N/A",
        "",
    ])

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

    # Default: run both if neither flag is given
    bench_size = args.size or not args.perf
    bench_perf = args.perf or not args.size

    profiles = PROFILES
    if args.profiles:
        requested = set(args.profiles)
        profiles = [p for p in PROFILES if p.name in requested]
        unknown = requested - {p.name for p in PROFILES}
        if unknown:
            print(f"Unknown profile names: {', '.join(sorted(unknown))}", file=sys.stderr)
            print(f"Available: {', '.join(p.name for p in PROFILES)}", file=sys.stderr)
            sys.exit(1)

    results_json: Path = Path(args.results)
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
    print(f"Benchmarking {len(profiles)} profile(s) — mode: {' + '.join(modes)}{resume_note}")
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
        bench_size=bench_size,
        bench_perf=bench_perf,
        output_path=markdown_path,
        results_json=results_json,
    )
    print(f"Wrote markdown summary: {markdown_path}")


if __name__ == "__main__":
    main()
