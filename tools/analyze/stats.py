# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

import contextlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


def resolve_nm_tool() -> Path | None:
    """Find arm-none-eabi-nm, llvm-nm, or rust-nm."""
    for name in ("arm-none-eabi-nm", "llvm-nm", "rust-nm"):
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
                    for name in ("llvm-nm.exe", "llvm-nm"):
                        candidate = bin_dir / name
                        if candidate.exists():
                            return candidate
    return None


def resolve_size_tool() -> Path | None:
    """Find arm-none-eabi-size, llvm-size, or rust-size."""
    for name in ("arm-none-eabi-size", "llvm-size", "rust-size"):
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


@dataclass
class StackStats:
    stack_start: int
    stack_end: int
    stack_left: int
    ram_start: int | None
    total_ram: int | None
    static_ram_used: int | None
    stack_pct: float | None


def get_stack_stats(elf_path: Path) -> StackStats | None:
    """Extract symbol bounds and compute remaining stack space and RAM usage."""
    nm_tool = resolve_nm_tool()
    if not nm_tool or not elf_path.exists():
        return None

    try:
        res = subprocess.run(
            [str(nm_tool), str(elf_path)],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return None

    symbols: dict[str, int] = {}
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            addr_str, _, name = parts[0], parts[1], parts[2]
            try:
                symbols[name] = int(addr_str, 16)
            except ValueError:
                pass

    sstack = (
        symbols.get("_sstack") if "_sstack" in symbols else symbols.get("_stack_limit")
    )
    estack = (
        symbols.get("_estack") if "_estack" in symbols else symbols.get("_stack_top")
    )
    ram_start = symbols.get("_ram_start")

    if sstack is None or estack is None:
        return None

    stack_left = estack - sstack

    if ram_start is not None:
        total_ram = estack - ram_start
        static_ram_used = sstack - ram_start
    else:
        sizes = get_elf_section_sizes(elf_path)
        static_ram_used = sizes.get("data", 0) + sizes.get("bss", 0)
        ram_start = sstack - static_ram_used
        total_ram = estack - ram_start

    stack_pct = (stack_left / total_ram * 100.0) if total_ram > 0 else 0.0

    return StackStats(
        stack_start=sstack,
        stack_end=estack,
        stack_left=stack_left,
        ram_start=ram_start,
        total_ram=total_ram,
        static_ram_used=static_ram_used,
        stack_pct=stack_pct,
    )


def get_elf_section_sizes(elf_path: Path) -> dict[str, int]:
    """Return text/data/bss bytes for the given ELF via size tool."""
    size_tool = resolve_size_tool()
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
        except Exception:
            pass
    return {}


def run_cargo_bloat(
    repo_root: Path,
    package_name: str | None = None,
    cwd: Path | None = None,
    target: str = "thumbv8m.main-none-eabi",
    debug: bool = False,
    crates: bool = False,
    env: dict[str, str] | None = None,
) -> str:
    """Run cargo bloat for a given crate and return stdout."""
    cargo = shutil.which("cargo")
    if not cargo:
        return "cargo tool not found."

    cmd = [cargo, "bloat", "--target", target]
    if package_name:
        cmd.extend(["-p", package_name])
    if not debug:
        cmd.append("--release")
    if crates:
        cmd.append("--crates")
    else:
        cmd.extend(["-n", "10"])

    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    working_dir = str(cwd) if cwd else str(repo_root)

    try:
        res = subprocess.run(
            cmd,
            cwd=working_dir,
            capture_output=True,
            text=True,
            env=full_env,
        )
        return res.stdout.strip() if res.returncode == 0 else res.stderr.strip()
    except Exception as exc:
        return f"Failed to run cargo bloat: {exc}"


def print_binary_stats(
    title: str,
    elf_path: Path,
    package_name: str | None = None,
    repo_root: Path | None = None,
    cwd: Path | None = None,
    debug: bool = False,
    crates: bool = False,
    env: dict[str, str] | None = None,
):
    """Print complete stats report for a binary."""
    print("==================================================")
    print(f" STATS: {title}")
    print("==================================================")
    print(f" ELF File: {elf_path}")

    # 1. Section sizes (arm-none-eabi-size)
    sizes = get_elf_section_sizes(elf_path)
    if sizes:
        text = sizes.get("text", 0)
        data = sizes.get("data", 0)
        bss = sizes.get("bss", 0)
        flash_total = text + data
        ram_static = data + bss
        print("\n--- [ arm-none-eabi-size ] ---")
        print(f"  .text section:      {text:>8,} bytes ({text / 1024:>6.2f} KB)")
        print(f"  .data section:      {data:>8,} bytes ({data / 1024:>6.2f} KB)")
        print(f"  .bss section:       {bss:>8,} bytes ({bss / 1024:>6.2f} KB)")
        print(
            f"  Flash Total:        {flash_total:>8,} bytes ({flash_total / 1024:>6.2f} KB)"
        )
        print(
            f"  Static RAM Used:    {ram_static:>8,} bytes ({ram_static / 1024:>6.2f} KB)"
        )

    # 2. Stack Space
    stack_stats = get_stack_stats(elf_path)
    if stack_stats:
        print("\n--- [ Stack & RAM Analysis ] ---")
        if stack_stats.total_ram:
            print(
                f"  Total RAM Allocated: {stack_stats.total_ram:>8,} bytes ({stack_stats.total_ram / 1024:>6.2f} KB)"
            )
        if stack_stats.static_ram_used is not None:
            print(
                f"  Static RAM Reserved:  {stack_stats.static_ram_used:>8,} bytes ({stack_stats.static_ram_used / 1024:>6.2f} KB)"
            )
        print(
            f"  Space Left for Stack: {stack_stats.stack_left:>8,} bytes ({stack_stats.stack_left / 1024:>6.2f} KB)"
        )
        if stack_stats.stack_pct is not None:
            print(
                f"  Stack Space % Left:   {stack_stats.stack_pct:>8.2f}% of RAM available"
            )
    else:
        print("\n--- [ Stack & RAM Analysis ] ---")
        print(
            "  Could not resolve stack symbols (_sstack/_estack or _stack_limit/_stack_top)."
        )

    # 3. Cargo Bloat
    if (package_name or cwd) and (repo_root or cwd):
        print("\n--- [ Cargo Bloat ] ---")
        bloat_out = run_cargo_bloat(
            repo_root=repo_root or Path("."),
            package_name=package_name,
            cwd=cwd,
            debug=debug,
            crates=crates,
            env=env,
        )
        print(bloat_out)
    print()
