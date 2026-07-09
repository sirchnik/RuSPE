# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

import argparse
import subprocess
import sys
import time
import os
from pathlib import Path
import traceback

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boards.musca_b1.secure.tasks import get_qemu_cmd
from tools.tests.common import (
    QemuRunner,
    collect_token_from_telnet,
    run_go_test_client,
    VERBOSE,
)


def build_images(debug: bool) -> tuple[Path, Path]:
    print("Building images...")
    inv_path = REPO_ROOT / ".venv" / "bin" / "inv"
    cmd = [str(inv_path), "build", "--nspe=test"]
    if debug:
        cmd.append("--debug")

    subprocess.run(
        cmd,
        cwd=REPO_ROOT / "boards" / "musca_b1" / "secure",
        check=True,
    )

    profile = "debug" if debug else "release"
    target_dir = REPO_ROOT / "target" / "thumbv8m.main-none-eabi" / profile
    secure_elf = target_dir / "musca_b1_secure"
    non_secure_elf = target_dir / "musca_b1_test_nspe"
    return secure_elf, non_secure_elf


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Musca QEMU integration test.")
    parser.add_argument(
        "--debug", action="store_true", help="Build and use debug profile."
    )
    args = parser.parse_args()
    try:
        secure_elf, non_secure_elf = build_images(args.debug)

        PORT = 23638

        print("Starting QEMU...")
        qemu_cmd = get_qemu_cmd(
            secure_elf, non_secure_elf, telnet_port=PORT, telnet_wait=True
        )

        # Debug: print the exact QEMU command used only when verbose
        if VERBOSE:
            print("QEMU command:", " ".join(qemu_cmd))

        runner = QemuRunner(qemu_cmd, cwd=REPO_ROOT)
        runner.start()

        # Wait for QEMU to open the telnet server; CI can be slower so allow
        # overriding the wait and timeout via env vars.
        initial_wait = int(os.getenv("MUSCA_INITIAL_WAIT", "5"))
        telnet_timeout = int(os.getenv("MUSCA_TELNET_TIMEOUT", "15"))
        time.sleep(initial_wait)

        token_hex = collect_token_from_telnet(port=PORT, timeout=telnet_timeout)

        runner.stop()

        if not runner.spe_done:
            print("Error: Did not see 'Init SPE done...' in stdout.")
            sys.exit(1)

        if not token_hex:
            print("Error: Token collection failed.")
            sys.exit(1)

        print("NSPE output valid.")
        print("Token:", token_hex[:30] + "...")

        success = run_go_test_client(REPO_ROOT, token_hex)
        if not success:
            sys.exit(1)

        print("Test passed!")
    except Exception:
        print("Unhandled exception in test_musca.py:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
