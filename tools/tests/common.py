# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

import binascii
import io
import re
import socket
import subprocess
import threading
from pathlib import Path


class QemuRunner:
    def __init__(self, cmd: list[str], cwd: Path):
        self.cmd = cmd
        self.cwd = cwd
        self.qemu: subprocess.Popen[str] | None = None
        self.spe_done = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.qemu = subprocess.Popen(
            self.cmd,
            cwd=self.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        def read_qemu_stdout() -> None:
            if self.qemu is None or self.qemu.stdout is None:
                return
            for line in self.qemu.stdout:
                if "Init SPE done, jumping to non-secure" in line:
                    self.spe_done = True
                    print("Found: Init SPE done, jumping to non-secure")

        self._thread = threading.Thread(target=read_qemu_stdout, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self.qemu:
            self.qemu.terminate()
            self.qemu.wait(timeout=5)


def collect_token_from_telnet(port: int, timeout: int = 5) -> str | None:
    print(f"Connecting to telnet on port {port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
    except Exception as e:
        print(f"Failed to connect to telnet: {e}")
        return None

    s.settimeout(timeout)
    nspe_output = ""
    token_hex: str | None = None

    try:
        while True:
            data = s.recv(4096)
            if not data:
                break
            text = data.decode("utf-8", errors="ignore")
            nspe_output += text

            match = re.search(r"token_buf:\s*([a-fA-F0-9]+)\r?\n", nspe_output)
            if match:
                try:
                    import cbor2

                    token_bytes = binascii.unhexlify(match.group(1))
                    with io.BytesIO(token_bytes) as fp:
                        cbor2.load(fp)
                        exact_len = fp.tell()
                    token_hex = token_bytes[:exact_len].hex()
                    print(
                        f"Extracted token from NSPE output, exact len = {exact_len} bytes."
                    )
                    break
                except ImportError:
                    print("cbor2 module not found, using raw token buffer")
                    token_hex = match.group(1)
                    break
                except Exception as e:
                    print(f"Failed to parse CBOR token: {e}")
                    token_hex = match.group(1)
                    break
    except socket.timeout:
        print("Timeout waiting for token.")

    s.close()
    if token_hex is None:
        print(
            f"Error: Did not find token_buf in NSPE output.\nNSPE Output:\n{nspe_output}"
        )

    return token_hex


def run_go_test_client(repo_root: Path, token_hex: str) -> bool:
    print("Running go test client...")
    go_cmd = ["go", "run", ".", "-token-src", token_hex, "-nonce", "00" * 32]
    try:
        subprocess.run(go_cmd, cwd=repo_root / "tools" / "test-client", check=True)
        print("Go test client verified token successfully.")
        return True
    except subprocess.CalledProcessError:
        print("Go test client failed to verify the token.")
        return False
