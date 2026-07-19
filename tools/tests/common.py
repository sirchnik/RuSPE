# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

import binascii
import io
import os
import re
import socket
import subprocess
import threading
import time
import traceback
from pathlib import Path
import cbor2


def _verbose() -> bool:
    v = os.getenv("VERBOSE", "0").lower()
    return v in ("1", "true", "yes", "on")


VERBOSE = _verbose()


class QemuRunner:
    def __init__(self, cmd: list[str], cwd: Path):
        self.cmd = cmd
        self.cwd = cwd
        self.qemu: subprocess.Popen[str] | None = None
        self.spe_done = False
        self._spe_done_logged = False
        self._threads: list[threading.Thread] = []
        
        self.secure_port: int | None = None
        for i, arg in enumerate(self.cmd):
            if arg == "-serial" and i + 1 < len(self.cmd):
                next_arg = self.cmd[i + 1]
                if next_arg.startswith("telnet:127.0.0.1:"):
                    self.secure_port = int(next_arg.split(":")[2].split(",")[0])
                    break

    def _read_qemu_stdout(self) -> None:
        if self.qemu is None or self.qemu.stdout is None:
            return
        for line in self.qemu.stdout:
            if VERBOSE:
                print("QEMU:", line.rstrip())
            if "Init SPE done, jumping to non-secure" in line and not self._spe_done_logged:
                self.spe_done = True
                self._spe_done_logged = True
                print("Init SPE done, jumping to non-secure")

    def _read_secure_telnet(self) -> None:
        if not self.secure_port:
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            time.sleep(1.0)
            s.connect(("127.0.0.1", self.secure_port))
            buffer = ""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                text = data.decode("utf-8", errors="ignore")
                buffer += text
                if VERBOSE:
                    print("SECURE:", text.rstrip())
                if "Init SPE done, jumping to non-secure" in buffer and not self._spe_done_logged:
                    self.spe_done = True
                    self._spe_done_logged = True
                    print("Init SPE done, jumping to non-secure")
        except Exception as e:
            print(f"Failed to connect to secure telnet: {e}")

    def start(self) -> None:
        self.qemu = subprocess.Popen(
            self.cmd,
            cwd=self.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if VERBOSE:
            print(f"Starting QEMU: {' '.join(self.cmd)} (cwd={self.cwd})")

        stdout_thread = threading.Thread(target=self._read_qemu_stdout, daemon=True)
        stdout_thread.start()
        self._threads.append(stdout_thread)

        if self.secure_port:
            secure_thread = threading.Thread(target=self._read_secure_telnet, daemon=True)
            secure_thread.start()
            self._threads.append(secure_thread)

    def stop(self) -> None:
        if self.qemu:
            self.qemu.terminate()
            self.qemu.wait(timeout=5)


def collect_token_from_telnet(port: int, timeout: int = 5) -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        print(f"Connected to telnet on 127.0.0.1:{port}")
    except Exception as e:
        print(f"Failed to connect to telnet: {e}")
        return None

    s.settimeout(timeout)
    nspe_output = ""
    token_hex: str | None = None

    try:
        while True:
            try:
                data = s.recv(4096)
            except Exception as e:
                print(f"Exception while receiving from telnet: {e}")
                traceback.print_exc()
                break
            if not data:
                break
            text = data.decode("utf-8", errors="ignore")
            nspe_output += text

            match = re.search(r"token_buf:\s*([a-fA-F0-9]+)\r?\n", nspe_output)
            if match:
                try:
                    token_bytes = binascii.unhexlify(match.group(1))
                    with io.BytesIO(token_bytes) as fp:
                        cbor2.load(fp)
                        exact_len = fp.tell()
                    token_hex = token_bytes[:exact_len].hex()
                    if VERBOSE:
                        print(
                            f"Extracted token from NSPE output, exact len = {exact_len} bytes."
                        )
                    break
                except Exception as e:
                    print(f"Failed to parse CBOR token: {e}")
                    traceback.print_exc()
                    token_hex = match.group(1)
                    break
    except socket.timeout:
        print("Timeout waiting for token.")
        print("NSPE output so far:\n" + nspe_output)

    s.close()
    if token_hex is None:
        print(
            f"Error: Did not find token_buf in NSPE output. NSPE Output:\n{nspe_output}..."
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
