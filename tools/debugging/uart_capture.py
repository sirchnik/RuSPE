# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

"""Reusable helpers to flash a board and capture its UART output.

The UART is always opened *before* programming starts, so no output emitted
right after the reset can be lost. Captured text is only accepted once the
start marker of the freshly flashed firmware has been seen, which guarantees
that the result belongs to the new image and not to a previous run.
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Generator, IO, Iterable

import contextlib

from invoke.context import Context

from tools.build.board import BoardConfig, flash_hex, program_hex
from tools.debugging.term import get_cypress_port

if TYPE_CHECKING:
    import serial

DEFAULT_BAUD = 115200
DEFAULT_TIMEOUT = 40

NSPE_START_MARKER = "--- NSPE TEST START ---"
NSPE_END_MARKER = "--- NSPE TEST END ---"


class UartError(RuntimeError):
    """Raised when the expected UART output could not be captured."""


@dataclass(frozen=True)
class UartCapture:
    """Text captured from the UART, starting at the firmware start marker."""

    text: str
    complete: bool

    def search(self, pattern: str) -> re.Match[str] | None:
        return re.search(pattern, self.text)

    def value(self, pattern: str, group: int = 1) -> str | None:
        match = self.search(pattern)
        return match.group(group) if match else None

    def int_value(self, pattern: str, group: int = 1) -> int | None:
        raw = self.value(pattern, group)
        return int(raw) if raw is not None else None

    @property
    def cycles(self) -> int | None:
        return self.int_value(r"cycles_elapsed\s+(\d+)")


class UartMonitor:
    """Serial reader that can be opened before the board is programmed."""

    def __init__(
        self,
        port: str | None = None,
        baud: int = DEFAULT_BAUD,
        echo: bool = True,
        out: IO[str] | None = None,
    ) -> None:
        self.port = port or get_cypress_port()
        self.baud = baud
        self.echo = echo
        self._out = out
        self._serial: serial.Serial | None = None

    def __enter__(self) -> UartMonitor:
        import serial  # imported lazily so builds work without pyserial

        self._serial = serial.Serial(self.port, self.baud, timeout=0.1)
        self.discard()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._serial is not None:
            self._serial.close()
            self._serial = None

    def discard(self) -> None:
        """Drop everything currently buffered (e.g. output of a previous run)."""
        if self._serial is not None:
            with contextlib.suppress(Exception):
                self._serial.reset_input_buffer()

    def _write(self, text: str) -> None:
        if not self.echo:
            return
        stream = self._out or sys.stdout
        stream.write(text)
        stream.flush()

    def capture(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        start_marker: str | None = NSPE_START_MARKER,
        end_marker: str | None = NSPE_END_MARKER,
        expect: Iterable[str] = (),
        idle_timeout: float | None = None,
    ) -> UartCapture:
        """Read until `end_marker` (or timeout) and return the captured text.

        `start_marker` anchors the capture: text received before it is dropped,
        so only output of the currently running firmware is returned.
        `expect` are additional strings (e.g. a build identifier) that must be
        present, otherwise a `UartError` is raised — this catches the case where
        the board is still running an older image.
        """
        if self._serial is None:
            raise UartError("UartMonitor is not open; use it as a context manager")

        deadline = time.monotonic() + timeout
        last_data = time.monotonic()
        buffer = ""
        complete = False

        while time.monotonic() < deadline:
            chunk = self._serial.read(512)
            if not chunk:
                if idle_timeout is not None and buffer and (
                    time.monotonic() - last_data > idle_timeout
                ):
                    break
                continue

            last_data = time.monotonic()
            text = chunk.decode("utf-8", errors="replace")
            buffer += text
            self._write(text)

            if end_marker and end_marker in _anchored(buffer, start_marker):
                complete = True
                break

        captured = _anchored(buffer, start_marker)
        if start_marker and start_marker not in buffer:
            raise UartError(
                f"No '{start_marker}' seen on {self.port} within {timeout:.0f}s — "
                "the board may not have been reset or is running other firmware"
            )

        missing = [marker for marker in expect if marker not in captured]
        if missing:
            raise UartError(
                f"UART output on {self.port} is missing {missing}; "
                "the board is likely running a different image than the one just flashed"
            )

        return UartCapture(text=captured, complete=complete)


def _anchored(buffer: str, start_marker: str | None) -> str:
    # Anchor on the last marker so stale output of a previous run is skipped.
    if start_marker and start_marker in buffer:
        return buffer[buffer.rindex(start_marker) :]
    return buffer


def flash_image(
    ctx: Context, board: BoardConfig, hex_path: Path, openocd: bool = False
) -> Path:
    """Program `hex_path` onto `board` (probe-rs by default, OpenOCD optional)."""
    if openocd:
        return program_hex(ctx, board, hex_path)
    return flash_hex(ctx, board, hex_path)


@contextlib.contextmanager
def uart_attached(
    port: str | None = None,
    baud: int = DEFAULT_BAUD,
    echo: bool = True,
    out: IO[str] | None = None,
) -> Generator[UartMonitor, None, None]:
    """Open the board UART, yielding a monitor that is ready before flashing."""
    with UartMonitor(port=port, baud=baud, echo=echo, out=out) as monitor:
        yield monitor


def flash_and_capture(
    ctx: Context,
    board: BoardConfig,
    hex_path: Path,
    *,
    port: str | None = None,
    baud: int = DEFAULT_BAUD,
    timeout: float = DEFAULT_TIMEOUT,
    openocd: bool = False,
    echo: bool = True,
    out: IO[str] | None = None,
    start_marker: str | None = NSPE_START_MARKER,
    end_marker: str | None = NSPE_END_MARKER,
    expect: Iterable[str] = (),
    idle_timeout: float | None = None,
    flash_out: IO[str] | None = None,
) -> UartCapture:
    """Attach to the UART, flash the image and return the resulting output."""
    with uart_attached(port=port, baud=baud, echo=echo, out=out) as monitor:
        with _redirect(flash_out):
            flash_image(ctx, board, hex_path, openocd=openocd)
        return monitor.capture(
            timeout=timeout,
            start_marker=start_marker,
            end_marker=end_marker,
            expect=expect,
            idle_timeout=idle_timeout,
        )


@contextlib.contextmanager
def _redirect(stream: IO[str] | None) -> Generator[None, None, None]:
    if stream is None:
        yield
        return
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        yield


def run_firmware(
    ctx: Context,
    board: BoardConfig,
    hex_path: Path,
    *,
    port: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    openocd: bool = False,
    markers: bool = True,
    idle_timeout: float | None = None,
) -> UartCapture:
    """Flash an image and stream its UART output to stdout.

    With `markers=False` (e.g. for the Tock NSPE, which has no test markers)
    the capture stops after `idle_timeout` seconds without new data.
    """
    resolved_port = port or get_cypress_port()
    print(f"Attaching UART {resolved_port} before flashing {hex_path.name} ...")
    capture = flash_and_capture(
        ctx,
        board,
        hex_path,
        port=resolved_port,
        timeout=timeout,
        openocd=openocd,
        start_marker=NSPE_START_MARKER if markers else None,
        end_marker=NSPE_END_MARKER if markers else None,
        idle_timeout=idle_timeout if idle_timeout is not None else (None if markers else 3.0),
    )
    if not capture.complete and markers:
        print(f"\n[warn] '{NSPE_END_MARKER}' not seen within {timeout:.0f}s")
    if capture.cycles is not None:
        print(f"\ncycles_elapsed: {capture.cycles:,}")
    return capture
