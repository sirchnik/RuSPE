# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

import os
import subprocess


def get_cypress_port() -> str:
    from serial.tools.list_ports import comports

    for port in comports():
        if (
            "Cypress" in (port.manufacturer or "")
            or "Cypress" in (port.description or "")
            or "04B4:" in port.hwid
        ):
            return port.device

    if os.name != "nt":
        import glob

        matches = glob.glob("/dev/serial/by-id/*Cypress*")
        if matches:
            return matches[0]

    raise RuntimeError("Could not find Cypress serial port for non-secure terminal")


def launch_split(cmd_left: str, cmd_right: str):
    if os.name == "nt":
        cmd = f'wt -d . cmd /c "{cmd_left}" ; split-pane -d . cmd /c "{cmd_right}"'
        subprocess.run(cmd, shell=True)
    else:
        tmux_cmd = f"tmux new-session '{cmd_left}' \\; split-window -h '{cmd_right}' \\; set-option destroy-unattached on \\; set -g mouse on \\; attach"

        is_desktop = "DISPLAY" in os.environ or "WAYLAND_DISPLAY" in os.environ

        if is_desktop:
            import shutil

            terminals = [
                "x-terminal-emulator",
                "gnome-terminal",
                "konsole",
                "xfce4-terminal",
                "mate-terminal",
                "wezterm",
                "alacritty",
                "xterm",
            ]
            term = None
            for t in terminals:
                if shutil.which(t):
                    term = t
                    break

            if term:
                if term in ("gnome-terminal", "mate-terminal"):
                    run_cmd = f'{term} -- sh -c "{tmux_cmd}"'
                elif term == "wezterm":
                    run_cmd = f'{term} start -- sh -c "{tmux_cmd}"'
                elif term == "xfce4-terminal":
                    run_cmd = f'{term} -x sh -c "{tmux_cmd}"'
                else:
                    run_cmd = f'{term} -e sh -c "{tmux_cmd}"'
                subprocess.Popen(run_cmd, shell=True)
                return
