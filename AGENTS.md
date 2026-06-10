<!--
SPDX-FileCopyrightText: Infineon Technologies AG

SPDX-License-Identifier: MIT
-->

# RuSPE AGENTS.md

This project uses invoke for directory specific tasks make sure to change directory.
It should be found at `./.venv/bin/invoke`.

Available tasks are:
- `invoke build` - builds all projects
- `invoke fmt` - formats all projects
- `invoke clippy` - runs clippy on all projects
- `invoke test` - runs tests on all projects
