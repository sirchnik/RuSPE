<!--
SPDX-FileCopyrightText: Infineon Technologies AG

SPDX-License-Identifier: MIT
-->

# Test client

Test client for [`integrations/tock/tock_psa_app`](../../integrations/tock/tock_psa_app).

This is a go application as https://github.com/veraison/psatoken provides validation
for psa-tokens.

Token retrieval supports both direct serial access and telnet bridging.
Use `-tty telnet://HOST[:PORT]` (default port: `23`) to talk to a remote target.

Timeout and pacing values can be configured from the command line:

- `-token-timeout` overall timeout for a token request (default: `30s`, `0` disables)
- `-serial-read-timeout` timeout used for serial/telnet read operations (default: `2s`)
