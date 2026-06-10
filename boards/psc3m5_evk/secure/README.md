<!--
SPDX-FileCopyrightText: Infineon Technologies AG

SPDX-License-Identifier: MIT
-->

# Secure world application for PSOC Control C3M5 Evaluation Kit

See the [PSC3M5_EVK README](../psc3m5_evk/README.md) for more information about
the board and how to build and flash it.

This board crate is a binary for TrustZone-M secure-world that switches to
non-secure world after initialization.

## Setup

1. Provision the board with `edgeprotecttools`-configuration from this crate:
   (Refer to [PSC3M5_EVK README](../psc3m5_evk/README.md) for more details on
   provisioning)

   ```bash
   cd edgeprotecttools
   edgeprotecttools -t psoc_c3 init
   edgeprotecttools -t psoc_c3 provision-device -p ns_policy/policy_oem_provisioning.json
   ```

2. Build and flash the secure world application:

   ```bash
   invoke flash
   ```

   This will build the secure world application, merge it with the non-secure
   kernel, and flash the combined binary to the board.
