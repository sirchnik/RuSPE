<!--
SPDX-FileCopyrightText: Infineon Technologies AG

SPDX-License-Identifier: MIT
-->

# PSOC™ Control C3M5 Evaluation Kit

<img src="https://assets.infineon.com/is/image/infineon/kit-psc3m5-evk-main-picture-kit-psc3m5-evk.png" width="40%">

The [PSOC™ Control C3M5 Evaluation Kit](https://www.infineon.com/evaluation-board/kit-psc3m5-evk) is an evaluation board for the PSOC™ Control C3M5 microcontroller, based on the Arm Cortex-M33 architecture with TrustZone-M.

This directory serves as the root folder for the `psc3m5_evk` board implementation in RuSPE.

---

## Device Provisioning (Protection Contexts)

Infineon's PSOC™ Control C3 features **Protection Contexts (PC)** to partition resources. Out of the box, all contexts are restricted to secure mode. To access non-secure memory segments and run NSPE apps/kernels, the board must be provisioned.

To initialize the workspace configuration and provision the board, run:
```bash
inv provision
```

This task automatically:
1. Checks if `edgeprotecttools` workspace configuration is initialized. If not, it executes `edgeprotecttools -t psoc_c3 init`.
2. Provisions the device with the custom OEM policy configuration found at `edgeprotecttools/ns_policy/policy_oem_provisioning.json`.

---

## Building & Flashing

The secure-world application builds the secure binary, merges it with the chosen non-secure environment (Tock or test application), and produces a combined `.hex` file.

Navigate to the `secure` workspace directory and run:

```bash
cd boards/psc3m5_evk/secure
```

### 1. Using Tock OS Kernel
To build and flash the secure world merged with Tock OS kernel (running `tock_psa_app`):
```bash
inv flash --nspe=tock
```

### 2. Using Test Application
To build and flash the secure world merged with the simple test application:
```bash
inv flash --nspe=test
```

### 3. Alternate Targets
For target programming via OpenOCD instead of `probe-rs`, replace `flash` with `program`:
```bash
inv program --nspe=tock
```

---

## Serial Console & Logging

To monitor secure and non-secure world log output simultaneously, run the split-terminal terminal utility:
```bash
inv term
```

---

## Troubleshooting

### Erasing Flash
If provisioning fails with errors such as `ERROR : Unable to read current LCS value`, it is often because of invalid memory state or locked sectors. Erase all flash pages on the device using:

```bash
invoke erase
```

This command runs OpenOCD with the acquisition-disabled target script configuration to safely erase the target flash memory, resetting the board to a clean state for provisioning.
