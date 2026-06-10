<!--
SPDX-FileCopyrightText: Infineon Technologies AG

SPDX-License-Identifier: MIT
-->

# Memory Configuration for `psc3m5_evk_secure_ipc`

This document summarizes the TrustZone memory split used by the
`psc3m5_evk_secure_ipc` board setup.

See also standard [secure board docs](../psc3m5_evk_secure/mem-conf.md) for general information.

## Configuration

**Service placement is configurable at build time** via Python configuration in [tasks.py](./tasks.py).
The selected service entry in `tools/build/service_catalog.py` controls the service handle and memory placement
(flash origin/length and SRAM origin/length).
Both the selected service crate and secure IPC board are compiled from the same configuration, ensuring a coherent merged image.

Default values (current configuration):
- Flash: `0x3201_0000` - `0x3201_3F00` (31.75 KB)
- SRAM: `0x3400_2F00` - `0x3400_4000` (8.7 KB)

To change service placement or switch services, update `tools/build/service_catalog.py` and rebuild.

## Regions Overview

### SRAM

| Region                      |     Size |                           Configuration |
| --------------------------- | -------: | --------------------------------------: |
| `0x3400_0000`-`0x3400_2F00` | 12,032 B |                   Secure privileged (S) |
| `0x3400_2F00`-`0x3400_5100` |  8,704 B |                 Secure unprivileged (S) |
| `0x2400_5100`-`0x2400_88E4` | 14,308 B |   Non-Secure privileged (NS kernel RAM) |
| `0x2400_88E4`-`0x2400_F000` | 26,396 B | Non-Secure unprivileged (NS app memory) |
| `0x2400_F000`-`0x2401_0000` |     4 KB |            Shared Memory (SHM) (unused) |

### Flash

| Region                      |     Size |             Configuration |
| --------------------------- | -------: | ------------------------: |
| `0x3200_0000`-`0x3201_0000` |    64 KB |     Secure Privileged (S) |
| `0x3201_0000`-`0x3201_FF00` | 63.75 KB |   Secure Unprivileged (S) |
| `0x3201_FF00`-`0x3202_0000` |    256 B | Non-Secure Callable (NSC) |
| `0x2202_0000`-`0x2204_0000` |   128 KB |           Non-Secure (NS) |

## Files

These files are relevant for the memory configuration:

- `boards/psc3m5_evk_secure_ipc/layout.ld`: Top-level linker script for the secure IPC SPM image, secure privileged SRAM, and NSC veneer region
- `boards/psc3m5_evk_secure_ipc/secure_layout.ld`: Section placement for the secure IPC SPM image
- `boards/services/*/layout.ld`: Memory-region definitions for each embedded service image
- `boards/psc3m5_evk_test/layout.ld`: Non-secure linker layout for the companion non-secure image
- `chips/psc3/src/security.rs`: SAU/PPC configuration defining the secure and non-secure split
