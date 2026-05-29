# Memory Configuration for `psc3m5_evk_secure_ipc`

This document summarizes the TrustZone memory split used by the
`psc3m5_evk_secure_ipc` board setup.

See also standard [secure board docs](../psc3m5_evk_secure/mem-conf.md) for general information.

## Regions Overview

### SRAM

| Region                      |     Size |                           Configuration |
| --------------------------- | -------: | --------------------------------------: |
| `0x3400_0000`-`0x3400_3800` | 14,336 B |        Secure privileged (S) (SPM SRAM) |
| `0x3400_3800`-`0x3400_4000` |  2,048 B | Secure unprivileged (S) (attest service) |
| `0x2400_4000`-`0x2400_77E4` | 14,308 B |   Non-Secure privileged (NS kernel RAM) |
| `0x2400_77E4`-`0x2400_F000` | 30,748 B | Non-Secure unprivileged (NS app memory) |
| `0x2400_F000`-`0x2401_0000` |     4 KB |            Shared Memory (SHM) (unused) |

### Flash

| Region                      |     Size |                 Configuration |
| --------------------------- | -------: | ----------------------------: |
| `0x3200_0000`-`0x3201_0000` |    64 KB |     Secure (S), IPC SPM image |
| `0x3201_0000`-`0x3201_3F00` | 15.75 KB | Secure (S), embedded services |
| `0x3201_3F00`-`0x3201_4000` |    256 B |     Non-Secure Callable (NSC) |
| `0x2201_4000`-`0x2204_0000` |   176 KB |               Non-Secure (NS) |

## Files

These files are relevant for the memory configuration:

- `boards/psc3m5_evk_secure_ipc/layout.ld`: Top-level linker script for the secure IPC SPM image, secure privileged SRAM, and NSC veneer region
- `boards/psc3m5_evk_secure_ipc/secure_layout.ld`: Section placement for the secure IPC SPM image
- `boards/services/attest/layout.ld`: Memory-region definitions for the embedded attestation service image and its secure unprivileged SRAM window
- `boards/services/attest/service_layout.ld`: Section placement for the embedded attestation service image
- `tock/boards/build_scripts/tock_kernel_layout.ld`: Non-secure linker layout defining `_sappmem`
- `chips/psc3/src/security.rs`: SAU/PPC configuration defining the secure and non-secure split
