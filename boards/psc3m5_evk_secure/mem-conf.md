# Memory Configuration for `psc3m5_evk` with Secure and Non-Secure Worlds

This document summarizes the TrustZone memory split used by the
`psc3m5_evk_secure` board setup.

## Regions Overview

Notes:

- Address ranges are shown as `[start, end)` (end address is exclusive).
- `Secure (S)` is accessible only from secure world.
- `Non-Secure (NS)` is used by the non-secure Tock kernel/application.
- `Shared Memory (SHM)` is intentionally accessible from both worlds.
- `Non-Secure Callable (NSC)` is the secure gateway region for veneers.

### SRAM

| Region                      |  Size |       Configuration |
| --------------------------- | ----: | ------------------: |
| `0x3400_0000`-`0x3400_4000` | 16 KB |          Secure (S) |
| `0x2400_4000`-`0x2400_F000` | 44 KB |     Non-Secure (NS) |
| `0x2400_F000`-`0x2401_0000` |  4 KB | Shared Memory (SHM) |

### Flash

| Region                      |     Size |             Configuration |
| --------------------------- | -------: | ------------------------: |
| `0x3200_0000`-`0x3200_FF00` | 63.75 KB |                Secure (S) |
| `0x3200_FF00`-`0x3201_0000` |    256 B | Non-Secure Callable (NSC) |
| `0x2201_0100`-`0x2204_0000` |   192 KB |           Non-Secure (NS) |

## Implementation

- For bus access control, the Infineon MPC (Memory Protection Controller) has to
  be used that is provisioned using `edgeprotecttools` with the
  `ns_policy/policy_oem_provisioning.json` policy file. This policy configures
  the MPC to enforce the above memory split.
- For software/CPU access control, the standard ARMv8-M SAU (Security
  Attribution Unit) is used in code.
- Peripherals are marked non-secure in code with the PPC (Peripheral Protection
  Controller).
