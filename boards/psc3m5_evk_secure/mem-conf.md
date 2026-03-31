## SRAM

| Region                      |  Size |       Configuration |
| --------------------------- | ----: | ------------------: |
| `0x3400_0000`-`0x3000_4000` | 16 KB |          Secure (S) |
| `0x2400_4000`-`0x2000_F000` | 44 KB |     Non-Secure (NS) |
| `0x2400_F000`-`0x2001_0000` |  4 KB | Shared Memory (SHM) |

## Flash

| Region                      |      Size |             Configuration |
| --------------------------- | --------: | ------------------------: |
| `0x3200_0000`-`0x3001_0000` |     64 KB |                Secure (S) |
| `0x3201_0000`-`0x3001_0100` |     256 B | Non-Secure Callable (NSC) |
| `0x2201_0100`-`0x2004_0000` | 191,75 KB |           Non-Secure (NS) |
