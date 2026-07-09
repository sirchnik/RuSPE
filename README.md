<!--
SPDX-FileCopyrightText: Infineon Technologies AG

SPDX-License-Identifier: MIT
-->

<div align="center">
  <img src="docs/logo.svg" alt="RuSPE Logo" width="200"/>

  <h1>RuSPE</h1> 
  <span style="font-size: 18px;">
  Proof-of-concept Rust implementation of an TrustedFirmware-M
  (TF-M)/ARM Firware Framework
  </span>
</div>


### Current status
- Initial attestation: basic support (initial_attestation) is implemented.
- Isolation: MPU-based isolation is implemented

<div align="center">
  <img src="docs/spe-arch.svg" alt="RuSPE Architecture" width="300"/>
</div>



**Everything is a work in progress.**

## Installation

Needed tools:
- Rust toolchain
- probe-rs or ModusToolboxProgTools OpenOCD (for debugging)
- Python
- Go (optional for test client)

Setup workspace:

```bash
uv venv
uv sync # install Python dependencies
source .venv/bin/activate # activate the virtual environment
inv install # install cargo tools
inv vscode # generate VSCode configuration for development
```

## Usage on PSC3M5_EVK

The PSC3M5_EVK board is a development board from Infineon with TrustZone-M. It
is currently the only board supported by this project.
For trying it out follow these steps.

1. Provision the device with the protection context configuration:
  ```bash
  cd boards/psc3m5_evk/edgeprotecttools
  edgeprotecttools -t psoc_c3 init
  edgeprotecttools -t psoc_c3 provision-device -p ns_policy/policy_oem_provisioning.json
  ```

2. Build and flash the tock board image:
  ```bash
  cd boards/psc3m5_evk/secure
  inv flash --nspe=tock
  ```

3. Run tests against a flashed device using the client tester go application:
  ```bash
  cd tools/test-client
  go run . --token-src tty
  ```

## Disclaimer

This is a student research project sponsored by Infineon Technologies AG, and is
not intended for production use.

The code is provided "as is" without any warranties. This is not an officially
supported Infineon product.
