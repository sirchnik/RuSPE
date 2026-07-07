# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

from pathlib import Path
from tools.generate.generate_service import ServiceSpec

REPO_ROOT = Path(__file__).resolve().parents[3]

ATTEST_SPEC = ServiceSpec(
    name="attest",
    package_name="psc3m5_evk_attest_srv",
    mode="generated",
    service_dir=REPO_ROOT / "boards" / "psc3m5_evk" / "services" / "attest_srv",
    generated_import="use ruspe_psc3::services::attest::{InitialAttestation, Psc3AttestPlatform};",
    generated_service_type="InitialAttestation<spe::spm_api::IpcPsaClient>",
    generated_service_ctor="InitialAttestation::new(Psc3AttestPlatform::new(Some(0x32007F00)))",
)

CRYPTO_SPEC = ServiceSpec(
    name="crypto",
    package_name="psc3m5_evk_crypto_srv",
    mode="generated",
    service_dir=REPO_ROOT / "boards" / "psc3m5_evk" / "services" / "crypto_srv",
    generated_import="use ruspe_psc3::services::crypto::Crypto;",
    generated_service_type="Crypto",
    generated_service_ctor="Crypto::new([\n    0xc3, 0xfe, 0xe8, 0x4c, 0x73, 0x49, 0xd8, 0xe8, 0x44, 0x3d, 0xe4, 0xae, 0x65, 0xf7, 0xea, 0x3b,\n    0xb8, 0x09, 0x3b, 0xe9, 0xb1, 0x5b, 0xc4, 0xbd, 0x4a, 0x54, 0x95, 0x3c, 0xd3, 0x31, 0xce, 0x1b,\n])",
)

CATALOG = {
    "attest": ATTEST_SPEC,
    "crypto": CRYPTO_SPEC,
}
