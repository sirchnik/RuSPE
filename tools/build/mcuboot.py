# SPDX-FileCopyrightText: Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

import sys
import hashlib
from pathlib import Path
from intelhex import IntelHex
from cryptography.hazmat.primitives import serialization


def load_key(key_path: Path):
    if not key_path.exists():
        print(f"Error: Signing key not found at {key_path}", file=sys.stderr)
        print(
            "Please generate it using the following OpenSSL command:", file=sys.stderr
        )
        print(
            f"openssl ecparam -name prime256v1 -genkey -noout -out {key_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def calc_signer_id(private_key) -> bytes:
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    hasher = hashlib.sha256()
    hasher.update(pub_bytes)
    return hasher.digest()


def patch_mcuboot_sig(
    hex_path: Path,
    mcuboot_addr: int,
    payload_start: int,
    payload_end: int,
    signing_key_path: Path | None = None,
):
    print(f"Patching MCUboot signature in {hex_path}")
    ih = IntelHex(str(hex_path))

    max_addr = ih.maxaddr()
    if max_addr is None:
        print("Hex file is empty.")
        return

    rom_max = min(max_addr, payload_end)
    if rom_max < payload_start:
        print(f"No payload found between {hex(payload_start)} and {hex(payload_end)}.")
        return

    # Extract the payload bytes
    payload_data = ih.tobinarray(start=payload_start, end=rom_max)

    hasher = hashlib.sha256()
    hasher.update(payload_data)
    measurement = hasher.digest()

    if signing_key_path is None:
        print("Warning: Using default signing key")
        signing_key_path = Path(__file__).parent / "default_signing_key.pem"

    private_key = load_key(signing_key_path)
    signer_id = calc_signer_id(private_key)

    # TLV constants
    tlv_magic = 0x2016
    measure_type = (0x1 << 12) | (0x00 << 6) | 0x08
    measure_len = len(measurement)
    signer_type = (0x1 << 12) | (0x00 << 6) | 0x01
    signer_len = len(signer_id)
    tlv_tot_len = 4 + 4 + measure_len + 4 + signer_len

    import struct

    tlv_data = struct.pack("<HH", tlv_magic, tlv_tot_len)
    tlv_data += struct.pack("<HH", measure_type, measure_len)
    tlv_data += measurement
    tlv_data += struct.pack("<HH", signer_type, signer_len)
    tlv_data += signer_id

    # Patch the TLV payload at the reserved address
    for i, b in enumerate(tlv_data):
        ih[mcuboot_addr + i] = b

    ih.write_hex_file(str(hex_path))
    print(f"Successfully patched {hex_path.name} with measurement: {measurement.hex()}")
    print(f"Using Signer ID: {signer_id.hex()}")
