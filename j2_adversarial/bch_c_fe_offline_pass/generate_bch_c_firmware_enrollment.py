import json
import random
import hashlib
import hmac
from pathlib import Path

import bchlib

ROOT = Path(".")
CAPTURE_DIR = ROOT / "puf_results"

REP_HELPER = ROOT / "j2_adversarial/puf_helper_original.json"
FROZEN_INDEXES = ROOT / "j2_adversarial/bch_c_selected_indices.json"

OUT_JSON = ROOT / "j2_adversarial/bch_c_firmware_enrollment.json"
OUT_HEADER = ROOT / "main/puf_enrollment_bch_c_region1.h"

ENROLLMENT = range(1, 21)

RNG_SEED = 20260913

M = 9
T = 16
SECRET_BYTES = 16
KEY_BYTES = 32
PACKET_BYTES = 34
PACKET_BITS = 272

HKDF_INFO = b"L-POPI/ESP32/SRAM-PUF/v1"
COMMIT_INFO = b"L-POPI/ESP32/SRAM-PUF/key-commit/v1"


def parse_capture(path, region, region_bytes):
    text = path.read_text()

    prefix = f"PUF_REGION,{region},"
    hex_data = None

    for line in text.splitlines():
        line = line.strip()

        if line.startswith(prefix):
            parts = line.split(",")

            # Existing capture format normally has:
            # PUF_REGION,<id>,<hex>
            for item in reversed(parts):
                item = item.strip()

                if len(item) == region_bytes * 2:
                    try:
                        bytes.fromhex(item)
                        hex_data = item
                        break
                    except ValueError:
                        pass

            if hex_data is not None:
                break

    if hex_data is None:
        # Compatibility with captures containing a raw-region
        # hex field under a slightly different prefix.
        for line in text.splitlines():
            fields = line.strip().split(",")

            for item in reversed(fields):
                item = item.strip()

                if len(item) == region_bytes * 2:
                    try:
                        bytes.fromhex(item)
                    except ValueError:
                        continue

                    hex_data = item
                    break

            if hex_data is not None:
                break

    if hex_data is None:
        raise ValueError(f"Could not parse {path}")

    raw = bytes.fromhex(hex_data)

    if len(raw) != region_bytes:
        raise ValueError(
            f"{path}: expected {region_bytes} bytes, got {len(raw)}"
        )

    return raw


def bytes_to_bits(data):
    return [
        (byte >> shift) & 1
        for byte in data
        for shift in range(7, -1, -1)
    ]


def bit_at(data, index):
    return (data[index // 8] >> (7 - index % 8)) & 1


def majority_reference(captures):
    nbits = len(captures[0]) * 8
    out = []

    for index in range(nbits):
        ones = sum(bit_at(c, index) for c in captures)
        out.append(1 if ones * 2 >= len(captures) else 0)

    return out


def pack_bits(bits):
    if len(bits) % 8:
        raise ValueError("Bit count must be byte aligned")

    out = bytearray(len(bits) // 8)

    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (7 - i % 8)

    return bytes(out)


def hkdf_sha256(ikm, salt, info, length):
    # RFC 5869 HKDF-SHA-256.
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    okm = b""
    previous = b""
    counter = 1

    while len(okm) < length:
        previous = hmac.new(
            prk,
            previous + info + bytes([counter]),
            hashlib.sha256
        ).digest()

        okm += previous
        counter += 1

    return okm[:length]


def c_u16_array(name, values):
    lines = [
        f"static const uint16_t {name}[{len(values)}] = {{"
    ]

    for i in range(0, len(values), 12):
        chunk = values[i:i+12]
        lines.append(
            "    " + ", ".join(str(v) for v in chunk) + ","
        )

    lines.append("};")
    return "\n".join(lines)


def c_u8_array(name, values):
    lines = [
        f"static const uint8_t {name}[{len(values)}] = {{"
    ]

    for i in range(0, len(values), 12):
        chunk = values[i:i+12]
        lines.append(
            "    " + ", ".join(f"0x{x:02x}" for x in chunk) + ","
        )

    lines.append("};")
    return "\n".join(lines)


rep = json.loads(REP_HELPER.read_text())
frozen = json.loads(FROZEN_INDEXES.read_text())

region = rep["region"]
region_bytes = rep["region_bytes"]

stable_pool = rep["bit_indexes"]
indexes = frozen["bit_indexes"]

assert len(stable_pool) == 1664
assert indexes == stable_pool[:PACKET_BITS]
assert len(indexes) == PACKET_BITS
assert len(set(indexes)) == PACKET_BITS

captures = [
    parse_capture(
        CAPTURE_DIR / f"capture_{n:03d}.txt",
        region,
        region_bytes
    )
    for n in ENROLLMENT
]

reference = majority_reference(captures)

# EXACT deterministic benchmark secret used by test_bch_holdout.py.
rng = random.Random(RNG_SEED)

secret = bytes(
    rng.randrange(0, 256)
    for _ in range(SECRET_BYTES)
)

bch = bchlib.BCH(T, m=M)

assert bch.m == 9
assert bch.t == 16
assert bch.n == 511
assert bch.ecc_bits == 144
assert bch.ecc_bytes == 18
assert bch.prim_poly == 0x211

data = bytearray(secret)
ecc = bytearray(bch.encode(data))
codeword = bytes(data + ecc)

assert len(codeword) == PACKET_BYTES

codeword_bits = bytes_to_bits(codeword)

enrolled_puf_bits = [
    reference[index]
    for index in indexes
]

helper_bits = [
    p ^ c
    for p, c in zip(enrolled_puf_bits, codeword_bits)
]

helper_bytes = pack_bits(helper_bits)

assert len(helper_bytes) == PACKET_BYTES

# Preserve the exact salt already frozen by the repetition enrollment.
salt = bytes.fromhex(rep["hkdf_salt_hex"])

key = hkdf_sha256(
    secret,
    salt,
    HKDF_INFO,
    KEY_BYTES
)

commitment = hashlib.sha256(
    COMMIT_INFO + key
).digest()

index_canonical = ",".join(map(str, indexes)).encode()
index_sha = hashlib.sha256(index_canonical).hexdigest()

obj = {
    "version": "lpofi-bch-c-firmware-integration-v1",
    "purpose": (
        "Reproducible BCH-C firmware integration using the "
        "same deterministic benchmark secret as the held-out experiment; "
        "not a production secret-generation method."
    ),
    "region": region,
    "region_bytes": region_bytes,
    "enrollment": "captures 001-020",
    "selection_rule": (
        "first 272 indexes from frozen 1664-bit "
        "enrollment-only stable-cell pool"
    ),
    "bit_order": "MSB-first within each SRAM byte",
    "m": M,
    "t": T,
    "n": bch.n,
    "prim_poly": bch.prim_poly,
    "ecc_bits": bch.ecc_bits,
    "ecc_bytes": bch.ecc_bytes,
    "secret_bytes": SECRET_BYTES,
    "packet_bytes": PACKET_BYTES,
    "selected_bits": PACKET_BITS,
    "benchmark_rng_seed": RNG_SEED,
    "bit_indexes": indexes,
    "bit_indexes_canonical_sha256": index_sha,
    "benchmark_secret_hex": secret.hex(),
    "ecc_hex": bytes(ecc).hex(),
    "codeword_hex": codeword.hex(),
    "helper_hex": helper_bytes.hex(),
    "hkdf_salt_hex": salt.hex(),
    "hkdf_info": HKDF_INFO.decode(),
    "commit_info": COMMIT_INFO.decode(),
    "derived_key_hex_validation_only": key.hex(),
    "key_commitment_hex": commitment.hex(),
}

OUT_JSON.write_text(
    json.dumps(obj, indent=2) + "\n"
)

header = f"""/*
 * Generated BCH-C enrollment data.
 *
 * Enrollment captures: 001-020
 * Region: {region}
 *
 * BCH-C: m=9, t=16, n=511
 * Shortened packet: 34 bytes / 272 bits
 *
 * Selection:
 * first 272 indexes from the frozen enrollment-only
 * 1664-bit stable-cell pool.
 *
 * IMPORTANT:
 * The secret used for this integration artifact is the
 * deterministic J2 benchmark secret (seed {RNG_SEED}).
 * This is for reproducible experimental validation and
 * is NOT a production secret-generation procedure.
 */

#pragma once

#include <stdint.h>

#define LPOFI_BCH_PUF_REGION {region}
#define LPOFI_BCH_PUF_REGION_BYTES {region_bytes}

#define LPOFI_BCH_PUF_SELECTED_BITS {PACKET_BITS}
#define LPOFI_BCH_PUF_SECRET_BYTES {SECRET_BYTES}
#define LPOFI_BCH_PUF_PACKET_BYTES {PACKET_BYTES}
#define LPOFI_BCH_PUF_KEY_BYTES {KEY_BYTES}

{c_u16_array("lpofi_bch_puf_bit_indexes", indexes)}

{c_u8_array("lpofi_bch_puf_helper_bytes", helper_bytes)}

{c_u8_array("lpofi_bch_puf_hkdf_salt", salt)}

{c_u8_array("lpofi_bch_puf_key_commitment", commitment)}
"""

OUT_HEADER.write_text(header)

print("BCH-C firmware enrollment generated")
print("region            :", region)
print("region bytes      :", region_bytes)
print("selected bits     :", len(indexes))
print("index range       :", min(indexes), "..", max(indexes))
print("index SHA256      :", index_sha)
print("secret            :", secret.hex())
print("ECC               :", bytes(ecc).hex())
print("codeword          :", codeword.hex())
print("helper            :", helper_bytes.hex())
print("salt              :", salt.hex())
print("derived key       :", key.hex())
print("commitment        :", commitment.hex())
print("JSON              :", OUT_JSON)
print("header            :", OUT_HEADER)
print("BCH_C_FIRMWARE_ENROLLMENT_GENERATED")
