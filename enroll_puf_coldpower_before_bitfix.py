#!/usr/bin/env python3
"""Enroll an ESP32 SRAM-PUF from early-boot capture files.

This tool implements a practical *code-offset fuzzy extractor* for the
characterisation data collected by ``collect_reset_puf.py``:

  helper = selected_reference_bits XOR repetition_encode(random_secret)
  key    = HKDF-SHA256(random_secret, enrollment_salt, context)

The helper data and key commitment are safe to deploy with the firmware; the
random secret and derived key are deliberately never written to disk.  The
generated C header is device-specific and must be regenerated for each ESP32.

This is a repetition-code baseline, not a BCH implementation.  It makes the
enrollment/reproduction boundary measurable before replacing the code with a
reviewed BCH implementation for a production system.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import secrets
from pathlib import Path

SCHEME = "lpofi-code-offset-repetition-v1"
HKDF_INFO = b"L-POPI/ESP32/SRAM-PUF/v1"
COMMIT_INFO = b"L-POPI/ESP32/SRAM-PUF/key-commit/v1"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 using only Python's standard library."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def read_region(path, region, bytes_per_region):
    """
    Read one region from cold-power capture format:

        CAPTURE,1
        TIMESTAMP,...
        REGION,1,0x3FFF2000,256
        HEXDATA
    """
    lines = [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    prefix = f"REGION,{region},"

    index = None
    metadata = None

    for i, line in enumerate(lines):
        if line.startswith(prefix):
            index = i
            metadata = line.split(",")
            break

    if index is None:
        raise ValueError(f"{path}: missing Region {region}")

    if len(metadata) < 4:
        raise ValueError(
            f"{path}: malformed region metadata: {lines[index]}"
        )

    declared_region = int(metadata[1])
    declared_address = metadata[2]
    declared_size = int(metadata[3])

    if declared_region != region:
        raise ValueError(
            f"{path}: expected region {region}, got {declared_region}"
        )

    if declared_size != bytes_per_region:
        raise ValueError(
            f"{path}: expected {bytes_per_region} bytes, got {declared_size}"
        )

    if index + 1 >= len(lines):
        raise ValueError(f"{path}: missing hexadecimal data")

    value = lines[index + 1].strip()

    expected_hex_len = bytes_per_region * 2

    if len(value) != expected_hex_len:
        raise ValueError(
            f"{path}: expected {expected_hex_len} hex chars, "
            f"got {len(value)}"
        )

    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            f"{path}: invalid hexadecimal region data"
        ) from exc

    if len(raw) != bytes_per_region:
        raise ValueError(
            f"{path}: expected {bytes_per_region} bytes, "
            f"got {len(raw)}"
        )

    return raw

def load_captures(capture_dir: Path, region: int, bytes_per_region: int) -> list[list[int]]:
    files = sorted(capture_dir.glob("capture_*.txt"))
    if len(files) < 2:
        raise ValueError("At least two capture_*.txt files are required")
    return [read_region(path, region, bytes_per_region) for path in files]


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("Bit length must be a multiple of 8")
    return bytes(sum(bit << (7 - offset) for offset, bit in enumerate(bits[start:start + 8]))
                 for start in range(0, len(bits), 8))


def bytes_to_bits(value: bytes) -> list[int]:
    return [int(bit) for byte in value for bit in f"{byte:08b}"]


def repeat_encode(secret: bytes, group_size: int) -> list[int]:
    return [bit for bit in bytes_to_bits(secret) for _ in range(group_size)]


def reproduce(sample: list[int], indexes: list[int], helper: list[int], group_size: int) -> bytes:
    noisy_codeword = [sample[index] ^ mask for index, mask in zip(indexes, helper)]
    decoded = [int(sum(noisy_codeword[start:start + group_size]) > group_size // 2)
               for start in range(0, len(noisy_codeword), group_size)]
    return bits_to_bytes(decoded)


def c_array(name: str, values: list[int], c_type: str, columns: int = 12) -> str:
    rows = []
    for start in range(0, len(values), columns):
        rows.append("    " + ", ".join(str(v) for v in values[start:start + columns]))
    return f"static const {c_type} {name}[{len(values)}] = {{\n" + ",\n".join(rows) + "\n};\n"


def write_header(path: Path, enrollment: dict) -> None:
    indexes = enrollment["bit_indexes"]
    # The JSON stores helper bits packed into bytes. Firmware indexes one
    # helper *bit* per selected PUF position, so expand them before emitting C.
    helper = bytes_to_bits(bytes.fromhex(enrollment["helper_hex"]))
    if len(helper) != len(indexes):
        raise ValueError("Packed helper data length does not match selected bits")
    salt = list(bytes.fromhex(enrollment["hkdf_salt_hex"]))
    commitment = list(bytes.fromhex(enrollment["key_commitment_hex"]))
    body = """/* Generated by enroll_puf.py. Public, device-specific helper data. */
#pragma once
#include <stdint.h>

#define LPOFI_PUF_REGION_ID %(region)d
#define LPOFI_PUF_REGION_BYTES %(region_bytes)d
#define LPOFI_PUF_GROUP_SIZE %(group_size)d
#define LPOFI_PUF_SECRET_BYTES %(secret_bytes)d
#define LPOFI_PUF_SELECTED_BITS %(selected_bits)d

""" % {
        "region": enrollment["region"], "region_bytes": enrollment["region_bytes"],
        "group_size": enrollment["group_size"], "secret_bytes": enrollment["secret_bytes"],
        "selected_bits": len(indexes),
    }
    body += c_array("lpofi_puf_bit_indexes", indexes, "uint16_t")
    body += c_array("lpofi_puf_helper_bits", helper, "uint8_t")
    body += c_array("lpofi_puf_hkdf_salt", salt, "uint8_t")
    body += c_array("lpofi_puf_key_commitment", commitment, "uint8_t")
    path.write_text(body, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Enroll a code-offset fuzzy extractor from ESP32 SRAM captures")
    parser.add_argument("--capture-dir", type=Path, default=Path("puf_results"))
    parser.add_argument("--region", type=int, default=1)
    parser.add_argument("--region-bytes", type=int, default=256)
    parser.add_argument("--reliability", type=float, default=0.95)
    parser.add_argument("--secret-bytes", type=int, default=16, help="Random secret size before HKDF")
    parser.add_argument("--key-bytes", type=int, default=32)
    parser.add_argument("--group-size", type=int, default=13, help="Odd repetition-code group size")
    parser.add_argument("--output", type=Path, default=Path("enrollment/puf_helper.json"))
    parser.add_argument("--header", type=Path, default=Path("main/puf_enrollment_generated.h"))
    args = parser.parse_args()

    if not 0.5 < args.reliability <= 1:
        parser.error("--reliability must be in (0.5, 1]")
    if args.group_size < 3 or args.group_size % 2 == 0:
        parser.error("--group-size must be odd and at least 3")

    captures = load_captures(args.capture_dir, args.region, args.region_bytes)
    bit_count = args.region_bytes * 8
    ones = [sum(capture[index] for capture in captures) for index in range(bit_count)]
    reference = [int(count * 2 >= len(captures)) for count in ones]
    reliability = [max(count / len(captures), 1 - count / len(captures)) for count in ones]
    need_bits = args.secret_bytes * 8 * args.group_size
    candidates = sorted((index for index, value in enumerate(reliability) if value >= args.reliability),
                        key=lambda index: reliability[index], reverse=True)
    if len(candidates) < need_bits:
        parser.error(f"Only {len(candidates)} reliable bits; {need_bits} required. Lower --reliability or reduce key/group size.")
    indexes = sorted(candidates[:need_bits])
    secret = secrets.token_bytes(args.secret_bytes)
    codeword = repeat_encode(secret, args.group_size)
    helper = [reference[index] ^ code_bit for index, code_bit in zip(indexes, codeword)]
    salt = secrets.token_bytes(32)
    key = hkdf_sha256(secret, salt, HKDF_INFO, args.key_bytes)
    commitment = hashlib.sha256(COMMIT_INFO + key).digest()

    failures = []
    max_group_errors = 0
    for number, sample in enumerate(captures, start=1):
        candidate_secret = reproduce(sample, indexes, helper, args.group_size)
        if candidate_secret != secret:
            failures.append(number)
        group_errors = [sum(sample[index] ^ reference[index]
                            for index in indexes[start:start + args.group_size])
                        for start in range(0, len(indexes), args.group_size)]
        max_group_errors = max(max_group_errors, max(group_errors))

    enrollment = {
        "version": 1, "scheme": SCHEME, "region": args.region, "region_bytes": args.region_bytes,
        "capture_count": int(len(captures)), "reliability_threshold": args.reliability,
        "group_size": args.group_size, "secret_bytes": args.secret_bytes, "key_bytes": args.key_bytes,
        "selected_bits": need_bits, "bit_indexes": indexes,
        "helper_hex": bits_to_bytes(helper).hex(), "hkdf_salt_hex": salt.hex(),
        "key_commitment_hex": commitment.hex(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(enrollment, indent=2) + "\n", encoding="utf-8")
    args.header.parent.mkdir(parents=True, exist_ok=True)
    write_header(args.header, enrollment)

    print(f"Enrolled region {args.region} from {len(captures)} captures")
    print(f"Selected bits: {need_bits}; threshold: {args.reliability:.1%}; group size: {args.group_size}")
    print(f"Max raw errors in one repetition group: {max_group_errors}/{args.group_size}")
    print(f"Reproduction: {'PASS' if not failures else 'FAIL on captures ' + str(failures)}")
    print(f"Public helper: {args.output}")
    print(f"Firmware header: {args.header}")
    if failures:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
