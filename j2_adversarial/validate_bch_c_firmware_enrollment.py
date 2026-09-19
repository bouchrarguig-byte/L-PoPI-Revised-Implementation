import json
import hashlib
import hmac
from pathlib import Path

import bchlib

ROOT = Path(".")
CAPTURE_DIR = ROOT / "puf_results"

FW_PATH = ROOT / "j2_adversarial/bch_c_firmware_enrollment.json"

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


def bit_at(data, index):
    return (data[index // 8] >> (7 - index % 8)) & 1


def bytes_to_bits(data):
    return [
        (byte >> shift) & 1
        for byte in data
        for shift in range(7, -1, -1)
    ]


def pack_bits(bits):
    assert len(bits) % 8 == 0

    out = bytearray(len(bits) // 8)

    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (7 - i % 8)

    return bytes(out)


def hkdf_sha256(ikm, salt, info, length):
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


fw = json.loads(FW_PATH.read_text())

assert fw["m"] == 9
assert fw["t"] == 16
assert fw["n"] == 511
assert fw["ecc_bits"] == 144
assert fw["ecc_bytes"] == 18
assert fw["selected_bits"] == 272
assert fw["packet_bytes"] == 34

region = fw["region"]
region_bytes = fw["region_bytes"]

indexes = fw["bit_indexes"]
helper = bytes.fromhex(fw["helper_hex"])
helper_bits = bytes_to_bits(helper)

salt = bytes.fromhex(fw["hkdf_salt_hex"])
expected_commitment = bytes.fromhex(
    fw["key_commitment_hex"]
)

expected_secret = bytes.fromhex(
    fw["benchmark_secret_hex"]
)

expected_codeword = bytes.fromhex(
    fw["codeword_hex"]
)

assert len(indexes) == 272
assert len(helper_bits) == 272
assert len(expected_codeword) == 34

bch = bchlib.BCH(16, m=9)

successes = 0

print("=" * 78)
print("L-PoPI BCH-C FIRMWARE ENROLLMENT -- HELD-OUT VALIDATION")
print("=" * 78)
print("source             :", FW_PATH)
print("held-out captures  : 021-030")
print("selected bits      :", len(indexes))
print("packet bytes       :", len(helper))
print()

for capture_number in range(21, 31):

    path = CAPTURE_DIR / f"capture_{capture_number:03d}.txt"

    raw = parse_capture(
        path,
        region,
        region_bytes
    )

    noisy_puf_bits = [
        bit_at(raw, index)
        for index in indexes
    ]

    recovered_bits = [
        p ^ h
        for p, h in zip(
            noisy_puf_bits,
            helper_bits
        )
    ]

    recovered_packet = bytearray(
        pack_bits(recovered_bits)
    )

    raw_errors = sum(
        a != b
        for a, b in zip(
            recovered_bits,
            bytes_to_bits(expected_codeword)
        )
    )

    data = bytearray(
        recovered_packet[:16]
    )

    ecc = bytearray(
        recovered_packet[16:]
    )

    decoder_return = bch.decode(
        data,
        recv_ecc=ecc
    )

    corrected = False

    if decoder_return >= 0:
        bch.correct(
            data,
            ecc
        )

        corrected = True

    secret_ok = (
        corrected and
        bytes(data) == expected_secret
    )

    if corrected:
        key = hkdf_sha256(
            bytes(data),
            salt,
            HKDF_INFO,
            32
        )

        commitment = hashlib.sha256(
            COMMIT_INFO + key
        ).digest()

        commitment_ok = hmac.compare_digest(
            commitment,
            expected_commitment
        )
    else:
        commitment_ok = False

    passed = (
        decoder_return >= 0
        and secret_ok
        and commitment_ok
    )

    if passed:
        successes += 1

    print(
        f"Capture {capture_number:03d}: "
        f"{'PASS' if passed else 'FAIL'} | "
        f"raw_errors={raw_errors:2d} | "
        f"decoder={decoder_return} | "
        f"secret={'PASS' if secret_ok else 'FAIL'} | "
        f"commitment={'PASS' if commitment_ok else 'FAIL'}"
    )


print()
print(
    f"BCH_C_HEADER_HOLDOUT,{successes}/10,"
    f"{'PASS' if successes == 10 else 'FAIL'}"
)

if successes != 10:
    raise SystemExit(1)

print("BCH_C_FIRMWARE_ENROLLMENT_OFFLINE_OK")
