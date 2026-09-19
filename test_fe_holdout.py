#!/usr/bin/env python3

from pathlib import Path
import json
import hashlib
import hmac

CAPTURE_DIR = Path("puf_results")
HELPER_FILE = Path("enrollment/puf_helper_region1_coldpower.json")

HOLDOUT = range(21, 31)

HKDF_INFO = b"L-POPI/ESP32/SRAM-PUF/v1"
COMMIT_INFO = b"L-POPI/ESP32/SRAM-PUF/key-commit/v1"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    output = b""
    previous = b""
    counter = 1

    while len(output) < length:
        previous = hmac.new(
            prk,
            previous + info + bytes([counter]),
            hashlib.sha256
        ).digest()

        output += previous
        counter += 1

    return output[:length]


def bytes_to_bits(value: bytes):
    return [
        int(bit)
        for byte in value
        for bit in f"{byte:08b}"
    ]


def bits_to_bytes(bits):
    if len(bits) % 8:
        raise ValueError("Bit length must be multiple of 8")

    return bytes(
        sum(
            bit << (7 - offset)
            for offset, bit in enumerate(bits[start:start + 8])
        )
        for start in range(0, len(bits), 8)
    )


def read_region(path: Path, region: int, bytes_per_region: int):
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    prefix = f"REGION,{region},"

    for i, line in enumerate(lines):
        if line.startswith(prefix):
            fields = line.split(",")

            if len(fields) < 4:
                raise ValueError(f"{path}: malformed metadata")

            declared_size = int(fields[3])

            if declared_size != bytes_per_region:
                raise ValueError(
                    f"{path}: expected {bytes_per_region} bytes, "
                    f"got {declared_size}"
                )

            if i + 1 >= len(lines):
                raise ValueError(f"{path}: missing hexadecimal data")

            raw = bytes.fromhex(lines[i + 1])

            if len(raw) != bytes_per_region:
                raise ValueError(
                    f"{path}: invalid data length {len(raw)}"
                )

            return bytes_to_bits(raw)

    raise ValueError(f"{path}: Region {region} not found")


def reproduce(sample, indexes, helper, group_size):
    noisy_codeword = [
        sample[index] ^ mask
        for index, mask in zip(indexes, helper)
    ]

    decoded = []

    group_errors = []

    for start in range(0, len(noisy_codeword), group_size):
        group = noisy_codeword[start:start + group_size]

        ones = sum(group)

        decoded_bit = int(
            ones > group_size // 2
        )

        decoded.append(decoded_bit)

        # Number of disagreements with decoded repetition value.
        errors = sum(
            bit != decoded_bit
            for bit in group
        )

        group_errors.append(errors)

    return (
        bits_to_bytes(decoded),
        group_errors
    )


with HELPER_FILE.open("r", encoding="utf-8") as f:
    enrollment = json.load(f)

region = enrollment["region"]
region_bytes = enrollment["region_bytes"]
group_size = enrollment["group_size"]
key_bytes = enrollment["key_bytes"]

indexes = enrollment["bit_indexes"]

helper = bytes_to_bits(
    bytes.fromhex(enrollment["helper_hex"])
)

# Packed helper should correspond exactly to selected indexes.
helper = helper[:len(indexes)]

salt = bytes.fromhex(
    enrollment["hkdf_salt_hex"]
)

expected_commitment = bytes.fromhex(
    enrollment["key_commitment_hex"]
)

print("=" * 84)
print("L-PoPI SRAM-PUF FUZZY EXTRACTOR -- HELD-OUT VALIDATION")
print("=" * 84)
print(f"Region              : {region}")
print(f"Selected SRAM bits  : {len(indexes)}")
print(f"Group size          : {group_size}")
print(f"Secret bits         : {len(indexes) // group_size}")
print(f"Held-out captures   : 021-030")
print("=" * 84)

passes = 0
failures = 0

all_max_group_errors = []
all_selected_raw_errors = []

for capture_number in HOLDOUT:

    path = (
        CAPTURE_DIR
        / f"capture_{capture_number:03d}.txt"
    )

    sample = read_region(
        path,
        region,
        region_bytes
    )

    secret, group_errors = reproduce(
        sample,
        indexes,
        helper,
        group_size
    )

    key = hkdf_sha256(
        secret,
        salt,
        HKDF_INFO,
        key_bytes
    )

    commitment = hashlib.sha256(
        COMMIT_INFO + key
    ).digest()

    passed = hmac.compare_digest(
        commitment,
        expected_commitment
    )

    max_group_errors = max(group_errors)

    # A repetition group fails if > floor(group_size/2)
    failing_groups = sum(
        errors > group_size // 2
        for errors in group_errors
    )

    # This is not BER relative to enrollment reference;
    # it reports total minority errors inside decoded groups.
    total_group_errors = sum(group_errors)

    all_max_group_errors.append(max_group_errors)
    all_selected_raw_errors.append(total_group_errors)

    if passed:
        passes += 1
        status = "PASS"
    else:
        failures += 1
        status = "FAIL"

    print(
        f"Capture {capture_number:03d}: "
        f"{status} | "
        f"max group errors={max_group_errors}/{group_size} | "
        f"failing groups={failing_groups} | "
        f"group minority errors={total_group_errors}"
    )


print("\n" + "=" * 84)
print("FINAL HELD-OUT RESULT")
print("=" * 84)

total = passes + failures

print(f"PASS                 : {passes}/{total}")
print(f"FAIL                 : {failures}/{total}")
print(f"Reconstruction rate  : {100.0 * passes / total:.2f}%")
print(
    f"Worst observed group : "
    f"{max(all_max_group_errors)}/{group_size}"
)

print("=" * 84)

if failures == 0:
    print(
        "RESULT: all unseen cold-power captures reconstructed "
        "a key matching the enrollment commitment."
    )
else:
    print(
        "RESULT: at least one unseen cold-power capture failed "
        "key reconstruction."
    )
