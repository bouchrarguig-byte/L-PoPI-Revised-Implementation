import json
import copy
import hashlib
import hmac
from pathlib import Path

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


ROOT = Path(".")
HELPER_PATH = ROOT / "j2_adversarial" / "puf_helper_original.json"
CAPTURE_PATH = ROOT / "puf_results" / "capture_021.txt"

HKDF_INFO = b"L-POPI/ESP32/SRAM-PUF/v1"
COMMIT_INFO = b"L-POPI/ESP32/SRAM-PUF/key-commit/v1"


def bytes_to_bits(data):
    bits = []
    for byte in data:
        for bit_position in range(7, -1, -1):
            bits.append((byte >> bit_position) & 1)
    return bits


def bits_to_bytes(bits):
    out = bytearray()

    for start in range(0, len(bits), 8):
        value = 0
        chunk = bits[start:start + 8]

        for bit in chunk:
            value = (value << 1) | bit

        if len(chunk) < 8:
            value <<= (8 - len(chunk))

        out.append(value)

    return bytes(out)


def hex_to_bits(hex_string):
    return bytes_to_bits(bytes.fromhex(hex_string))


def parse_capture(path, region=1, region_bytes=256):
    lines = [line.strip() for line in path.read_text().splitlines()]

    prefix = f"REGION,{region},"

    for i, line in enumerate(lines):
        if line.startswith(prefix):
            parts = line.split(",")

            if len(parts) < 4:
                raise ValueError("Malformed REGION line")

            size = int(parts[3])

            if size != region_bytes:
                raise ValueError(
                    f"Unexpected region size {size}; expected {region_bytes}"
                )

            raw = bytes.fromhex(lines[i + 1])

            if len(raw) != region_bytes:
                raise ValueError(
                    f"Unexpected raw length {len(raw)}; expected {region_bytes}"
                )

            return bytes_to_bits(raw)

    raise ValueError(f"Region {region} not found in {path}")


def reproduce(sample_bits, helper):
    indexes = helper["bit_indexes"]
    helper_bits = hex_to_bits(helper["helper_hex"])
    group_size = helper["group_size"]

    if len(indexes) != helper["selected_bits"]:
        raise ValueError("bit_indexes length mismatch")

    if len(helper_bits) < helper["selected_bits"]:
        raise ValueError("helper bit length too short")

    helper_bits = helper_bits[:helper["selected_bits"]]

    noisy_codeword = [
        sample_bits[index] ^ mask
        for index, mask in zip(indexes, helper_bits)
    ]

    decoded = []

    for start in range(0, len(noisy_codeword), group_size):
        group = noisy_codeword[start:start + group_size]

        decoded_bit = int(
            sum(group) > group_size // 2
        )

        decoded.append(decoded_bit)

    secret = bits_to_bytes(decoded)

    salt = bytes.fromhex(helper["hkdf_salt_hex"])

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=helper["key_bytes"],
        salt=salt,
        info=HKDF_INFO,
    )

    key = hkdf.derive(secret)

    commitment = hashlib.sha256(
        COMMIT_INFO + key
    ).hexdigest()

    expected = helper["key_commitment_hex"]

    return hmac.compare_digest(
        commitment,
        expected
    )


def flip_helper_positions(helper, positions):
    tampered = copy.deepcopy(helper)

    helper_bytes = bytearray.fromhex(
        tampered["helper_hex"]
    )

    for bit_pos in positions:
        byte_idx = bit_pos // 8
        bit_idx = 7 - (bit_pos % 8)

        helper_bytes[byte_idx] ^= (
            1 << bit_idx
        )

    tampered["helper_hex"] = helper_bytes.hex()

    return tampered


def tamper_hex_first_bit(helper, field):
    tampered = copy.deepcopy(helper)

    value = bytearray.fromhex(
        tampered[field]
    )

    value[0] ^= 0x80

    tampered[field] = value.hex()

    return tampered


with open(HELPER_PATH, "r") as f:
    original = json.load(f)


sample = parse_capture(
    CAPTURE_PATH,
    region=original["region"],
    region_bytes=original["region_bytes"],
)


tests = []


tests.append((
    "T0 original helper",
    original
))


tests.append((
    "T1 flip 1 helper bit in group 0",
    flip_helper_positions(
        original,
        [0]
    )
))


tests.append((
    "T2 flip 6 helper bits in group 0",
    flip_helper_positions(
        original,
        list(range(0, 6))
    )
))


tests.append((
    "T3 flip 7 helper bits in group 0",
    flip_helper_positions(
        original,
        list(range(0, 7))
    )
))


tests.append((
    "T4 tamper HKDF salt",
    tamper_hex_first_bit(
        original,
        "hkdf_salt_hex"
    )
))


tests.append((
    "T5 tamper key commitment",
    tamper_hex_first_bit(
        original,
        "key_commitment_hex"
    )
))


print("=" * 76)
print("L-PoPI J2 -- HELPER-DATA TAMPERING TEST")
print("=" * 76)

print(f"Capture      : {CAPTURE_PATH}")
print(f"Region       : {original['region']}")
print(f"Selected bits: {original['selected_bits']}")
print(f"Group size   : {original['group_size']}")
print()


for name, helper in tests:
    try:
        ok = reproduce(
            sample,
            helper
        )

        print(
            f"{name:44s} -> "
            f"{'PASS' if ok else 'FAIL'}"
        )

    except Exception as e:
        print(
            f"{name:44s} -> "
            f"ERROR: {e}"
        )


print()
print("Interpretation:")
print(
    "PASS = reconstructed key matches "
    "stored enrollment commitment"
)
print(
    "FAIL = reconstructed key does not "
    "match stored enrollment commitment"
)
