import json
import math
import random
import csv
import hashlib
import hmac
from pathlib import Path


ROOT = Path(".")
HELPER_PATH = ROOT / "j2_adversarial" / "puf_helper_original.json"
CAPTURE_DIR = ROOT / "puf_results"
OUTPUT_CSV = ROOT / "j2_adversarial" / "controlled_noise_results.csv"

HKDF_INFO = b"L-POPI/ESP32/SRAM-PUF/v1"
COMMIT_INFO = b"L-POPI/ESP32/SRAM-PUF/key-commit/v1"

NOISE_RATES = [
    0.0,
    0.0025,
    0.005,
    0.01,
    0.02,
    0.05,
    0.10,
    0.15,
    0.20,
    0.25,
    0.30,
    0.35,
    0.40,
    0.50,
]

TRIALS_PER_CAPTURE = 100
RNG_SEED = 20260913


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


def hkdf_sha256(ikm, salt, info, length):
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


def parse_capture(path, region=1, region_bytes=256):
    lines = [line.strip() for line in path.read_text().splitlines()]

    prefix = f"REGION,{region},"

    for i, line in enumerate(lines):
        if line.startswith(prefix):
            parts = line.split(",")

            if len(parts) < 4:
                raise ValueError(f"Malformed REGION line in {path}")

            size = int(parts[3])

            if size != region_bytes:
                raise ValueError(
                    f"{path}: unexpected region size {size}, "
                    f"expected {region_bytes}"
                )

            raw = bytes.fromhex(lines[i + 1])

            if len(raw) != region_bytes:
                raise ValueError(
                    f"{path}: raw length {len(raw)}, "
                    f"expected {region_bytes}"
                )

            return bytes_to_bits(raw)

    raise ValueError(f"Region {region} not found in {path}")


def helper_bits_from_hex(helper_hex, selected_bits):
    raw = bytes.fromhex(helper_hex)
    bits = bytes_to_bits(raw)
    return bits[:selected_bits]


def reconstruct(sample_bits, helper):
    indexes = helper["bit_indexes"]
    helper_bits = helper_bits_from_hex(
        helper["helper_hex"],
        helper["selected_bits"]
    )

    group_size = helper["group_size"]

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

    key = hkdf_sha256(
        secret,
        salt,
        HKDF_INFO,
        helper["key_bytes"]
    )

    commitment = hashlib.sha256(
        COMMIT_INFO + key
    ).digest()

    expected = bytes.fromhex(
        helper["key_commitment_hex"]
    )

    return hmac.compare_digest(
        commitment,
        expected
    )


def inject_noise_selected_bits(sample_bits, selected_indexes, noise_rate, rng):
    noisy = list(sample_bits)

    n_selected = len(selected_indexes)

    n_flips = round(noise_rate * n_selected)

    if n_flips == 0:
        return noisy, 0

    positions = rng.sample(
        range(n_selected),
        n_flips
    )

    for selected_position in positions:
        raw_index = selected_indexes[selected_position]
        noisy[raw_index] ^= 1

    return noisy, n_flips


def wilson_interval(successes, total, z=1.96):
    if total == 0:
        return 0.0, 0.0

    p = successes / total

    denominator = 1 + (z * z) / total

    centre = (
        p + (z * z) / (2 * total)
    ) / denominator

    margin = (
        z
        * math.sqrt(
            (p * (1 - p) / total)
            + (z * z) / (4 * total * total)
        )
        / denominator
    )

    return max(0.0, centre - margin), min(1.0, centre + margin)


with open(HELPER_PATH, "r") as f:
    helper = json.load(f)


captures = []

for number in range(21, 31):
    path = CAPTURE_DIR / f"capture_{number:03d}.txt"

    if not path.exists():
        raise FileNotFoundError(path)

    bits = parse_capture(
        path,
        region=helper["region"],
        region_bytes=helper["region_bytes"]
    )

    captures.append((number, bits))


print("=" * 80)
print("L-PoPI J2.2 -- SYNTHETIC CONTROLLED-NOISE ROBUSTNESS")
print("=" * 80)

print(f"Captures            : 021-030 ({len(captures)} held-out captures)")
print(f"Selected bits       : {helper['selected_bits']}")
print(f"Group size          : {helper['group_size']}")
print(f"Trials per capture  : {TRIALS_PER_CAPTURE}")
print(f"Trials per rate     : {TRIALS_PER_CAPTURE * len(captures)}")
print(f"RNG seed            : {RNG_SEED}")
print()


# Baseline validation first
baseline_pass = 0

for capture_number, bits in captures:
    ok = reconstruct(bits, helper)

    status = "PASS" if ok else "FAIL"

    print(
        f"Baseline capture {capture_number:03d}: {status}"
    )

    if ok:
        baseline_pass += 1


print()
print(
    f"Baseline reconstruction: "
    f"{baseline_pass}/{len(captures)}"
)
print()

if baseline_pass != len(captures):
    raise RuntimeError(
        "Baseline held-out reconstruction is not 10/10. "
        "Stop before noise injection."
    )


rows = []

for rate_index, noise_rate in enumerate(NOISE_RATES):
    successes = 0
    total = 0

    flips_example = None

    for capture_number, bits in captures:

        for trial in range(TRIALS_PER_CAPTURE):

            # deterministic but distinct RNG stream
            seed = (
                RNG_SEED
                + rate_index * 1_000_000
                + capture_number * 10_000
                + trial
            )

            rng = random.Random(seed)

            noisy_bits, n_flips = inject_noise_selected_bits(
                bits,
                helper["bit_indexes"],
                noise_rate,
                rng
            )

            if flips_example is None:
                flips_example = n_flips

            ok = reconstruct(
                noisy_bits,
                helper
            )

            successes += int(ok)
            total += 1


    success_rate = successes / total

    ci_low, ci_high = wilson_interval(
        successes,
        total
    )

    row = {
        "noise_rate": noise_rate,
        "noise_percent": noise_rate * 100,
        "flips_per_trial": flips_example,
        "successes": successes,
        "trials": total,
        "success_rate": success_rate,
        "success_percent": success_rate * 100,
        "ci95_low_percent": ci_low * 100,
        "ci95_high_percent": ci_high * 100,
    }

    rows.append(row)

    print(
        f"Noise {noise_rate*100:6.2f}% | "
        f"flips={flips_example:4d} | "
        f"success={successes:4d}/{total:4d} | "
        f"{success_rate*100:7.3f}% | "
        f"95% CI [{ci_low*100:7.3f}, {ci_high*100:7.3f}]"
    )


with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "noise_rate",
            "noise_percent",
            "flips_per_trial",
            "successes",
            "trials",
            "success_rate",
            "success_percent",
            "ci95_low_percent",
            "ci95_high_percent",
        ]
    )

    writer.writeheader()
    writer.writerows(rows)


print()
print(f"CSV written to: {OUTPUT_CSV}")
print()
print(
    "IMPORTANT: these results characterize synthetic "
    "independent bit-flip injection on selected SRAM-PUF bits. "
    "They are not physical environmental BER measurements."
)
