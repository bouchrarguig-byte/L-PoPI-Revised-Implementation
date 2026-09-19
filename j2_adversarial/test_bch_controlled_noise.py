import json
import math
import random
import csv
import hashlib
from pathlib import Path

import bchlib


ROOT = Path(".")
CAPTURE_DIR = ROOT / "puf_results"
REP_HELPER_PATH = ROOT / "j2_adversarial" / "puf_helper_original.json"

OUTPUT_CSV = ROOT / "j2_adversarial" / "bch_controlled_noise_results.csv"

ENROLLMENT = range(1, 21)
HOLDOUT = range(21, 31)

SECRET_BYTES = 16
RNG_SEED = 20260913

TRIALS_PER_CAPTURE = 100

NOISE_RATES = [
    0.020,
    0.025,
    0.030,
    0.035,
    0.040,
    0.045,
    0.050,
    0.055,
    0.060,
    0.065,
    0.070,
    0.075,
    0.080,
    0.090,
    0.100,
]

CANDIDATES = [
    {
        "name": "BCH-A",
        "m": 8,
        "t": 8,
    },
    {
        "name": "BCH-C",
        "m": 9,
        "t": 16,
    },
]


def bytes_to_bits(data):
    bits = []

    for byte in data:
        for pos in range(7, -1, -1):
            bits.append((byte >> pos) & 1)

    return bits


def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise ValueError("Bit length must be byte aligned")

    out = bytearray()

    for start in range(0, len(bits), 8):
        value = 0

        for bit in bits[start:start + 8]:
            value = (value << 1) | bit

        out.append(value)

    return bytes(out)


def parse_capture(path, region=1, region_bytes=256):
    lines = [
        line.strip()
        for line in path.read_text().splitlines()
    ]

    prefix = f"REGION,{region},"

    for i, line in enumerate(lines):
        if line.startswith(prefix):
            parts = line.split(",")

            if len(parts) < 4:
                raise ValueError(
                    f"Malformed REGION line in {path}"
                )

            size = int(parts[3])

            if size != region_bytes:
                raise ValueError(
                    f"{path}: region size {size}, "
                    f"expected {region_bytes}"
                )

            raw = bytes.fromhex(lines[i + 1])

            if len(raw) != region_bytes:
                raise ValueError(
                    f"{path}: raw length {len(raw)}, "
                    f"expected {region_bytes}"
                )

            return bytes_to_bits(raw)

    raise ValueError(
        f"Region {region} not found in {path}"
    )


def majority_reference(captures):
    n_bits = len(captures[0])

    reference = []

    for bit_index in range(n_bits):
        ones = sum(
            capture[bit_index]
            for capture in captures
        )

        zeros = len(captures) - ones

        if ones > zeros:
            reference.append(1)

        elif zeros > ones:
            reference.append(0)

        else:
            reference.append(
                captures[0][bit_index]
            )

    return reference


def xor_bits(a, b):
    if len(a) != len(b):
        raise ValueError("XOR length mismatch")

    return [
        x ^ y
        for x, y in zip(a, b)
    ]


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

    return (
        max(0.0, centre - margin),
        min(1.0, centre + margin),
    )


def inject_noise_selected(
    capture_bits,
    selected_indexes,
    noise_rate,
    rng
):
    noisy = list(capture_bits)

    n_selected = len(selected_indexes)

    n_flips = round(
        noise_rate * n_selected
    )

    if n_flips == 0:
        return noisy, 0

    positions = rng.sample(
        range(n_selected),
        n_flips
    )

    for pos in positions:
        raw_index = selected_indexes[pos]
        noisy[raw_index] ^= 1

    return noisy, n_flips


# ------------------------------------------------------------
# Load existing repetition helper only to reuse the same
# enrollment-selected stable-cell pool.
# ------------------------------------------------------------

with open(REP_HELPER_PATH, "r") as f:
    rep_helper = json.load(f)

stable_pool = rep_helper["bit_indexes"]


# ------------------------------------------------------------
# Load enrollment captures
# ------------------------------------------------------------

enrollment_captures = []

for number in ENROLLMENT:
    path = CAPTURE_DIR / f"capture_{number:03d}.txt"

    enrollment_captures.append(
        parse_capture(
            path,
            region=rep_helper["region"],
            region_bytes=rep_helper["region_bytes"]
        )
    )


# ------------------------------------------------------------
# Load held-out captures
# ------------------------------------------------------------

holdout_captures = []

for number in HOLDOUT:
    path = CAPTURE_DIR / f"capture_{number:03d}.txt"

    holdout_captures.append(
        (
            number,
            parse_capture(
                path,
                region=rep_helper["region"],
                region_bytes=rep_helper["region_bytes"]
            )
        )
    )


reference = majority_reference(
    enrollment_captures
)


# ------------------------------------------------------------
# Reproducible benchmark secret
# ------------------------------------------------------------

secret_rng = random.Random(
    RNG_SEED
)

secret = bytes(
    secret_rng.randrange(0, 256)
    for _ in range(SECRET_BYTES)
)

secret_commitment = hashlib.sha256(
    secret
).digest()


print("=" * 82)
print("L-PoPI J2 -- BCH SYNTHETIC CONTROLLED-NOISE ROBUSTNESS")
print("=" * 82)

print("Enrollment captures : 001-020")
print("Held-out captures   : 021-030")
print(f"Stable-cell pool    : {len(stable_pool)} bits")
print(f"Secret size         : {SECRET_BYTES * 8} bits")
print(f"Trials/capture/rate : {TRIALS_PER_CAPTURE}")
print(f"Trials/rate/scheme  : {TRIALS_PER_CAPTURE * len(holdout_captures)}")
print(f"RNG seed            : {RNG_SEED}")
print()


rows = []


for candidate_index, candidate in enumerate(CANDIDATES):

    name = candidate["name"]
    m = candidate["m"]
    t = candidate["t"]

    bch = bchlib.BCH(
        t,
        m=m
    )

    data = bytearray(secret)
    ecc = bytearray(
        bch.encode(data)
    )

    codeword = bytes(
        data + ecc
    )

    codeword_bits = bytes_to_bits(
        codeword
    )

    codeword_len = len(
        codeword_bits
    )

    selected_indexes = stable_pool[
        :codeword_len
    ]

    enrolled_puf_bits = [
        reference[index]
        for index in selected_indexes
    ]

    helper_bits = xor_bits(
        enrolled_puf_bits,
        codeword_bits
    )


    print("-" * 82)
    print(name)
    print("-" * 82)

    print(f"m              : {m}")
    print(f"t              : {t}")
    print(f"ecc_bits       : {bch.ecc_bits}")
    print(f"ecc_bytes      : {bch.ecc_bytes}")
    print(f"PUF bits used  : {codeword_len}")
    print()


    # --------------------------------------------------------
    # Baseline check before any synthetic noise
    # --------------------------------------------------------

    baseline_success = 0

    for capture_number, capture_bits in holdout_captures:

        observed = [
            capture_bits[index]
            for index in selected_indexes
        ]

        reconstructed_bits = xor_bits(
            observed,
            helper_bits
        )

        packet = bits_to_bytes(
            reconstructed_bits
        )

        noisy_data = bytearray(
            packet[:SECRET_BYTES]
        )

        noisy_ecc = bytearray(
            packet[SECRET_BYTES:]
        )

        nerr = bch.decode(
            noisy_data,
            noisy_ecc
        )

        if nerr >= 0:
            bch.correct(
                noisy_data,
                noisy_ecc
            )

        recovered = bytes(
            noisy_data
        )

        ok = (
            nerr >= 0
            and hashlib.sha256(
                recovered
            ).digest()
            == secret_commitment
        )

        baseline_success += int(ok)

        print(
            f"Baseline capture {capture_number:03d}: "
            f"{'PASS' if ok else 'FAIL'} | "
            f"decoder={nerr}"
        )


    print(
        f"Baseline reconstruction: "
        f"{baseline_success}/{len(holdout_captures)}"
    )

    print()

    if baseline_success != len(holdout_captures):
        raise RuntimeError(
            f"{name}: baseline is not 10/10. "
            "Stop before synthetic noise."
        )


    # --------------------------------------------------------
    # Synthetic noise sweep
    # --------------------------------------------------------

    for rate_index, noise_rate in enumerate(NOISE_RATES):

        successes = 0
        total = 0
        flips_example = None


        for capture_number, capture_bits in holdout_captures:

            for trial in range(TRIALS_PER_CAPTURE):

                seed = (
                    RNG_SEED
                    + candidate_index * 100_000_000
                    + rate_index * 1_000_000
                    + capture_number * 10_000
                    + trial
                )

                rng = random.Random(
                    seed
                )

                noisy_capture, n_flips = inject_noise_selected(
                    capture_bits,
                    selected_indexes,
                    noise_rate,
                    rng
                )

                if flips_example is None:
                    flips_example = n_flips


                observed = [
                    noisy_capture[index]
                    for index in selected_indexes
                ]

                reconstructed_bits = xor_bits(
                    observed,
                    helper_bits
                )

                packet = bits_to_bytes(
                    reconstructed_bits
                )

                noisy_data = bytearray(
                    packet[:SECRET_BYTES]
                )

                noisy_ecc = bytearray(
                    packet[SECRET_BYTES:]
                )

                nerr = bch.decode(
                    noisy_data,
                    noisy_ecc
                )

                if nerr >= 0:
                    bch.correct(
                        noisy_data,
                        noisy_ecc
                    )

                recovered = bytes(
                    noisy_data
                )

                ok = (
                    nerr >= 0
                    and hashlib.sha256(
                        recovered
                    ).digest()
                    == secret_commitment
                )

                successes += int(ok)
                total += 1


        success_rate = (
            successes / total
        )

        ci_low, ci_high = wilson_interval(
            successes,
            total
        )


        print(
            f"Noise {noise_rate*100:6.2f}% | "
            f"flips={flips_example:3d} | "
            f"success={successes:4d}/{total:4d} | "
            f"{success_rate*100:7.3f}% | "
            f"95% CI [{ci_low*100:7.3f}, "
            f"{ci_high*100:7.3f}]"
        )


        rows.append(
            {
                "scheme": name,
                "m": m,
                "t": t,
                "puf_bits_used": codeword_len,
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
        )


    print()


with open(OUTPUT_CSV, "w", newline="") as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "scheme",
            "m",
            "t",
            "puf_bits_used",
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
    writer.writerows(
        rows
    )


print("=" * 82)
print(f"CSV written to: {OUTPUT_CSV}")
print()
print(
    "IMPORTANT: synthetic independent bit-flip injection only. "
    "These noise levels are not physical environmental BER measurements."
)
print("=" * 82)
