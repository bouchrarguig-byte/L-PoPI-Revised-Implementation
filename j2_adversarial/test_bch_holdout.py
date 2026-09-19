import json
import hashlib
import random
from pathlib import Path

import bchlib


ROOT = Path(".")
CAPTURE_DIR = ROOT / "puf_results"
REP_HELPER_PATH = ROOT / "j2_adversarial" / "puf_helper_original.json"
OUTPUT_PATH = ROOT / "j2_adversarial" / "bch_holdout_results.json"

ENROLLMENT = range(1, 21)
HOLDOUT = range(21, 31)

SECRET_BYTES = 16
RNG_SEED = 20260913

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
            # deterministic tie break:
            # enrollment capture 001
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


# ------------------------------------------------------------
# Load repetition helper only to reuse the SAME enrollment-only
# stable-cell pool already validated in J1.
# ------------------------------------------------------------

with open(REP_HELPER_PATH, "r") as f:
    rep_helper = json.load(f)

stable_pool = rep_helper["bit_indexes"]

if len(stable_pool) != 1664:
    raise ValueError(
        f"Unexpected stable pool size: {len(stable_pool)}"
    )


# ------------------------------------------------------------
# Load physical enrollment / held-out captures
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
# Deterministic benchmark secret.
#
# IMPORTANT:
# this is only for reproducible ECC benchmarking.
# Production enrollment must use cryptographic randomness.
# ------------------------------------------------------------

rng = random.Random(RNG_SEED)

secret = bytes(
    rng.randrange(0, 256)
    for _ in range(SECRET_BYTES)
)

secret_commitment = hashlib.sha256(
    secret
).hexdigest()


print("=" * 78)
print("L-PoPI J2 -- BCH HELD-OUT RECONSTRUCTION")
print("=" * 78)

print("Enrollment captures : 001-020")
print("Held-out captures   : 021-030")
print(f"Stable-cell pool    : {len(stable_pool)} bits")
print(f"Secret size         : {SECRET_BYTES * 8} bits")
print(f"Benchmark RNG seed  : {RNG_SEED}")
print()


all_results = []


for candidate in CANDIDATES:

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

    codeword = bytes(data + ecc)
    codeword_bits = bytes_to_bits(
        codeword
    )

    codeword_len = len(codeword_bits)

    # Reuse the first N indexes from the exact same
    # enrollment-only stable pool as repetition-13.
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


    print("-" * 78)
    print(name)
    print("-" * 78)

    print(f"m                  : {m}")
    print(f"t                  : {t}")
    print(f"n                  : {bch.n}")
    print(f"ecc_bits           : {bch.ecc_bits}")
    print(f"ecc_bytes          : {bch.ecc_bytes}")
    print(f"codeword bytes     : {len(codeword)}")
    print(f"PUF bits used      : {codeword_len}")
    print()


    successes = 0
    per_capture = []


    for capture_number, capture_bits in holdout_captures:

        observed = [
            capture_bits[index]
            for index in selected_indexes
        ]

        noisy_codeword_bits = xor_bits(
            observed,
            helper_bits
        )

        raw_errors = sum(
            a != b
            for a, b in zip(
                noisy_codeword_bits,
                codeword_bits
            )
        )

        noisy_packet = bits_to_bytes(
            noisy_codeword_bits
        )

        noisy_data = bytearray(
            noisy_packet[:SECRET_BYTES]
        )

        noisy_ecc = bytearray(
            noisy_packet[SECRET_BYTES:]
        )

        nerr = bch.decode(
            noisy_data,
            noisy_ecc
        )

        decode_ok = nerr >= 0

        if decode_ok:
            bch.correct(
                noisy_data,
                noisy_ecc
            )

        recovered_secret = bytes(
            noisy_data
        )

        commitment_ok = (
            hashlib.sha256(
                recovered_secret
            ).hexdigest()
            == secret_commitment
        )

        ok = (
            decode_ok
            and commitment_ok
        )

        successes += int(ok)

        per_capture.append(
            {
                "capture": capture_number,
                "raw_errors": raw_errors,
                "decoder_reported_errors": nerr,
                "success": ok,
            }
        )

        print(
            f"Capture {capture_number:03d}: "
            f"{'PASS' if ok else 'FAIL'} | "
            f"raw_errors={raw_errors:2d} | "
            f"decoder={nerr}"
        )


    print()

    print(
        f"Held-out reconstruction: "
        f"{successes}/{len(holdout_captures)}"
    )

    print()

    all_results.append(
        {
            "name": name,
            "m": m,
            "t": t,
            "n": bch.n,
            "ecc_bits": bch.ecc_bits,
            "ecc_bytes": bch.ecc_bytes,
            "secret_bits": SECRET_BYTES * 8,
            "puf_bits_used": codeword_len,
            "stable_pool_size": len(stable_pool),
            "successes": successes,
            "trials": len(holdout_captures),
            "per_capture": per_capture,
        }
    )


output = {
    "experiment": (
        "L-PoPI BCH held-out reconstruction"
    ),
    "enrollment": "captures 001-020",
    "holdout": "captures 021-030",
    "stable_pool_source": (
        "same 1664 enrollment-only selected indexes "
        "used by repetition-13 baseline"
    ),
    "benchmark_rng_seed": RNG_SEED,
    "benchmark_secret_note": (
        "Deterministic secret used only for reproducible "
        "ECC comparison; not a production enrollment method."
    ),
    "results": all_results,
}


with open(OUTPUT_PATH, "w") as f:
    json.dump(
        output,
        f,
        indent=2
    )


print("=" * 78)
print(f"Results written to: {OUTPUT_PATH}")
print("=" * 78)
