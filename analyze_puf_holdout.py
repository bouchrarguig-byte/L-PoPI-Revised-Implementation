#!/usr/bin/env python3

from pathlib import Path
import numpy as np

CAPTURE_DIR = Path("puf_results")
REGION = 1
REGION_SIZE_BYTES = 256
REGION_SIZE_BITS = REGION_SIZE_BYTES * 8

ENROLLMENT = range(1, 21)   # 001-020
HOLDOUT = range(21, 31)     # 021-030

THRESHOLDS = [0.90, 0.95, 0.97, 0.99, 1.00]


def hex_to_bits(hex_data):
    hex_data = hex_data.strip()

    if len(hex_data) != REGION_SIZE_BYTES * 2:
        raise ValueError(
            f"Expected {REGION_SIZE_BYTES * 2} hex chars, "
            f"got {len(hex_data)}"
        )

    raw = bytes.fromhex(hex_data)

    if len(raw) != REGION_SIZE_BYTES:
        raise ValueError("Invalid region size")

    return np.unpackbits(
        np.frombuffer(raw, dtype=np.uint8)
    ).astype(np.uint8)


def load_capture(number):
    filename = CAPTURE_DIR / f"capture_{number:03d}.txt"

    if not filename.exists():
        raise FileNotFoundError(filename)

    lines = [
        line.strip()
        for line in filename.read_text().splitlines()
        if line.strip()
    ]

    prefix = f"REGION,{REGION},"

    for i, line in enumerate(lines):
        if line.startswith(prefix):
            fields = line.split(",")

            if len(fields) < 4:
                raise ValueError(f"Malformed metadata: {filename}")

            size = int(fields[3])

            if size != REGION_SIZE_BYTES:
                raise ValueError(
                    f"Unexpected size {size} in {filename}"
                )

            if i + 1 >= len(lines):
                raise ValueError(f"Missing data in {filename}")

            return hex_to_bits(lines[i + 1])

    raise ValueError(f"Region {REGION} not found in {filename}")


def majority_reference(matrix):
    # Enrollment contains 20 captures, so exact 10/10 ties are possible.
    # Tie-breaking is deterministic: use enrollment capture #1.
    sums = matrix.sum(axis=0)
    ref = (sums > matrix.shape[0] / 2).astype(np.uint8)

    ties = sums == matrix.shape[0] / 2
    ref[ties] = matrix[0, ties]

    return ref


print("=" * 76)
print("ESP32 SRAM-PUF ENROLLMENT / HELD-OUT ANALYSIS")
print("=" * 76)
print("Region       : 1")
print("Enrollment   : captures 001-020 (N=20)")
print("Held-out     : captures 021-030 (N=10)")
print("Region size  : 2048 bits")
print("=" * 76)

enrollment = np.array(
    [load_capture(i) for i in ENROLLMENT],
    dtype=np.uint8
)

holdout = np.array(
    [load_capture(i) for i in HOLDOUT],
    dtype=np.uint8
)

print("\nLoaded:")
print(f"  Enrollment : {enrollment.shape}")
print(f"  Held-out   : {holdout.shape}")

reference = majority_reference(enrollment)

# Reliability is defined relative to the enrollment majority value.
agreement = enrollment == reference
reliability = agreement.mean(axis=0)

print("\n" + "=" * 76)
print("ENROLLMENT BIT STABILITY")
print("=" * 76)

print(f"Mean reliability   : {reliability.mean() * 100:.4f}%")
print(f"Median reliability : {np.median(reliability) * 100:.4f}%")

for threshold in THRESHOLDS:
    count = int(np.sum(reliability >= threshold))
    print(
        f"Bits >= {threshold*100:5.1f}% : "
        f"{count:4d}/{REGION_SIZE_BITS} "
        f"({100*count/REGION_SIZE_BITS:.2f}%)"
    )

print("\n" + "=" * 76)
print("HELD-OUT BER AGAINST ENROLLMENT MAJORITY REFERENCE")
print("=" * 76)

# Raw BER first.
raw_bers = np.mean(holdout != reference, axis=1)

print("\nRAW -- all 2048 bits")
print(f"  Mean BER   : {raw_bers.mean()*100:.4f}%")
print(f"  Median BER : {np.median(raw_bers)*100:.4f}%")
print(f"  Min BER    : {raw_bers.min()*100:.4f}%")
print(f"  Max BER    : {raw_bers.max()*100:.4f}%")

print("\nPer held-out capture:")
for capture_no, ber in zip(HOLDOUT, raw_bers):
    print(f"  Capture {capture_no:03d}: {ber*100:.4f}%")

results = []

for threshold in THRESHOLDS:
    mask = reliability >= threshold
    nbits = int(mask.sum())

    if nbits == 0:
        continue

    bers = np.mean(
        holdout[:, mask] != reference[mask],
        axis=1
    )

    results.append(
        (
            threshold,
            nbits,
            bers.mean(),
            np.median(bers),
            bers.min(),
            bers.max()
        )
    )

print("\n" + "=" * 76)
print("STABLE-BIT SELECTION -- HELD-OUT RESULTS")
print("=" * 76)

print(
    f"{'Threshold':>10} "
    f"{'Bits':>7} "
    f"{'Mean BER':>12} "
    f"{'Median':>12} "
    f"{'Min':>12} "
    f"{'Max':>12}"
)

print("-" * 76)

for threshold, nbits, mean, median, minimum, maximum in results:
    print(
        f"{threshold*100:9.1f}% "
        f"{nbits:7d} "
        f"{mean*100:11.4f}% "
        f"{median*100:11.4f}% "
        f"{minimum*100:11.4f}% "
        f"{maximum*100:11.4f}%"
    )

print("\n" + "=" * 76)
print("INTERPRETATION")
print("=" * 76)
print(
    "Stable-bit selection was derived exclusively from captures 001-020."
)
print(
    "Captures 021-030 were not used for bit selection or reference construction."
)
print(
    "Therefore the held-out BER measures stability on unseen cold-power cycles."
)
print(
    "This is an intra-device experiment and does not measure inter-device uniqueness."
)
