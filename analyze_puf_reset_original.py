#!/usr/bin/env python3

"""
ESP32 SRAM-PUF Experimental Analysis
====================================

Input files:
    puf_results/reset_capture_01.txt
    ...
    puf_results/reset_capture_30.txt

Actual input format:

    RESET CAPTURE 1
    REGION 1
    <512 hexadecimal characters>
    REGION 2
    <512 hexadecimal characters>
    REGION 3
    <512 hexadecimal characters>

Each region:
    256 bytes
    2048 bits

Analysis:
    - Capture validation
    - Bit-level reliability
    - Stable-bit percentages
    - Unstable-bit count
    - Reference BER versus Capture 1
    - Pairwise Hamming distance
    - Pairwise BER
    - BER percentiles
    - Region ranking

Output:
    puf_analysis/
        region1_bit_reliability.csv
        region2_bit_reliability.csv
        region3_bit_reliability.csv

        hamming_matrix_region1.csv
        hamming_matrix_region2.csv
        hamming_matrix_region3.csv

        ber_region1.csv
        ber_region2.csv
        ber_region3.csv

        puf_statistics.txt

        reliability_region1.png
        reliability_region2.png
        reliability_region3.png

        ber_region1.png
        ber_region2.png
        ber_region3.png
"""

import re
import csv
from pathlib import Path

import numpy as np


# ============================================================
# CONFIGURATION
# ============================================================

CAPTURE_DIR = Path("puf_results")
OUTPUT_DIR = Path("puf_analysis")

NUM_CAPTURES = 30

REGIONS = [1, 2, 3]

REGION_SIZE_BYTES = 256
REGION_SIZE_BITS = REGION_SIZE_BYTES * 8

STABILITY_THRESHOLDS = [0.90, 0.95, 0.97, 0.99]


# ============================================================
# OPTIONAL MATPLOTLIB
# ============================================================

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


# ============================================================
# HEX -> BITS
# ============================================================

def hex_to_bits(hex_string):
    """
    Convert exactly 256 bytes of hexadecimal data
    into exactly 2048 bits.
    """

    hex_string = hex_string.strip()

    expected_hex_chars = REGION_SIZE_BYTES * 2

    if len(hex_string) != expected_hex_chars:
        raise ValueError(
            "Expected "
            + str(expected_hex_chars)
            + " hexadecimal characters, found "
            + str(len(hex_string))
        )

    if not re.fullmatch(r"[0-9A-Fa-f]+", hex_string):
        raise ValueError(
            "Region contains non-hexadecimal characters"
        )

    raw_bytes = bytes.fromhex(hex_string)

    if len(raw_bytes) != REGION_SIZE_BYTES:
        raise ValueError(
            "Expected "
            + str(REGION_SIZE_BYTES)
            + " bytes, found "
            + str(len(raw_bytes))
        )

    byte_array = np.frombuffer(
        raw_bytes,
        dtype=np.uint8
    )

    bits = np.unpackbits(byte_array)

    if len(bits) != REGION_SIZE_BITS:
        raise ValueError(
            "Expected "
            + str(REGION_SIZE_BITS)
            + " bits, found "
            + str(len(bits))
        )

    return bits.astype(np.uint8)


# ============================================================
# EXTRACT REGION
# ============================================================

def extract_region_data(filename, region_number):
    """
    Extract REGION N from the actual capture file.

    Format:

        REGION 1
        HEX DATA

        REGION 2
        HEX DATA

        REGION 3
        HEX DATA
    """

    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as file:

        lines = [
            line.strip()
            for line in file
            if line.strip()
        ]

    region_label = "REGION " + str(region_number)

    try:
        index = lines.index(region_label)
    except ValueError:
        raise ValueError(
            region_label
            + " not found in "
            + str(filename)
        )

    if index + 1 >= len(lines):
        raise ValueError(
            "No data after "
            + region_label
            + " in "
            + str(filename)
        )

    hex_data = lines[index + 1]

    if hex_data.startswith("REGION "):
        raise ValueError(
            "No hexadecimal data after "
            + region_label
        )

    return hex_to_bits(hex_data)


# ============================================================
# LOAD ALL CAPTURES
# ============================================================

def load_captures():

    print()
    print("Loading captures...")
    print()

    data = {}

    for region in REGIONS:
        data[region] = []

    for capture_number in range(
        1,
        NUM_CAPTURES + 1
    ):

        filename = (
            CAPTURE_DIR
            / (
                "reset_capture_"
                + str(capture_number).zfill(2)
                + ".txt"
            )
        )

        if not filename.exists():

            raise FileNotFoundError(
                "Missing capture file: "
                + str(filename)
            )

        print(
            "Loading capture "
            + str(capture_number)
            + "/"
            + str(NUM_CAPTURES)
            + " ...",
            end=""
        )

        try:

            for region in REGIONS:

                bits = extract_region_data(
                    filename,
                    region
                )

                data[region].append(bits)

            print(" OK")

        except Exception as error:

            print(" FAILED")

            raise RuntimeError(
                "Error in "
                + str(filename)
                + ": "
                + str(error)
            )

    print()
    print(
        "Successfully loaded "
        + str(NUM_CAPTURES)
        + "/"
        + str(NUM_CAPTURES)
        + " captures."
    )

    for region in REGIONS:

        print(
            "  Region "
            + str(region)
            + ": "
            + str(len(data[region]))
            + " × "
            + str(REGION_SIZE_BITS)
            + " bits"
        )

    return data


# ============================================================
# HAMMING DISTANCE
# ============================================================

def hamming_distance(a, b):

    return int(
        np.sum(a != b)
    )


# ============================================================
# HAMMING MATRIX
# ============================================================

def calculate_hamming_matrix(captures):

    number_of_captures = len(captures)

    matrix = np.zeros(
        (
            number_of_captures,
            number_of_captures
        ),
        dtype=np.int32
    )

    for i in range(number_of_captures):

        for j in range(i + 1, number_of_captures):

            distance = hamming_distance(
                captures[i],
                captures[j]
            )

            matrix[i, j] = distance
            matrix[j, i] = distance

    return matrix


# ============================================================
# BIT RELIABILITY
# ============================================================

def calculate_bit_reliability(captures):

    matrix = np.array(
        captures,
        dtype=np.uint8
    )

    number_of_captures = matrix.shape[0]

    ones_count = np.sum(
        matrix,
        axis=0
    )

    zeros_count = (
        number_of_captures
        - ones_count
    )

    majority_value = (
        ones_count >= zeros_count
    ).astype(np.uint8)

    majority_count = np.maximum(
        ones_count,
        zeros_count
    )

    reliability = (
        majority_count
        / number_of_captures
    )

    flip_count = (
        number_of_captures
        - majority_count
    )

    return {
        "ones_count": ones_count,
        "zeros_count": zeros_count,
        "majority_value": majority_value,
        "reliability": reliability,
        "flip_count": flip_count
    }


# ============================================================
# REFERENCE BER
# ============================================================

def calculate_reference_results(captures):

    reference = captures[0]

    results = []

    for i in range(len(captures)):

        distance = hamming_distance(
            reference,
            captures[i]
        )

        current_ber = (
            distance
            / REGION_SIZE_BITS
        )

        results.append({
            "capture": i + 1,
            "hamming_distance": distance,
            "ber": current_ber
        })

    return results


# ============================================================
# PAIRWISE VALUES
# ============================================================

def get_pairwise_values(matrix):

    values = []

    n = matrix.shape[0]

    for i in range(n):

        for j in range(i + 1, n):

            values.append(
                float(matrix[i, j])
            )

    return np.array(
        values,
        dtype=np.float64
    )


# ============================================================
# STATISTICS
# ============================================================

def calculate_statistics(values):

    values = np.asarray(
        values,
        dtype=np.float64
    )

    return {
        "count": len(values),
        "mean": float(np.mean(values)),
        "median": float(np.median(values)),
        "std": float(np.std(values)),
        "min": float(np.min(values)),
        "max": float(np.max(values)),
        "p95": float(np.percentile(values, 95)),
        "p99": float(np.percentile(values, 99))
    }


# ============================================================
# REGION ANALYSIS
# ============================================================

def analyze_region(
    region,
    captures
):

    print()
    print("=" * 70)
    print("REGION " + str(region))
    print("=" * 70)

    matrix = np.array(
        captures,
        dtype=np.uint8
    )

    print(
        "Captures : "
        + str(matrix.shape[0])
    )

    print(
        "Bits     : "
        + str(matrix.shape[1])
    )

    # --------------------------------------------------------
    # BIT RELIABILITY
    # --------------------------------------------------------

    reliability_data = (
        calculate_bit_reliability(
            captures
        )
    )

    reliability = (
        reliability_data["reliability"]
    )

    print()
    print("BIT-LEVEL RELIABILITY")
    print("-" * 70)

    mean_reliability = (
        np.mean(reliability)
    )

    median_reliability = (
        np.median(reliability)
    )

    minimum_reliability = (
        np.min(reliability)
    )

    maximum_reliability = (
        np.max(reliability)
    )

    print(
        "Mean reliability   : "
        + f"{mean_reliability * 100:.4f}%"
    )

    print(
        "Median reliability : "
        + f"{median_reliability * 100:.4f}%"
    )

    print(
        "Minimum reliability: "
        + f"{minimum_reliability * 100:.4f}%"
    )

    print(
        "Maximum reliability: "
        + f"{maximum_reliability * 100:.4f}%"
    )

    stable_counts = {}

    for threshold in STABILITY_THRESHOLDS:

        count = int(
            np.sum(
                reliability >= threshold
            )
        )

        stable_counts[threshold] = count

        percentage = (
            count
            / REGION_SIZE_BITS
            * 100
        )

        print(
            "Bits >= "
            + f"{threshold * 100:.0f}"
            + "% reliability : "
            + str(count)
            + " / "
            + str(REGION_SIZE_BITS)
            + " ("
            + f"{percentage:.2f}"
            + "%)"
        )

    unstable_count = int(
        np.sum(
            reliability < 0.90
        )
    )

    unstable_percentage = (
        unstable_count
        / REGION_SIZE_BITS
        * 100
    )

    print(
        "Bits < 90% reliability  : "
        + str(unstable_count)
        + " / "
        + str(REGION_SIZE_BITS)
        + " ("
        + f"{unstable_percentage:.2f}"
        + "%)"
    )

    # --------------------------------------------------------
    # HAMMING MATRIX
    # --------------------------------------------------------

    hamming_matrix = (
        calculate_hamming_matrix(
            captures
        )
    )

    pairwise_hd = (
        get_pairwise_values(
            hamming_matrix
        )
    )

    pairwise_ber = (
        pairwise_hd
        / REGION_SIZE_BITS
    )

    hd_stats = (
        calculate_statistics(
            pairwise_hd
        )
    )

    ber_stats = (
        calculate_statistics(
            pairwise_ber
        )
    )

    # --------------------------------------------------------
    # HAMMING RESULTS
    # --------------------------------------------------------

    print()
    print("PAIRWISE HAMMING DISTANCE")
    print("-" * 70)

    print(
        "Mean              : "
        + f"{hd_stats['mean']:.4f}"
        + " / "
        + str(REGION_SIZE_BITS)
    )

    print(
        "Median            : "
        + f"{hd_stats['median']:.4f}"
    )

    print(
        "Standard deviation: "
        + f"{hd_stats['std']:.4f}"
    )

    print(
        "Minimum           : "
        + f"{hd_stats['min']:.0f}"
    )

    print(
        "Maximum           : "
        + f"{hd_stats['max']:.0f}"
    )

    print(
        "95th percentile   : "
        + f"{hd_stats['p95']:.4f}"
    )

    print(
        "99th percentile   : "
        + f"{hd_stats['p99']:.4f}"
    )

    # --------------------------------------------------------
    # BER RESULTS
    # --------------------------------------------------------

    print()
    print("PAIRWISE BER")
    print("-" * 70)

    print(
        "Mean              : "
        + f"{ber_stats['mean'] * 100:.4f}%"
    )

    print(
        "Median            : "
        + f"{ber_stats['median'] * 100:.4f}%"
    )

    print(
        "Standard deviation: "
        + f"{ber_stats['std'] * 100:.4f}%"
    )

    print(
        "Minimum           : "
        + f"{ber_stats['min'] * 100:.4f}%"
    )

    print(
        "Maximum           : "
        + f"{ber_stats['max'] * 100:.4f}%"
    )

    print(
        "95th percentile   : "
        + f"{ber_stats['p95'] * 100:.4f}%"
    )

    print(
        "99th percentile   : "
        + f"{ber_stats['p99'] * 100:.4f}%"
    )

    # --------------------------------------------------------
    # REFERENCE
    # --------------------------------------------------------

    reference_results = (
        calculate_reference_results(
            captures
        )
    )

    reference_bers = np.array([
        item["ber"]
        for item in reference_results
    ])

    print()
    print("REFERENCE: CAPTURE 1")
    print("-" * 70)

    print(
        "Mean BER vs Capture 1    : "
        + f"{np.mean(reference_bers) * 100:.4f}%"
    )

    print(
        "Maximum BER vs Capture 1 : "
        + f"{np.max(reference_bers) * 100:.4f}%"
    )

    return {
        "region": region,
        "captures": matrix,
        "reliability": reliability_data,
        "hamming_matrix": hamming_matrix,
        "ber_matrix": (
            hamming_matrix
            / REGION_SIZE_BITS
        ),
        "pairwise_hd": pairwise_hd,
        "pairwise_ber": pairwise_ber,
        "hd_stats": hd_stats,
        "ber_stats": ber_stats,
        "reference_results": reference_results,
        "reference_bers": reference_bers,
        "stable_counts": stable_counts,
        "unstable_count": unstable_count
    }


# ============================================================
# SAVE RELIABILITY CSV
# ============================================================

def save_reliability_csv(
    region,
    result
):

    filename = (
        OUTPUT_DIR
        / (
            "region"
            + str(region)
            + "_bit_reliability.csv"
        )
    )

    data = result["reliability"]

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "bit_index",
            "byte_index",
            "bit_in_byte",
            "ones_count",
            "zeros_count",
            "majority_value",
            "reliability",
            "reliability_percent",
            "flip_count",
            "stable_ge_90",
            "stable_ge_95",
            "stable_ge_97",
            "stable_ge_99"
        ])

        for i in range(
            REGION_SIZE_BITS
        ):

            reliability = float(
                data["reliability"][i]
            )

            writer.writerow([
                i,
                i // 8,
                i % 8,
                int(data["ones_count"][i]),
                int(data["zeros_count"][i]),
                int(data["majority_value"][i]),
                reliability,
                reliability * 100,
                int(data["flip_count"][i]),
                int(reliability >= 0.90),
                int(reliability >= 0.95),
                int(reliability >= 0.97),
                int(reliability >= 0.99)
            ])

    return filename


# ============================================================
# SAVE MATRIX CSV
# ============================================================

def save_matrix_csv(
    filename,
    matrix
):

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        header = ["capture"]

        for i in range(
            len(matrix)
        ):

            header.append(
                "capture_"
                + str(i + 1).zfill(2)
            )

        writer.writerow(header)

        for i in range(
            len(matrix)
        ):

            row = [
                "capture_"
                + str(i + 1).zfill(2)
            ]

            for j in range(
                len(matrix)
            ):

                row.append(
                    int(matrix[i, j])
                )

            writer.writerow(row)


# ============================================================
# SAVE BER CSV
# ============================================================

def save_ber_csv(
    region,
    result
):

    filename = (
        OUTPUT_DIR
        / (
            "ber_region"
            + str(region)
            + ".csv"
        )
    )

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "capture",
            "hamming_distance_vs_capture1",
            "ber_vs_capture1",
            "ber_percent_vs_capture1"
        ])

        for item in (
            result["reference_results"]
        ):

            writer.writerow([
                item["capture"],
                item["hamming_distance"],
                item["ber"],
                item["ber"] * 100
            ])

    return filename


# ============================================================
# SAVE TEXT REPORT
# ============================================================

def save_statistics_report(
    results
):

    filename = (
        OUTPUT_DIR
        / "puf_statistics.txt"
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "ESP32 SRAM-PUF EXPERIMENTAL ANALYSIS\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        file.write(
            "Experimental configuration\n"
        )

        file.write(
            "-" * 70 + "\n"
        )

        file.write(
            "Number of captures: "
            + str(NUM_CAPTURES)
            + "\n"
        )

        file.write(
            "Regions analyzed: "
            + str(REGIONS)
            + "\n"
        )

        file.write(
            "Region size: "
            + str(REGION_SIZE_BYTES)
            + " bytes\n"
        )

        file.write(
            "Region size: "
            + str(REGION_SIZE_BITS)
            + " bits\n"
        )

        file.write(
            "Enrollment reference: Capture 1\n"
        )

        file.write(
            "Capture type: RESET captures\n"
        )

        file.write("\n")

        file.write(
            "IMPORTANT LIMITATION\n"
        )

        file.write(
            "-" * 70 + "\n"
        )

        file.write(
            "The experiment evaluates intra-device "
            "stability under repeated reset captures.\n"
        )

        file.write(
            "It does not establish inter-device uniqueness "
            "because only one physical ESP32 was evaluated.\n"
        )

        file.write("\n")

        for region in REGIONS:

            result = results[region]

            file.write(
                "=" * 70 + "\n"
            )

            file.write(
                "REGION "
                + str(region)
                + "\n"
            )

            file.write(
                "=" * 70 + "\n\n"
            )

            reliability = (
                result["reliability"]
                ["reliability"]
            )

            file.write(
                "BIT-LEVEL RELIABILITY\n"
            )

            file.write(
                "-" * 70 + "\n"
            )

            file.write(
                "Mean reliability: "
                + f"{np.mean(reliability) * 100:.4f}%\n"
            )

            file.write(
                "Median reliability: "
                + f"{np.median(reliability) * 100:.4f}%\n"
            )

            file.write(
                "Minimum reliability: "
                + f"{np.min(reliability) * 100:.4f}%\n"
            )

            file.write(
                "Maximum reliability: "
                + f"{np.max(reliability) * 100:.4f}%\n"
            )

            file.write("\n")

            for threshold in STABILITY_THRESHOLDS:

                count = (
                    result["stable_counts"]
                    [threshold]
                )

                percentage = (
                    count
                    / REGION_SIZE_BITS
                    * 100
                )

                file.write(
                    "Bits >= "
                    + f"{threshold * 100:.0f}"
                    + "%: "
                    + str(count)
                    + " ("
                    + f"{percentage:.2f}"
                    + "%)\n"
                )

            unstable = (
                result["unstable_count"]
            )

            unstable_percentage = (
                unstable
                / REGION_SIZE_BITS
                * 100
            )

            file.write(
                "Bits < 90%: "
                + str(unstable)
                + " ("
                + f"{unstable_percentage:.2f}"
                + "%)\n"
            )

            file.write("\n")

            hd = result["hd_stats"]

            file.write(
                "PAIRWISE HAMMING DISTANCE\n"
            )

            file.write(
                "-" * 70 + "\n"
            )

            file.write(
                "Mean: "
                + f"{hd['mean']:.4f}\n"
            )

            file.write(
                "Median: "
                + f"{hd['median']:.4f}\n"
            )

            file.write(
                "Standard deviation: "
                + f"{hd['std']:.4f}\n"
            )

            file.write(
                "Minimum: "
                + f"{hd['min']:.0f}\n"
            )

            file.write(
                "Maximum: "
                + f"{hd['max']:.0f}\n"
            )

            file.write(
                "95th percentile: "
                + f"{hd['p95']:.4f}\n"
            )

            file.write(
                "99th percentile: "
                + f"{hd['p99']:.4f}\n"
            )

            file.write("\n")

            bs = result["ber_stats"]

            file.write(
                "PAIRWISE BER\n"
            )

            file.write(
                "-" * 70 + "\n"
            )

            file.write(
                "Mean: "
                + f"{bs['mean'] * 100:.4f}%\n"
            )

            file.write(
                "Median: "
                + f"{bs['median'] * 100:.4f}%\n"
            )

            file.write(
                "Standard deviation: "
                + f"{bs['std'] * 100:.4f}%\n"
            )

            file.write(
                "Minimum: "
                + f"{bs['min'] * 100:.4f}%\n"
            )

            file.write(
                "Maximum: "
                + f"{bs['max'] * 100:.4f}%\n"
            )

            file.write(
                "95th percentile: "
                + f"{bs['p95'] * 100:.4f}%\n"
            )

            file.write(
                "99th percentile: "
                + f"{bs['p99'] * 100:.4f}%\n"
            )

            file.write("\n")

            reference_bers = (
                result["reference_bers"]
            )

            file.write(
                "REFERENCE CAPTURE BER\n"
            )

            file.write(
                "-" * 70 + "\n"
            )

            file.write(
                "Mean BER vs Capture 1: "
                + f"{np.mean(reference_bers) * 100:.4f}%\n"
            )

            file.write(
                "Maximum BER vs Capture 1: "
                + f"{np.max(reference_bers) * 100:.4f}%\n"
            )

            file.write("\n")

    return filename


# ============================================================
# PLOTS
# ============================================================

def create_plots(results):

    if not MATPLOTLIB_AVAILABLE:

        print()
        print(
            "Matplotlib is not installed."
        )

        print(
            "CSV and TXT analysis will still "
            "be generated."
        )

        return

    for region in REGIONS:

        result = results[region]

        reliability = (
            result["reliability"]
            ["reliability"]
        )

        # ----------------------------------------------------
        # Reliability histogram
        # ----------------------------------------------------

        plt.figure(
            figsize=(9, 6)
        )

        plt.hist(
            reliability * 100,
            bins=20
        )

        plt.xlabel(
            "Bit Reliability (%)"
        )

        plt.ylabel(
            "Number of SRAM Bits"
        )

        plt.title(
            "ESP32 SRAM-PUF Bit Reliability - "
            + "Region "
            + str(region)
        )

        plt.grid(
            True,
            alpha=0.3
        )

        plt.tight_layout()

        plt.savefig(
            OUTPUT_DIR
            / (
                "reliability_region"
                + str(region)
                + ".png"
            ),
            dpi=200
        )

        plt.close()

        # ----------------------------------------------------
        # BER histogram
        # ----------------------------------------------------

        pairwise_ber = (
            result["pairwise_ber"]
            * 100
        )

        plt.figure(
            figsize=(9, 6)
        )

        plt.hist(
            pairwise_ber,
            bins=20
        )

        plt.xlabel(
            "Pairwise BER (%)"
        )

        plt.ylabel(
            "Number of Capture Pairs"
        )

        plt.title(
            "ESP32 SRAM-PUF Pairwise BER - "
            + "Region "
            + str(region)
        )

        plt.grid(
            True,
            alpha=0.3
        )

        plt.tight_layout()

        plt.savefig(
            OUTPUT_DIR
            / (
                "ber_region"
                + str(region)
                + ".png"
            ),
            dpi=200
        )

        plt.close()


# ============================================================
# REGION RANKING
# ============================================================

def rank_regions(results):

    ranking = []

    for region in REGIONS:

        result = results[region]

        mean_ber = (
            result["ber_stats"]
            ["mean"]
        )

        mean_reliability = (
            np.mean(
                result["reliability"]
                ["reliability"]
            )
        )

        stable_95 = (
            result["stable_counts"]
            [0.95]
        )

        ranking.append({
            "region": region,
            "mean_ber": mean_ber,
            "mean_reliability":
                mean_reliability,
            "stable_95":
                stable_95
        })

    ranking.sort(
        key=lambda item:
            item["mean_ber"]
    )

    print()
    print("=" * 70)
    print("REGION RANKING")
    print("=" * 70)

    print()
    print(
        "Ranking criterion: lowest mean pairwise BER"
    )

    print()

    print(
        f"{'Rank':<8}"
        f"{'Region':<10}"
        f"{'Mean BER':<15}"
        f"{'Mean Reliability':<20}"
        f"{'Bits >=95%':<12}"
    )

    print("-" * 70)

    for rank, item in enumerate(
        ranking,
        start=1
    ):

        print(
            f"{rank:<8}"
            f"{item['region']:<10}"
            f"{item['mean_ber'] * 100:<15.4f}"
            f"{item['mean_reliability'] * 100:<20.4f}"
            f"{item['stable_95']:<12}"
        )

    print()

    best = ranking[0]

    print(
        "Best region by measured reset stability: "
        + str(best["region"])
    )

    print(
        "Mean pairwise BER: "
        + f"{best['mean_ber'] * 100:.4f}%"
    )

    print()

    print(
        "IMPORTANT:"
    )

    print(
        "This ranking measures intra-device "
        "reset stability only."
    )

    print(
        "It does NOT demonstrate inter-device uniqueness."
    )

    return ranking


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print(
        "ESP32 SRAM-PUF BIT-LEVEL ANALYSIS"
    )

    print("=" * 70)

    print(
        "Captures : "
        + str(NUM_CAPTURES)
    )

    print(
        "Regions  : "
        + str(REGIONS)
    )

    print(
        "Size     : "
        + str(REGION_SIZE_BITS)
        + " bits/region"
    )

    print(
        "Input    : "
        + str(CAPTURE_DIR)
    )

    print(
        "Output   : "
        + str(OUTPUT_DIR)
    )

    print("=" * 70)

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Load captures
    # --------------------------------------------------------

    data = load_captures()

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    results = {}

    for region in REGIONS:

        results[region] = (
            analyze_region(
                region,
                data[region]
            )
        )

    # --------------------------------------------------------
    # Save files
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("SAVING RESULTS")
    print("=" * 70)

    for region in REGIONS:

        result = results[region]

        reliability_file = (
            save_reliability_csv(
                region,
                result
            )
        )

        hamming_file = (
            OUTPUT_DIR
            / (
                "hamming_matrix_region"
                + str(region)
                + ".csv"
            )
        )

        save_matrix_csv(
            hamming_file,
            result["hamming_matrix"]
        )

        ber_file = (
            save_ber_csv(
                region,
                result
            )
        )

        print()
        print(
            "Region "
            + str(region)
            + ":"
        )

        print(
            "  "
            + str(reliability_file)
        )

        print(
            "  "
            + str(hamming_file)
        )

        print(
            "  "
            + str(ber_file)
        )

    # --------------------------------------------------------
    # Text report
    # --------------------------------------------------------

    report_file = (
        save_statistics_report(
            results
        )
    )

    print()
    print(
        "Statistics report:"
    )

    print(
        "  "
        + str(report_file)
    )

    # --------------------------------------------------------
    # Plots
    # --------------------------------------------------------

    create_plots(
        results
    )

    # --------------------------------------------------------
    # Ranking
    # --------------------------------------------------------

    rank_regions(
        results
    )

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)

    for region in REGIONS:

        result = results[region]

        mean_ber = (
            result["ber_stats"]
            ["mean"]
            * 100
        )

        max_ber = (
            result["ber_stats"]
            ["max"]
            * 100
        )

        mean_reliability = (
            np.mean(
                result["reliability"]
                ["reliability"]
            )
            * 100
        )

        stable_95 = (
            result["stable_counts"]
            [0.95]
        )

        print()
        print(
            "Region "
            + str(region)
        )

        print(
            "  Mean pairwise BER    : "
            + f"{mean_ber:.4f}%"
        )

        print(
            "  Maximum pairwise BER : "
            + f"{max_ber:.4f}%"
        )

        print(
            "  Mean bit reliability : "
            + f"{mean_reliability:.4f}%"
        )

        print(
            "  Bits >= 95%          : "
            + str(stable_95)
            + "/"
            + str(REGION_SIZE_BITS)
        )

    print()
    print("=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)

    print()
    print(
        "Results saved in:"
    )

    print(
        "  "
        + str(OUTPUT_DIR)
    )

    print()
    print(
        "These are RESET-capture measurements."
    )

    print(
        "They characterize intra-device stability."
    )

    print(
        "They do not establish inter-device uniqueness."
    )

    print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
