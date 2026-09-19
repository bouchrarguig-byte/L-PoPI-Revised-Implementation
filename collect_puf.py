#!/usr/bin/env python3

import csv
import os
import re
import time
from datetime import datetime

import serial
from serial.tools import list_ports


# ============================================================
# Configuration
# ============================================================

PORT = "/dev/ttyUSB0"
BAUD = 115200

NUM_CAPTURES = 30

NUM_REGIONS = 1
REGION_SIZE = 256

# Region 0 contains deterministic bootloader strings.
# We still capture it for diagnostics, but it is NOT included
# in the PUF statistical analysis.
PUF_REGIONS = [1]

OUTPUT_DIR = "puf_results"

RECONNECT_TIMEOUT = 30
CAPTURE_TIMEOUT = 15


# ============================================================
# Helpers
# ============================================================

def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("Responses have different lengths")

    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def bit_reliability(responses):
    """
    For each bit position, calculate the fraction of samples
    that agree with the majority value.

    Returns:
        average reliability,
        list of per-bit reliabilities
    """

    if not responses:
        return 0.0, []

    nbits = len(responses[0]) * 8
    reliabilities = []

    for bit_index in range(nbits):

        byte_index = bit_index // 8
        bit_in_byte = 7 - (bit_index % 8)

        ones = 0

        for response in responses:
            ones += (
                (response[byte_index] >> bit_in_byte) & 1
            )

        zeros = len(responses) - ones

        majority = max(ones, zeros)

        reliability = majority / len(responses)

        reliabilities.append(reliability)

    average = sum(reliabilities) / len(reliabilities)

    return average, reliabilities


def bit_bias(responses):
    """
    Fraction of bits that are 1 across all responses.
    """

    if not responses:
        return 0.0

    total_ones = 0
    total_bits = 0

    for response in responses:

        for byte in response:
            total_ones += byte.bit_count()
            total_bits += 8

    return total_ones / total_bits


def calculate_pairwise_stats(responses):

    distances = []

    for i in range(len(responses)):
        for j in range(i + 1, len(responses)):

            hd = hamming_distance(
                responses[i],
                responses[j]
            )

            distances.append(hd)

    if not distances:
        return 0.0, 0, 0

    return (
        sum(distances) / len(distances),
        min(distances),
        max(distances),
    )


# ============================================================
# Serial connection
# ============================================================

def wait_for_port():

    print(
        f"[+] Waiting for {PORT} "
        f"(timeout {RECONNECT_TIMEOUT}s)..."
    )

    deadline = time.time() + RECONNECT_TIMEOUT

    while time.time() < deadline:

        if os.path.exists(PORT):

            try:

                ser = serial.Serial(
                    PORT,
                    BAUD,
                    timeout=0.2
                )

                print("[+] Serial port connected")

                # Clear stale data.
                

                return ser

            except serial.SerialException:
                pass

        time.sleep(0.5)

    return None


# ============================================================
# Capture parser
# ============================================================

def read_capture(ser, capture_number):

    print()
    print("=" * 72)
    print(
        f"CAPTURE {capture_number}/{NUM_CAPTURES}"
    )
    print("=" * 72)

    print("[+] Waiting for PUF_CAPTURE_START")

    deadline = time.time() + CAPTURE_TIMEOUT

    started = False
    regions = {}

    while time.time() < deadline:

        try:
            line = ser.readline()

        except (serial.SerialException, OSError):

            print(
                "[!] Serial device disappeared "
                "during capture."
            )

            try:
                ser.close()
            except Exception:
                pass

            return None, "disconnect"

        if not line:
            continue

        text = line.decode(
            "ascii",
            errors="replace"
        ).strip()

        if text == "PUF_CAPTURE_START":

            started = True

            print("[+] PUF capture started")

            continue

        if not started:
            continue

        # ----------------------------------------------------
        # Region declaration
        # ----------------------------------------------------

        match = re.match(
            r"PUF_REGION_START,(\d+),(0x[0-9A-Fa-f]+),(\d+)",
            text
        )

        if match:

            region = int(match.group(1))
            address = match.group(2)
            size = int(match.group(3))

            print(
                f"[+] Region {region}: "
                f"{address}, {size} bytes"
            )

            continue

        # ----------------------------------------------------
        # Region data
        # ----------------------------------------------------

        if text.startswith("PUF_DATA,"):

            parts = text.split(",", 2)

            if len(parts) != 3:

                print(
                    "[!] Invalid PUF_DATA line"
                )

                continue

            region = int(parts[1])
            hex_data = parts[2].strip()

            try:
                data = bytes.fromhex(hex_data)

            except ValueError:

                print(
                    f"[!] Invalid hexadecimal data "
                    f"for region {region}"
                )

                return None, "invalid_data"

            if len(data) != REGION_SIZE:

                print(
                    f"[!] Region {region}: "
                    f"expected {REGION_SIZE} bytes, "
                    f"received {len(data)}"
                )

                return None, "invalid_size"

            regions[region] = data

            print(
                f"[+] Region {region}: "
                f"{len(data)} bytes received"
            )

            continue

        # ----------------------------------------------------
        # End of capture
        # ----------------------------------------------------

        if text == "PUF_CAPTURE_END":

            print("[+] PUF capture completed")

            missing = [
                r for r in PUF_REGIONS
                if r not in regions
            ]

            if missing:

                print(
                    "[!] Missing regions:",
                    missing
                )

                return None, "missing_region"

            return regions, "success"

    print(
        f"[!] Timeout waiting for capture "
        f"#{capture_number}"
    )

    return None, "timeout"


# ============================================================
# Save raw capture
# ============================================================

def save_raw_capture(
    capture_number,
    regions
):

    filename = os.path.join(
        OUTPUT_DIR,
        f"capture_{capture_number:03d}.txt"
    )

    with open(filename, "w") as f:

        f.write(
            f"CAPTURE,{capture_number}\n"
        )

        f.write(
            f"TIMESTAMP,"
            f"{datetime.now().isoformat()}\n"
        )

        for region in PUF_REGIONS:

            address = (
                0x3FFF1000 +
                region * 0x1000
            )

            data = regions[region]

            f.write(
                f"REGION,{region},"
                f"0x{address:08X},"
                f"{len(data)}\n"
            )

            f.write(
                data.hex().upper()
                + "\n"
            )

    return filename


# ============================================================
# Save CSV
# ============================================================

def save_csv(results):

    filename = os.path.join(
        OUTPUT_DIR,
        "puf_measurements.csv"
    )

    with open(
        filename,
        "w",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "capture",
            "region",
            "bytes",
            "bits",
            "HD_vs_capture_1",
            "BER_vs_capture_1"
        ])

        for row in results:

            writer.writerow(row)

    return filename


# ============================================================
# Main
# ============================================================

def main():

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    print("=" * 72)
    print(
        "L-POPI AUTOMATED SRAM PUF COLLECTOR"
    )
    print("=" * 72)

    print(f"Port: {PORT}")
    print(f"Captures requested: {NUM_CAPTURES}")
    print(f"Regions per capture: {NUM_REGIONS}")
    print(f"Bytes per region: {REGION_SIZE}")

    print()
    print(
        "IMPORTANT:"
    )
    print(
        "After every successful capture, "
        "perform a COMPLETE POWER CYCLE."
    )
    print(
        "Do NOT simply press the ESP32 reset button."
    )

    print()
    input("Press ENTER to start...")

    all_captures = {
        region: []
        for region in PUF_REGIONS
    }

    csv_results = []

    capture_number = 1

    while capture_number <= NUM_CAPTURES:

        ser = wait_for_port()

        if ser is None:

            print(
                "[!] Serial port did not appear."
            )

            print(
                "[!] Check USB connection."
            )

            break

        regions, status = read_capture(
            ser,
            capture_number
        )

        try:
            ser.close()
        except Exception:
            pass

        # ----------------------------------------------------
        # Failed capture
        # ----------------------------------------------------

        if regions is None:

            print(
                f"[!] Capture {capture_number} "
                f"failed: {status}"
            )

            print(
                "[+] Waiting for the ESP32 "
                "to reconnect..."
            )

            continue

        # ----------------------------------------------------
        # Save capture
        # ----------------------------------------------------

        filename = save_raw_capture(
            capture_number,
            regions
        )

        print(
            f"[+] Raw capture saved: {filename}"
        )

        # ----------------------------------------------------
        # Store PUF regions
        # ----------------------------------------------------

        for region in PUF_REGIONS:

            all_captures[region].append(
                regions[region]
            )

        # ----------------------------------------------------
        # Statistics against capture #1
        # ----------------------------------------------------

        for region in PUF_REGIONS:

            response = regions[region]

            reference = all_captures[region][0]

            hd = hamming_distance(
                reference,
                response
            )

            bits = REGION_SIZE * 8

            ber = hd / bits

            csv_results.append([
                capture_number,
                region,
                REGION_SIZE,
                bits,
                hd,
                f"{ber:.8f}"
            ])

            print(
                f"    Region {region}: "
                f"HD={hd}/{bits}, "
                f"BER={ber * 100:.4f}%"
            )

        # ----------------------------------------------------
        # Save CSV
        # ----------------------------------------------------

        csv_file = save_csv(
            csv_results
        )

        print(
            f"[+] CSV updated: {csv_file}"
        )

        # ----------------------------------------------------
        # Capture complete
        # ----------------------------------------------------

        if capture_number == NUM_CAPTURES:

            break

        print()
        print("=" * 72)
        print(
            "POWER CYCLE REQUIRED"
        )
        print("=" * 72)

        print(
            "1. Disconnect ESP32 USB power."
        )
        print(
            "2. Wait 5–10 seconds."
        )
        print(
            "3. Reconnect USB."
        )

        input(
            "Press ENTER after reconnecting "
            "the ESP32..."
        )

        capture_number += 1

    # ========================================================
    # Final statistics
    # ========================================================

    print()
    print("=" * 72)
    print("FINAL PUF STATISTICS")
    print("=" * 72)

    for region in PUF_REGIONS:

        responses = all_captures[region]

        if not responses:
            continue

        print()
        print(
            f"REGION {region}"
        )

        print(
            f"Samples: {len(responses)}"
        )

        # ----------------------------------------------------
        # HD vs first
        # ----------------------------------------------------

        reference = responses[0]

        hds = [
            hamming_distance(
                reference,
                r
            )
            for r in responses
        ]

        bits = REGION_SIZE * 8

        print(
            "HD vs Capture #1:"
        )

        print(
            "  "
            + ", ".join(
                str(x)
                for x in hds
            )
        )

        print(
            f"Average HD vs #1: "
            f"{sum(hds) / len(hds):.2f} "
            f"/ {bits}"
        )

        print(
            f"Average BER vs #1: "
            f"{(sum(hds) / len(hds)) / bits * 100:.4f}%"
        )

        # ----------------------------------------------------
        # Pairwise HD
        # ----------------------------------------------------

        avg_hd, min_hd, max_hd = (
            calculate_pairwise_stats(
                responses
            )
        )

        print(
            f"Pairwise average HD: "
            f"{avg_hd:.2f}/{bits}"
        )

        print(
            f"Pairwise minimum HD: "
            f"{min_hd}/{bits}"
        )

        print(
            f"Pairwise maximum HD: "
            f"{max_hd}/{bits}"
        )

        print(
            f"Pairwise mean BER: "
            f"{avg_hd / bits * 100:.4f}%"
        )

        # ----------------------------------------------------
        # Reliability
        # ----------------------------------------------------

        reliability, _ = (
            bit_reliability(
                responses
            )
        )

        print(
            f"Average bit reliability: "
            f"{reliability * 100:.4f}%"
        )

        # ----------------------------------------------------
        # Bias
        # ----------------------------------------------------

        bias = bit_bias(
            responses
        )

        print(
            f"Bit-1 bias: "
            f"{bias * 100:.4f}%"
        )

    print()
    print("=" * 72)
    print("COLLECTION FINISHED")
    print("=" * 72)

    print(
        f"Results directory: "
        f"{os.path.abspath(OUTPUT_DIR)}"
    )


if __name__ == "__main__":
    main()
