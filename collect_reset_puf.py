import serial
import time
import os
import re

PORT = "/dev/ttyUSB1"
BAUD = 115200

N = 30
SIZE = 256

REGIONS = [1, 2, 3]

os.makedirs("puf_results", exist_ok=True)


def hamming_distance(a, b):
    return sum(
        (x ^ y).bit_count()
        for x, y in zip(a, b)
    )


def wait_for_capture(ser, number):

    print()
    print("=" * 70)
    print(f"WAITING FOR RESET CAPTURE {number}/{N}")
    print("=" * 70)

    started = False
    data = {}

    while True:

        line = ser.readline()

        if not line:
            continue

        text = line.decode(
            "ascii",
            errors="replace"
        ).strip()

        if text == "PUF_CAPTURE_START":
            started = True
            print("[+] PUF_CAPTURE_START")
            continue

        if not started:
            continue

        match = re.match(
            r"PUF_DATA,(\d+),([0-9A-Fa-f]+)",
            text
        )

        if match:

            region = int(match.group(1))
            hex_data = match.group(2)

            try:
                raw = bytes.fromhex(hex_data)
            except ValueError:
                print("[!] Invalid hex data")
                continue

            if len(raw) == SIZE:

                data[region] = raw

                print(
                    f"[+] Region {region}: "
                    f"{len(raw)} bytes"
                )

        if text == "PUF_CAPTURE_END":

            print("[+] PUF_CAPTURE_END")

            missing = [
                r for r in REGIONS
                if r not in data
            ]

            if missing:

                print(
                    "[!] Missing:",
                    missing
                )

                return None

            return data


def save_capture(number, data):

    filename = (
        f"puf_results/"
        f"reset_capture_{number:02d}.txt"
    )

    with open(filename, "w") as f:

        f.write(
            f"RESET CAPTURE {number}\n"
        )

        for r in REGIONS:

            f.write(
                f"REGION {r}\n"
            )

            f.write(
                data[r].hex().upper()
                + "\n"
            )

    print(
        f"[+] Saved {filename}"
    )


print("=" * 70)
print("L-POPI SRAM PUF — RESET CHARACTERIZATION")
print("=" * 70)

print()
print("IMPORTANT:")
print()
print("Keep the ESP32 USB cable CONNECTED.")
print("Do NOT disconnect USB.")
print()
print("For every sample:")
print("  1. Wait for the program.")
print("  2. Press EN/RESET once.")
print("  3. Wait for the capture.")
print()
print("These are RESET captures, not cold-power captures.")
print()

input(
    "Press ENTER when ready..."
)

ser = serial.Serial(
    PORT,
    BAUD,
    timeout=0.2
)

print("[+] Serial port opened")

# Important:
# Do NOT clear the input buffer.

captures = {
    r: []
    for r in REGIONS
}

for number in range(1, N + 1):

    print()
    print("=" * 70)
    print(f"PRESS EN/RESET NOW — CAPTURE {number}/{N}")
    print("=" * 70)

    input(
        "Press ENTER, then immediately press EN/RESET..."
    )

    data = wait_for_capture(
        ser,
        number
    )

    if data is None:

        print(
            "[!] Capture failed."
        )

        continue

    save_capture(
        number,
        data
    )

    for r in REGIONS:
        captures[r].append(data[r])

    print()
    print(
        f"[+] SUCCESSFUL CAPTURE "
        f"{number}/{N}"
    )


ser.close()


# ============================================================
# Analysis
# ============================================================

print()
print("=" * 70)
print("RESET CHARACTERIZATION RESULTS")
print("=" * 70)

for r in REGIONS:

    samples = captures[r]

    if len(samples) < 2:
        continue

    print()
    print(
        f"REGION {r}"
    )
    print("-" * 50)

    reference = samples[0]

    hds = []

    for i, sample in enumerate(samples):

        distance = hamming_distance(
            reference,
            sample
        )

        hds.append(distance)

        print(
            f"Capture {i+1}: "
            f"HD={distance}/2048 "
            f"BER={distance/2048*100:.3f}%"
        )

    print()
    print(
        f"Average HD vs Capture 1: "
        f"{sum(hds)/len(hds):.2f}/2048"
    )

    print(
        f"Average BER: "
        f"{sum(hds)/len(hds)/2048*100:.3f}%"
    )

    # Pairwise distances

    pairwise = []

    for i in range(len(samples)):

        for j in range(i + 1, len(samples)):

            pairwise.append(
                hamming_distance(
                    samples[i],
                    samples[j]
                )
            )

    if pairwise:

        print(
            f"Pairwise mean HD: "
            f"{sum(pairwise)/len(pairwise):.2f}/2048"
        )

        print(
            f"Pairwise mean BER: "
            f"{sum(pairwise)/len(pairwise)/2048*100:.3f}%"
        )

print()
print("=" * 70)
print("DONE")
print("=" * 70)
