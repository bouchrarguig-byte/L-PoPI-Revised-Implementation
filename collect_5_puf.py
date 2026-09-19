import serial
import time
import os
import re

PORT = "/dev/ttyUSB0"
BAUD = 115200

N = 5
SIZE = 256

regions = {
    1: [],
    2: [],
    3: []
}


def wait_for_capture(ser, number):

    print()
    print("=" * 70)
    print(f"WAITING FOR POWER-UP CAPTURE {number}/{N}")
    print("=" * 70)

    started = False
    data = {}

    while True:

        try:
            line = ser.readline()

        except Exception as e:
            print("Serial error:", e)
            return None

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

        m = re.match(
            r"PUF_DATA,(\d+),([0-9A-Fa-f]+)",
            text
        )

        if m:

            region = int(m.group(1))
            hex_data = m.group(2)

            try:
                raw = bytes.fromhex(hex_data)
            except ValueError:
                print("[!] Invalid hexadecimal data")
                continue

            if len(raw) == SIZE:
                data[region] = raw
                print(
                    f"[+] Region {region}: "
                    f"{len(raw)} bytes"
                )

        if text == "PUF_CAPTURE_END":

            print("[+] PUF_CAPTURE_END")

            for r in [1, 2, 3]:

                if r not in data:
                    print(
                        f"[!] Missing region {r}"
                    )
                    return None

            return data


def hd(a, b):

    return sum(
        (x ^ y).bit_count()
        for x, y in zip(a, b)
    )


def save_capture(number, data):

    os.makedirs(
        "puf_results",
        exist_ok=True
    )

    filename = (
        f"puf_results/"
        f"capture_{number:02d}.txt"
    )

    with open(filename, "w") as f:

        f.write(
            f"CAPTURE {number}\n"
        )

        for r in [1, 2, 3]:

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
print("L-POPI SRAM PUF — CONTROLLED POWER-UP COLLECTION")
print("=" * 70)

print()
print("IMPORTANT:")
print("The ESP32 must be physically POWERED OFF now.")
print()
input(
    "Press ENTER when the ESP32 is disconnected..."
)

print()
print(
    "Now connect the ESP32 USB cable."
)
print(
    "The script will wait for /dev/ttyUSB0."
)

while not os.path.exists(PORT):
    time.sleep(0.2)

print("[+] /dev/ttyUSB0 detected")

ser = serial.Serial(
    PORT,
    BAUD,
    timeout=0.2
)

print("[+] Serial opened")

# Do NOT reset_input_buffer().
# Early boot data may already be waiting here.

for capture in range(1, N + 1):

    data = wait_for_capture(
        ser,
        capture
    )

    if data is None:
        print(
            "[!] Capture failed."
        )
        break

    save_capture(
        capture,
        data
    )

    for r in [1, 2, 3]:
        regions[r].append(data[r])

    print()
    print(
        f"SUCCESSFUL CAPTURE {capture}/{N}"
    )

    if capture < N:

        print()
        print("=" * 70)
        print("NOW PERFORM A COMPLETE POWER CYCLE")
        print("=" * 70)
        print()
        print("1. Disconnect USB.")
        print("2. Wait 10 seconds.")
        print("3. Reconnect USB.")
        print()
        input(
            "Press ENTER after reconnecting..."
        )

        # Wait until USB serial disappears,
        # then reappears.
        while os.path.exists(PORT):
            time.sleep(0.2)

        print("[+] USB serial disappeared")

        while not os.path.exists(PORT):
            time.sleep(0.2)

        print("[+] USB serial reappeared")

        try:
            ser.close()
        except:
            pass

        ser = serial.Serial(
            PORT,
            BAUD,
            timeout=0.2
        )

        print("[+] Serial reopened")


ser.close()

print()
print("=" * 70)
print("PRELIMINARY RESULTS")
print("=" * 70)

for r in [1, 2, 3]:

    samples = regions[r]

    if len(samples) < 2:
        continue

    print()
    print(f"REGION {r}")
    print("-" * 40)

    reference = samples[0]

    hds = []

    for i, sample in enumerate(samples):

        distance = hd(
            reference,
            sample
        )

        hds.append(distance)

        print(
            f"Capture {i + 1}: "
            f"HD = {distance}/2048 "
            f"BER = {distance / 2048 * 100:.3f}%"
        )

    print(
        f"Average HD vs capture 1: "
        f"{sum(hds) / len(hds):.2f}/2048"
    )

print()
print("=" * 70)
print("COLLECTION FINISHED")
print("=" * 70)
