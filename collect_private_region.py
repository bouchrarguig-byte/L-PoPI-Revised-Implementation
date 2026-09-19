#!/usr/bin/env python3
"""Collect a single, private debug SRAM region for characterization.

Run only while CONFIG_LPOFI_PUF_DEBUG_CAPTURE is enabled on a trusted host.
Do not upload the output or paste the PUF_DATA lines into chats or reports.
"""

import argparse
import re
import time
from pathlib import Path

import serial


def wait_for_capture(port, region, size):
    started, data = False, None
    while True:
        line = port.readline().decode("ascii", errors="replace").strip()
        if line == "PUF_CAPTURE_START":
            started = True
        elif started:
            match = re.fullmatch(r"PUF_DATA,(\d+),([0-9A-Fa-f]+)", line)
            if match and int(match.group(1)) == region:
                candidate = bytes.fromhex(match.group(2))
                if len(candidate) == size:
                    data = candidate
            elif line == "PUF_CAPTURE_END":
                return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True)
    parser.add_argument("--region", type=int, required=True)
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--size", type=int, default=256)
    parser.add_argument("--output", type=Path, default=Path("puf_private_results"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    with serial.Serial(args.port, 115200, timeout=0.25) as port:
        print("Press EN/RESET for each capture. Keep output private.")
        for number in range(1, args.count + 1):
            input(f"[{number}/{args.count}] Press Enter, then press EN/RESET: ")
            capture = wait_for_capture(port, args.region, args.size)
            if capture is None:
                raise SystemExit("Capture missing or invalid; retry this run.")
            path = args.output / f"reset_capture_{number:02d}.txt"
            path.write_text(f"RESET CAPTURE {number}\nREGION {args.region}\n{capture.hex().upper()}\n")
            print(f"Saved {path}")
            time.sleep(0.1)


if __name__ == "__main__":
    main()
