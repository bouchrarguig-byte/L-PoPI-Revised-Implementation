#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime, timezone
import argparse
import csv
import socket
import time

ROOT = Path(__file__).resolve().parents[2]

parser = argparse.ArgumentParser()

parser.add_argument(
    "--port",
    type=int,
    default=5005,
)

parser.add_argument(
    "--out",
    type=Path,
    default=(
        ROOT
        / "j5_ai/results/online_windowed/"
          "esp32_connectivity/receiver.csv"
    ),
)

args = parser.parse_args()

args.out.parent.mkdir(
    parents=True,
    exist_ok=True,
)

sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM,
)

sock.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_RCVBUF,
    1024 * 1024,
)

sock.bind(
    ("0.0.0.0", args.port)
)

exists = args.out.exists()

f = args.out.open(
    "a",
    newline="",
    encoding="utf-8",
)

writer = csv.DictWriter(
    f,
    fieldnames=[
        "timestamp_utc",
        "timestamp_ns",
        "src_ip",
        "src_port",
        "bytes",
        "device",
        "phase",
        "seq",
        "payload",
    ],
)

if not exists:
    writer.writeheader()
    f.flush()

print(
    "\n===== L-PoPI ESP32 UDP RECEIVER ====="
)

print(
    "listen = 0.0.0.0:%d" % args.port
)

print(
    "log    =",
    args.out,
)

print(
    "\nUDP_RECEIVER_READY"
)

try:

    while True:

        data, addr = sock.recvfrom(
            65535
        )

        now_ns = time.time_ns()

        now_utc = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )

        text = data.decode(
            "utf-8",
            errors="replace",
        )

        fields = {}

        for part in text.split("|")[1:]:

            if "=" not in part:
                continue

            k, v = part.split(
                "=",
                1,
            )

            fields[k] = v

        device = fields.get(
            "device",
            "",
        )

        phase = fields.get(
            "phase",
            "",
        )

        seq = fields.get(
            "seq",
            "",
        )

        writer.writerow({
            "timestamp_utc":
                now_utc,

            "timestamp_ns":
                now_ns,

            "src_ip":
                addr[0],

            "src_port":
                addr[1],

            "bytes":
                len(data),

            "device":
                device,

            "phase":
                phase,

            "seq":
                seq,

            "payload":
                text,
        })

        f.flush()

        ack = (
            f"ACK|seq={seq}|"
            f"server_ns={now_ns}"
        ).encode()

        sock.sendto(
            ack,
            addr,
        )

        print(
            f"{now_utc} | "
            f"{addr[0]}:{addr[1]} | "
            f"bytes={len(data)} | "
            f"device={device} | "
            f"phase={phase} | "
            f"seq={seq} | ACK"
        )

except KeyboardInterrupt:

    print(
        "\nUDP_RECEIVER_STOPPED_OK"
    )

finally:

    f.close()
    sock.close()
