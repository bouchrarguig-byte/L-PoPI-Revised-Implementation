#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime, timezone
import argparse
import csv
import hashlib
import json
import os
import resource
import subprocess
import tempfile
import time
import traceback

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F

from torch_geometric.data import Data
from torch_geometric.nn import GATv2Conv


# ============================================================
# PATHS
# ============================================================

HERE = Path(__file__).resolve()
REPO = HERE.parents[2]

J5 = REPO / "j5_ai"
RESULTS = J5 / "results" / "online_windowed"

POLICY_FILE = RESULTS / "deployment_policy_frozen_0512.json"

EXTRACTOR_FILE = (
    RESULTS / "deployment_extractor_frozen_argus5.json"
)

ARGUS_BIN = (
    REPO / "tools/argus5/src/argus/bin/argus"
)

RA_BIN = (
    REPO / "tools/argus5/src/clients/bin/ra"
)


# ============================================================
# UTILS
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for block in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(block)

    return h.hexdigest()


def current_rss_mb():

    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    kb = float(
                        line.split()[1]
                    )
                    return kb / 1024.0
    except Exception:
        pass

    return float("nan")


def cpu_seconds_self_children():

    me = resource.getrusage(
        resource.RUSAGE_SELF
    )

    children = resource.getrusage(
        resource.RUSAGE_CHILDREN
    )

    return (
        me.ru_utime
        + me.ru_stime
        + children.ru_utime
        + children.ru_stime
    )


def read_host_cpu_counters():

    with open("/proc/stat", "r") as f:
        fields = f.readline().split()[1:]

    values = [
        float(x)
        for x in fields
    ]

    total = sum(values)

    idle = (
        values[3]
        +
        (
            values[4]
            if len(values) > 4
            else 0.0
        )
    )

    return total, idle


def host_cpu_percent(before, after):

    total0, idle0 = before
    total1, idle1 = after

    dt = total1 - total0
    di = idle1 - idle0

    if dt <= 0:
        return float("nan")

    return (
        100.0
        * (dt - di)
        / dt
    )


def host_mem_used_mb():

    values = {}

    with open("/proc/meminfo", "r") as f:

        for line in f:

            key, rest = line.split(
                ":",
                1,
            )

            values[key] = float(
                rest.strip().split()[0]
            )

    total = values.get(
        "MemTotal",
        0.0,
    )

    available = values.get(
        "MemAvailable",
        0.0,
    )

    return (
        total - available
    ) / 1024.0


def child_peak_rss_mb():

    r = resource.getrusage(
        resource.RUSAGE_CHILDREN
    )

    # Linux ru_maxrss is KiB.
    return float(
        r.ru_maxrss
    ) / 1024.0


def append_csv(path, row):

    path = Path(path)

    exists = path.exists()

    with path.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=list(row.keys()),
        )

        if not exists:
            writer.writeheader()

        writer.writerow(row)


# ============================================================
# MODEL — EXACT TRAINING ARCHITECTURE
# ============================================================

class OnlineGATv2(torch.nn.Module):

    def __init__(self):

        super().__init__()

        self.conv1 = GATv2Conv(
            3,
            16,
            heads=4,
            concat=True,
            dropout=0.2,
        )

        self.conv2 = GATv2Conv(
            64,
            16,
            heads=2,
            concat=True,
            dropout=0.2,
        )

        self.out = GATv2Conv(
            32,
            2,
            heads=1,
            concat=False,
            dropout=0.0,
        )

    def forward(self, data):

        x = data.x
        e = data.edge_index

        x = F.elu(
            self.conv1(x, e)
        )

        x = F.dropout(
            x,
            p=0.2,
            training=self.training,
        )

        x = F.elu(
            self.conv2(x, e)
        )

        x = F.dropout(
            x,
            p=0.2,
            training=self.training,
        )

        return self.out(x, e)


# ============================================================
# FROZEN POLICY
# ============================================================

def load_frozen_policy():

    if not POLICY_FILE.exists():
        raise FileNotFoundError(
            POLICY_FILE
        )

    policy = json.loads(
        POLICY_FILE.read_text(
            encoding="utf-8"
        )
    )

    if (
        policy.get("policy_status")
        !=
        "FROZEN_FOR_PROSPECTIVE_LIVE_GATEWAY_EVALUATION"
    ):
        raise RuntimeError(
            "Frozen deployment policy "
            "status is invalid."
        )

    cog = policy["coggat"]

    if float(cog["threshold"]) != 0.512:
        raise RuntimeError(
            "Unexpected frozen threshold."
        )

    if float(cog["alpha"]) != 0.1:
        raise RuntimeError(
            "Unexpected alpha."
        )

    if float(cog["lambda"]) != 0.8:
        raise RuntimeError(
            "Unexpected lambda."
        )

    model_path = (
        REPO
        / policy["model"]["checkpoint"]
    )

    scaler_path = (
        REPO
        / policy["model"]["scaler"]
    )

    if not model_path.exists():
        raise FileNotFoundError(
            model_path
        )

    if not scaler_path.exists():
        raise FileNotFoundError(
            scaler_path
        )

    frozen_hashes = policy["sha256"]

    expected_model = frozen_hashes[
        "best_online_gatv2.pt"
    ]

    expected_scaler = frozen_hashes[
        "online_train_only_scaler.joblib"
    ]

    actual_model = sha256_file(
        model_path
    )

    actual_scaler = sha256_file(
        scaler_path
    )

    if actual_model != expected_model:
        raise RuntimeError(
            "MODEL SHA256 MISMATCH"
        )

    if actual_scaler != expected_scaler:
        raise RuntimeError(
            "SCALER SHA256 MISMATCH"
        )

    return (
        policy,
        model_path,
        scaler_path,
    )


# ============================================================
# ARGUS / RA
# ============================================================

def parse_numeric(value):

    value = str(value).strip()

    if not value:
        return np.nan

    multipliers = {
        "K": 1e3,
        "M": 1e6,
        "G": 1e9,
        "k": 1e3,
        "m": 1e6,
        "g": 1e9,
    }

    last = value[-1]

    if last in multipliers:

        try:
            return (
                float(value[:-1])
                * multipliers[last]
            )
        except Exception:
            return np.nan

    try:
        return float(value)
    except Exception:
        return np.nan


def pcap_to_flows(pcap_path):

    pcap_path = Path(pcap_path)

    argus_start = time.perf_counter()

    with tempfile.TemporaryDirectory(
        prefix="lpopi_argus_"
    ) as tmp:

        tmp = Path(tmp)

        argus_file = (
            tmp / "window.argus"
        )

        cmd_argus = [
            str(ARGUS_BIN),
            "-r",
            str(pcap_path),
            "-w",
            str(argus_file),
        ]

        proc = subprocess.run(
            cmd_argus,
            capture_output=True,
            text=True,
        )

        if proc.returncode != 0:
            raise RuntimeError(
                "ARGUS FAILED:\n"
                + proc.stderr
            )

        cmd_ra = [
            str(RA_BIN),
            "-n",
            "-L",
            "-1",
            "-r",
            str(argus_file),
            "-s",
            "proto",
            "saddr:64",
            "daddr:64",
            "pkts",
            "bytes",
            "dur",
            "-c",
            ",",
        ]

        proc = subprocess.run(
            cmd_ra,
            capture_output=True,
            text=True,
        )

        if proc.returncode != 0:
            raise RuntimeError(
                "RA FAILED:\n"
                + proc.stderr
            )

        raw_lines = [
            x.strip()
            for x in proc.stdout.splitlines()
            if x.strip()
        ]

    argus_ms = (
        time.perf_counter()
        - argus_start
    ) * 1000.0

    rows = []

    for source_row, line in enumerate(
        raw_lines
    ):

        parts = [
            x.strip()
            for x in line.split(",")
        ]

        if len(parts) < 6:
            continue

        proto = str(parts[0]).strip().lower()

        # Never feed Argus management records into the ML model.
        if proto == "man":
            continue

        saddr = parts[1]
        daddr = parts[2]

        pkts = parse_numeric(
            parts[3]
        )

        byt = parse_numeric(
            parts[4]
        )

        dur = parse_numeric(
            parts[5]
        )

        if (
            not np.isfinite(pkts)
            or
            not np.isfinite(byt)
            or
            not np.isfinite(dur)
        ):
            continue

        rows.append({
            "source_row":
                int(source_row),

            "proto":
                proto,

            "saddr":
                str(saddr),

            "daddr":
                str(daddr),

            "pkts":
                float(pkts),

            "bytes":
                float(byt),

            "dur":
                float(dur),
        })

    return (
        pd.DataFrame(rows),
        argus_ms,
    )


# ============================================================
# GRAPH — SAME CONNECTIVITY AS TRAINING
# ============================================================

def build_graph(flow_df, scaler):

    if len(flow_df) == 0:
        return None

    raw = flow_df[
        [
            "pkts",
            "bytes",
            "dur",
        ]
    ].to_numpy(
        dtype=np.float64
    )

    z = scaler.transform(raw)

    x = torch.tensor(
        z,
        dtype=torch.float32,
    )

    src = []
    dst = []

    prev_s = {}
    prev_d = {}

    for idx, row in (
        flow_df
        .reset_index(drop=True)
        .iterrows()
    ):

        s = str(row["saddr"])
        d = str(row["daddr"])

        if s in prev_s:

            j = prev_s[s]

            src.extend(
                [j, idx]
            )

            dst.extend(
                [idx, j]
            )

        if d in prev_d:

            j = prev_d[d]

            if j != idx:

                src.extend(
                    [j, idx]
                )

                dst.extend(
                    [idx, j]
                )

        prev_s[s] = idx
        prev_d[d] = idx

    if src:

        edge_index = torch.tensor(
            [src, dst],
            dtype=torch.long,
        )

    else:

        edge_index = torch.empty(
            (2, 0),
            dtype=torch.long,
        )

    return Data(
        x=x,
        edge_index=edge_index,
    )


# ============================================================
# FROZEN CAUSAL COG-GAT
# ============================================================

class CausalCogGAT:

    def __init__(
        self,
        alpha,
        lam,
        threshold,
    ):

        self.alpha = float(alpha)
        self.lam = float(lam)
        self.threshold = float(
            threshold
        )

        # Continuous live session state.
        # Reset only when the gateway
        # process/session is restarted.
        self.state = {}

    def apply(
        self,
        flow_df,
        gat_prob,
    ):

        scores = []
        preds = []

        histories = []
        seen_values = []

        for i, row in (
            flow_df
            .reset_index(drop=True)
            .iterrows()
        ):

            src = str(
                row["saddr"]
            )

            p = float(
                gat_prob[i]
            )

            if src in self.state:

                seen = 1

                hist = float(
                    self.state[src]
                )

                score = (
                    (1.0 - self.lam) * p
                    + self.lam * hist
                )

                self.state[src] = (
                    self.alpha * p
                    +
                    (1.0 - self.alpha)
                    * self.state[src]
                )

            else:

                seen = 0

                hist = p
                score = p

                self.state[src] = p

            pred = int(
                score
                >=
                self.threshold
            )

            histories.append(hist)
            seen_values.append(seen)
            scores.append(score)
            preds.append(pred)

        return (
            np.asarray(
                scores,
                dtype=float,
            ),
            np.asarray(
                preds,
                dtype=int,
            ),
            np.asarray(
                histories,
                dtype=float,
            ),
            np.asarray(
                seen_values,
                dtype=int,
            ),
        )


# ============================================================
# SESSION SUMMARY
# ============================================================

def save_summary(
    path,
    summary,
):

    tmp = Path(
        str(path) + ".tmp"
    )

    tmp.write_text(
        json.dumps(
            summary,
            indent=2,
        ),
        encoding="utf-8",
    )

    tmp.replace(path)


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "L-PoPI frozen 1-s "
            "stateful online Cog-GAT gateway"
        )
    )

    parser.add_argument(
        "--pcap-dir",
        type=Path,
        default=None,
    )

    parser.add_argument(
        "--interface",
        default="wlp113s0",
    )

    parser.add_argument(
        "--stable-seconds",
        type=float,
        default=1.5,
    )

    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=0.20,
    )

    parser.add_argument(
        "--self-check",
        action="store_true",
    )

    parser.add_argument(
        "--session-id",
        default=None,
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Frozen policy + integrity
    # --------------------------------------------------------

    (
        policy,
        model_path,
        scaler_path,
    ) = load_frozen_policy()

    if not EXTRACTOR_FILE.exists():
        raise FileNotFoundError(
            EXTRACTOR_FILE
        )

    extractor = json.loads(
        EXTRACTOR_FILE.read_text(
            encoding="utf-8"
        )
    )

    if (
        extractor.get("status")
        != "FROZEN_FOR_PROSPECTIVE_LIVE_GATEWAY"
    ):
        raise RuntimeError(
            "Invalid extractor freeze status."
        )

    if not ARGUS_BIN.exists():
        raise FileNotFoundError(ARGUS_BIN)

    if not RA_BIN.exists():
        raise FileNotFoundError(RA_BIN)

    expected_argus = (
        extractor["sha256"]["argus"]
    )

    expected_ra = (
        extractor["sha256"]["ra"]
    )

    if sha256_file(ARGUS_BIN) != expected_argus:
        raise RuntimeError(
            "ARGUS5 SHA256 MISMATCH"
        )

    if sha256_file(RA_BIN) != expected_ra:
        raise RuntimeError(
            "RA5 SHA256 MISMATCH"
        )

    alpha = float(
        policy["coggat"]["alpha"]
    )

    lam = float(
        policy["coggat"]["lambda"]
    )

    threshold = float(
        policy["coggat"]["threshold"]
    )

    # --------------------------------------------------------
    # Device/model/scaler
    # --------------------------------------------------------

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    scaler = joblib.load(
        scaler_path
    )

    model = OnlineGATv2().to(
        device
    )

    model.load_state_dict(
        torch.load(
            model_path,
            map_location=device,
            weights_only=True,
        )
    )

    model.eval()

    # --------------------------------------------------------
    # CUDA / model warm-up before prospective measurements.
    # No live data and no Cog-GAT state are used or modified.
    # --------------------------------------------------------

    warmup_start = time.perf_counter()

    warm_x = torch.zeros(
        (2, 3),
        dtype=torch.float32,
        device=device,
    )

    warm_edges = torch.tensor(
        [[0, 1], [1, 0]],
        dtype=torch.long,
        device=device,
    )

    warm_graph = Data(
        x=warm_x,
        edge_index=warm_edges,
    )

    with torch.no_grad():
        for _ in range(3):
            _ = model(warm_graph)

    if device.type == "cuda":
        torch.cuda.synchronize()

    warmup_ms = (
        time.perf_counter()
        - warmup_start
    ) * 1000.0

    print(
        "\nMODEL_WARMUP_MS =",
        f"{warmup_ms:.3f}"
    )

    print(
        "\n===== L-PoPI ONLINE GATEWAY ====="
    )

    print(
        "device      =",
        device,
    )

    if device.type == "cuda":
        print(
            "gpu         =",
            torch.cuda.get_device_name(0),
        )

    print(
        "model       =",
        model_path,
    )

    print(
        "scaler      =",
        scaler_path,
    )

    print(
        "policy      =",
        POLICY_FILE,
    )

    print(
        "mode        = src"
    )

    print(
        "alpha       =",
        alpha,
    )

    print(
        "lambda      =",
        lam,
    )

    print(
        "threshold   =",
        threshold,
    )

    print(
        "window      = 1.0 s"
    )

    print(
        "features    = "
        "pkts, bytes, dur"
    )

    print(
        "model_sha256 =",
        sha256_file(model_path),
    )

    print(
        "scaler_sha256 =",
        sha256_file(scaler_path),
    )

    print(
        "policy_sha256 =",
        sha256_file(POLICY_FILE),
    )

    print(
        "argus       =",
        ARGUS_BIN,
    )

    print(
        "ra          =",
        RA_BIN,
    )

    print(
        "argus_sha256 =",
        sha256_file(ARGUS_BIN),
    )

    print(
        "ra_sha256    =",
        sha256_file(RA_BIN),
    )

    print(
        "extractor_policy_sha256 =",
        sha256_file(EXTRACTOR_FILE),
    )

    print(
        "flow_filter = proto != man"
    )

    if args.self_check:

        print(
            "\nGATEWAY_SELF_CHECK_OK"
        )

        return

    if args.pcap_dir is None:
        raise RuntimeError(
            "--pcap-dir is required "
            "unless --self-check is used."
        )

    pcap_dir = (
        args.pcap_dir
        .expanduser()
        .resolve()
    )

    pcap_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Session output
    # --------------------------------------------------------

    if args.session_id:

        session_id = (
            args.session_id
        )

    else:

        session_id = (
            datetime.now(
                timezone.utc
            )
            .strftime(
                "%Y%m%dT%H%M%SZ"
            )
        )

    session_dir = (
        RESULTS
        / "live_gateway"
        / session_id
    )

    session_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    flow_csv = (
        session_dir
        / "flow_decisions.csv"
    )

    window_csv = (
        session_dir
        / "window_metrics.csv"
    )

    summary_json = (
        session_dir
        / "session_summary.json"
    )

    errors_log = (
        session_dir
        / "errors.log"
    )

    metadata = {
        "session_id":
            session_id,

        "started_utc":
            utc_now(),

        "interface":
            args.interface,

        "pcap_dir":
            str(pcap_dir),

        "window_seconds":
            1.0,

        "features":
            [
                "pkts",
                "bytes",
                "dur",
            ],

        "coggat": {
            "mode": "src",
            "alpha": alpha,
            "lambda": lam,
            "threshold":
                threshold,
        },

        "device":
            str(device),

        "gpu":
            (
                torch.cuda.get_device_name(0)
                if device.type == "cuda"
                else None
            ),

        "torch":
            torch.__version__,

        "model_warmup_before_measurement":
            True,

        "model_warmup_iterations":
            3,

        "model_warmup_ms":
            float(warmup_ms),

        "model_sha256":
            sha256_file(
                model_path
            ),

        "scaler_sha256":
            sha256_file(
                scaler_path
            ),

        "deployment_policy_sha256":
            sha256_file(
                POLICY_FILE
            ),

        "extractor_policy_sha256":
            sha256_file(
                EXTRACTOR_FILE
            ),

        "argus_version":
            "5.0.4",

        "ra_version":
            "5.0.4",

        "argus_binary":
            str(ARGUS_BIN),

        "ra_binary":
            str(RA_BIN),

        "argus_sha256":
            sha256_file(
                ARGUS_BIN
            ),

        "ra_sha256":
            sha256_file(
                RA_BIN
            ),

        "network_record_filter":
            "proto != man",

        "prospective_rules": {
            "threshold_locked_before_capture":
                True,

            "live_training":
                False,

            "live_threshold_tuning":
                False,

            "test_reused":
                False,
        },
    }

    (
        session_dir
        / "session_metadata.json"
    ).write_text(
        json.dumps(
            metadata,
            indent=2,
        ),
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # State
    # --------------------------------------------------------

    cog = CausalCogGAT(
        alpha=alpha,
        lam=lam,
        threshold=threshold,
    )

    processed = set()

    file_state = {}

    total_windows = 0
    nonempty_windows = 0
    empty_windows = 0

    total_flows = 0

    total_normal = 0
    total_risk = 0

    total_argus_ms = 0.0
    total_ml_ms = 0.0
    total_postclose_ms = 0.0

    started_perf = (
        time.perf_counter()
    )

    print(
        "\n===== PROSPECTIVE LIVE SESSION ====="
    )

    print(
        "session_id =",
        session_id,
    )

    print(
        "pcap_dir   =",
        pcap_dir,
    )

    print(
        "output     =",
        session_dir,
    )

    print(
        "\nWaiting for completed PCAP windows..."
    )

    # --------------------------------------------------------
    # Watch loop
    # --------------------------------------------------------

    try:

        while True:

            now = time.time()

            pcaps = sorted(
                pcap_dir.glob("*.pcap")
            )

            for pcap in pcaps:

                if pcap in processed:
                    continue

                try:
                    stat = pcap.stat()
                except FileNotFoundError:
                    continue

                age = (
                    now
                    - stat.st_mtime
                )

                size = stat.st_size
                pcap_finalized_epoch = stat.st_mtime

                old = file_state.get(
                    pcap
                )

                file_state[pcap] = (
                    size,
                    now,
                )

                if (
                    age
                    <
                    args.stable_seconds
                ):
                    continue

                if old is None:
                    continue

                old_size, old_seen = old

                if size != old_size:
                    continue

                if (
                    now - old_seen
                    <
                    args.poll_seconds
                ):
                    continue

                # --------------------------------------------
                # Completed PCAP -> decision
                # --------------------------------------------

                wall0 = (
                    time.perf_counter()
                )

                cpu0 = (
                    cpu_seconds_self_children()
                )

                host_cpu0 = (
                    read_host_cpu_counters()
                )

                host_mem_before = (
                    host_mem_used_mb()
                )

                rss_before = (
                    current_rss_mb()
                )

                try:

                    (
                        flows,
                        argus_ms,
                    ) = pcap_to_flows(
                        pcap
                    )

                    n_flows = len(
                        flows
                    )

                    ml0 = (
                        time.perf_counter()
                    )

                    if n_flows > 0:

                        graph = build_graph(
                            flows,
                            scaler,
                        )

                        graph = graph.to(
                            device
                        )

                        if (
                            device.type
                            == "cuda"
                        ):
                            torch.cuda.synchronize()

                        infer_start = (
                            time.perf_counter()
                        )

                        with torch.no_grad():

                            logits = model(
                                graph
                            )

                            gat_prob = (
                                torch.softmax(
                                    logits,
                                    dim=1,
                                )[:, 1]
                                .detach()
                                .cpu()
                                .numpy()
                            )

                        if (
                            device.type
                            == "cuda"
                        ):
                            torch.cuda.synchronize()

                        (
                            cog_scores,
                            predictions,
                            history_values,
                            seen_values,
                        ) = cog.apply(
                            flows,
                            gat_prob,
                        )

                        ml_ms = (
                            time.perf_counter()
                            -
                            infer_start
                        ) * 1000.0

                    else:

                        gat_prob = (
                            np.asarray([])
                        )

                        cog_scores = (
                            np.asarray([])
                        )

                        predictions = (
                            np.asarray(
                                [],
                                dtype=int,
                            )
                        )

                        history_values = (
                            np.asarray([])
                        )

                        seen_values = (
                            np.asarray(
                                [],
                                dtype=int,
                            )
                        )

                        ml_ms = 0.0

                    wall1 = (
                        time.perf_counter()
                    )

                    cpu1 = (
                        cpu_seconds_self_children()
                    )

                    host_cpu1 = (
                        read_host_cpu_counters()
                    )

                    postclose_ms = (
                        wall1 - wall0
                    ) * 1000.0

                    pipeline_cpu_percent = (
                        100.0
                        *
                        (cpu1 - cpu0)
                        /
                        max(
                            wall1 - wall0,
                            1e-9,
                        )
                    )

                    host_cpu_pct = (
                        host_cpu_percent(
                            host_cpu0,
                            host_cpu1,
                        )
                    )

                    rss_after = (
                        current_rss_mb()
                    )

                    host_mem_after = (
                        host_mem_used_mb()
                    )

                    child_peak_mb = (
                        child_peak_rss_mb()
                    )

                    decision_epoch = (
                        time.time()
                    )

                    finalized_to_decision_ms = (
                        decision_epoch
                        - pcap_finalized_epoch
                    ) * 1000.0

                    n_risk = int(
                        predictions.sum()
                    )

                    n_normal = int(
                        n_flows
                        -
                        n_risk
                    )

                    if n_flows == 0:

                        window_decision = (
                            "EMPTY"
                        )

                    elif n_risk > 0:

                        window_decision = (
                            "RISK"
                        )

                    else:

                        window_decision = (
                            "NORMAL"
                        )

                    # ----------------------------------------
                    # Per-flow log
                    # ----------------------------------------

                    for i, row in (
                        flows
                        .reset_index(drop=True)
                        .iterrows()
                    ):

                        append_csv(
                            flow_csv,
                            {
                                "timestamp_utc":
                                    utc_now(),

                                "pcap":
                                    pcap.name,

                                "flow_index":
                                    int(i),

                                "proto":
                                    row["proto"],

                                "saddr":
                                    row["saddr"],

                                "daddr":
                                    row["daddr"],

                                "pkts":
                                    float(
                                        row["pkts"]
                                    ),

                                "bytes":
                                    float(
                                        row["bytes"]
                                    ),

                                "dur":
                                    float(
                                        row["dur"]
                                    ),

                                "gat_probability":
                                    float(
                                        gat_prob[i]
                                    ),

                                "history_before":
                                    float(
                                        history_values[i]
                                    ),

                                "seen_source_before":
                                    int(
                                        seen_values[i]
                                    ),

                                "coggat_score":
                                    float(
                                        cog_scores[i]
                                    ),

                                "threshold":
                                    threshold,

                                "prediction":
                                    int(
                                        predictions[i]
                                    ),

                                "decision":
                                    (
                                        "RISK"
                                        if predictions[i]
                                        else "NORMAL"
                                    ),
                            },
                        )

                    # ----------------------------------------
                    # Window log
                    # ----------------------------------------

                    processing_seconds = (
                        postclose_ms
                        / 1000.0
                    )

                    processing_throughput = (
                        n_flows
                        /
                        processing_seconds
                        if processing_seconds > 0
                        else np.nan
                    )

                    observed_flows_per_s = (
                        n_flows / 1.0
                    )

                    gpu_allocated_mb = (
                        torch.cuda.memory_allocated()
                        / 1024**2
                        if device.type == "cuda"
                        else 0.0
                    )

                    gpu_reserved_mb = (
                        torch.cuda.memory_reserved()
                        / 1024**2
                        if device.type == "cuda"
                        else 0.0
                    )

                    window_row = {
                        "timestamp_utc":
                            utc_now(),

                        "pcap":
                            pcap.name,

                        "pcap_bytes":
                            int(size),

                        "n_flows":
                            int(n_flows),

                        "normal_flows":
                            int(n_normal),

                        "risk_flows":
                            int(n_risk),

                        "window_decision":
                            window_decision,

                        "argus_ra_ms":
                            float(
                                argus_ms
                            ),

                        "ml_inference_ms":
                            float(
                                ml_ms
                            ),

                        "processing_start_to_decision_ms":
                            float(
                                postclose_ms
                            ),

                        "pcap_finalized_to_decision_ms":
                            float(
                                finalized_to_decision_ms
                            ),

                        "window_start_to_decision_est_ms":
                            float(
                                1000.0
                                +
                                finalized_to_decision_ms
                            ),

                        "observed_flows_per_s":
                            float(
                                observed_flows_per_s
                            ),

                        "processing_throughput_flows_s":
                            float(
                                processing_throughput
                            ),

                        "pipeline_cpu_percent":
                            float(
                                pipeline_cpu_percent
                            ),

                        "host_cpu_percent":
                            float(
                                host_cpu_pct
                            ),

                        "python_rss_before_mb":
                            float(
                                rss_before
                            ),

                        "python_rss_after_mb":
                            float(
                                rss_after
                            ),

                        "child_peak_rss_mb":
                            float(
                                child_peak_mb
                            ),

                        "host_mem_used_before_mb":
                            float(
                                host_mem_before
                            ),

                        "host_mem_used_after_mb":
                            float(
                                host_mem_after
                            ),

                        "gpu_allocated_mb":
                            float(
                                gpu_allocated_mb
                            ),

                        "gpu_reserved_mb":
                            float(
                                gpu_reserved_mb
                            ),

                        "threshold":
                            threshold,
                    }

                    append_csv(
                        window_csv,
                        window_row,
                    )

                    # ----------------------------------------
                    # Totals
                    # ----------------------------------------

                    total_windows += 1

                    if n_flows > 0:
                        nonempty_windows += 1
                    else:
                        empty_windows += 1

                    total_flows += (
                        n_flows
                    )

                    total_normal += (
                        n_normal
                    )

                    total_risk += (
                        n_risk
                    )

                    total_argus_ms += (
                        argus_ms
                    )

                    total_ml_ms += (
                        ml_ms
                    )

                    total_postclose_ms += (
                        postclose_ms
                    )

                    elapsed_s = (
                        time.perf_counter()
                        -
                        started_perf
                    )

                    summary = {
                        "session_id":
                            session_id,

                        "updated_utc":
                            utc_now(),

                        "threshold":
                            threshold,

                        "alpha":
                            alpha,

                        "lambda":
                            lam,

                        "windows":
                            total_windows,

                        "nonempty_windows":
                            nonempty_windows,

                        "empty_windows":
                            empty_windows,

                        "flows":
                            total_flows,

                        "normal_flows":
                            total_normal,

                        "risk_flows":
                            total_risk,

                        "risk_fraction":
                            (
                                total_risk
                                /
                                total_flows
                                if total_flows
                                else 0.0
                            ),

                        "mean_argus_ra_ms":
                            (
                                total_argus_ms
                                /
                                total_windows
                            ),

                        "mean_ml_inference_ms":
                            (
                                total_ml_ms
                                /
                                total_windows
                            ),

                        "mean_decision_after_window_close_ms":
                            (
                                total_postclose_ms
                                /
                                total_windows
                            ),

                        "elapsed_session_s":
                            elapsed_s,

                        "causal_sources_in_state":
                            len(
                                cog.state
                            ),

                        "policy_changed_during_session":
                            False,

                        "live_training":
                            False,
                    }

                    save_summary(
                        summary_json,
                        summary,
                    )

                    print(
                        f"{pcap.name} | "
                        f"flows={n_flows} | "
                        f"NORMAL={n_normal} | "
                        f"RISK={n_risk} | "
                        f"decision={window_decision} | "
                        f"Argus+ra={argus_ms:.2f} ms | "
                        f"ML={ml_ms:.2f} ms | "
                        f"processing={postclose_ms:.2f} ms | "
                        f"finalized->decision={finalized_to_decision_ms:.2f} ms | "
                        f"PipelineCPU={pipeline_cpu_percent:.1f}% | "
                        f"HostCPU={host_cpu_pct:.1f}% | "
                        f"PythonRSS={rss_after:.1f} MB"
                    )

                    processed.add(
                        pcap
                    )

                except Exception as exc:

                    msg = (
                        f"\n[{utc_now()}] "
                        f"{pcap}\n"
                        f"{exc}\n"
                        f"{traceback.format_exc()}\n"
                    )

                    with errors_log.open(
                        "a",
                        encoding="utf-8",
                    ) as f:
                        f.write(msg)

                    print(
                        "ERROR processing",
                        pcap.name,
                        "- see",
                        errors_log,
                    )

                    # Prevent tight retry loop.
                    time.sleep(0.5)

            time.sleep(
                args.poll_seconds
            )

    except KeyboardInterrupt:

        print(
            "\nGateway stopped by user."
        )

        print(
            "Processed windows =",
            total_windows,
        )

        print(
            "Processed flows   =",
            total_flows,
        )

        print(
            "NORMAL flows      =",
            total_normal,
        )

        print(
            "RISK flows        =",
            total_risk,
        )

        print(
            "Output            =",
            session_dir,
        )

        print(
            "\nONLINE_GATEWAY_SESSION_STOPPED_OK"
        )


if __name__ == "__main__":
    main()
