#!/usr/bin/env python3

from pathlib import Path
import pandas as pd
import numpy as np
import hashlib
import json
import re

ROOT = Path.home() / "L-PoPI-Revised-Implementation"

RESULTS = ROOT / "j5_ai/results/online_windowed"

OUT = RESULTS / "final_3run_analysis_20261008"
OUT.mkdir(parents=True, exist_ok=True)

RUNS = {
    "run01": {
        "receiver":
            RESULTS / "esp32_final/run01_receiver.csv",

        "pcaps":
            RESULTS / "live_pcaps/esp32_run01",

        "gateway":
            RESULTS / "live_gateway/20261008T160902Z",
    },

    "run02": {
        "receiver":
            RESULTS / "esp32_final/run02_receiver.csv",

        "pcaps":
            RESULTS / "live_pcaps/esp32_run02",

        "gateway":
            RESULTS / "live_gateway/20261008T165513Z",
    },

    "run03": {
        "receiver":
            RESULTS / "esp32_final/run03_receiver.csv",

        "pcaps":
            RESULTS / "live_pcaps/esp32_run03",

        "gateway":
            RESULTS / "live_gateway/20261008T171254Z",
    },
}

EXPECTED_POLICY = {
    "threshold": 0.512,
    "alpha": 0.1,
    "lambda": 0.8,
}

PHASES = [
    "WARMUP",
    "BASELINE",
    "VARIATION",
    "BURST",
]

PUBLISHED_PHASES = [
    "BASELINE",
    "VARIATION",
    "BURST",
]


# ============================================================
# Utilities
# ============================================================

def sha256_file(path):

    path = Path(path)

    h = hashlib.sha256()

    with path.open("rb") as f:

        for block in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(block)

    return h.hexdigest()


def pcap_time(name):

    m = re.search(
        r"window_(\d{8}T\d{6})\.pcap",
        str(name),
    )

    if not m:
        return pd.NaT

    return pd.to_datetime(
        m.group(1),
        format="%Y%m%dT%H%M%S",
        utc=True,
    )


def q95(x):

    x = pd.to_numeric(
        x,
        errors="coerce",
    ).dropna()

    if len(x) == 0:
        return np.nan

    return x.quantile(0.95)


def metric_stats(x):

    x = pd.to_numeric(
        x,
        errors="coerce",
    ).dropna()

    if len(x) == 0:

        return {
            "n": 0,
            "mean": np.nan,
            "sd": np.nan,
            "median": np.nan,
            "p95": np.nan,
            "min": np.nan,
            "max": np.nan,
        }

    return {
        "n":
            int(len(x)),

        "mean":
            float(x.mean()),

        "sd":
            float(
                x.std(ddof=1)
                if len(x) > 1
                else 0.0
            ),

        "median":
            float(x.median()),

        "p95":
            float(x.quantile(.95)),

        "min":
            float(x.min()),

        "max":
            float(x.max()),
    }


# ============================================================
# Global containers
# ============================================================

receiver_audit = []

completeness = []

all_flows = []

all_windows = []

run_overview = []

phase_boundary_rows = []

provenance = {}


# ============================================================
# Main per-run audit
# ============================================================

for run, cfg in RUNS.items():

    print()
    print("=" * 72)
    print(run.upper())
    print("=" * 72)

    receiver_file = cfg["receiver"]
    pcap_dir = cfg["pcaps"]
    gateway_dir = cfg["gateway"]

    for p in [
        receiver_file,
        gateway_dir / "session_summary.json",
        gateway_dir / "session_metadata.json",
        gateway_dir / "window_metrics.csv",
        gateway_dir / "flow_decisions.csv",
    ]:

        if not p.exists():
            raise FileNotFoundError(p)

    # --------------------------------------------------------
    # Session policy validation
    # --------------------------------------------------------

    summary = json.loads(
        (
            gateway_dir /
            "session_summary.json"
        ).read_text()
    )

    if float(summary["threshold"]) != 0.512:
        raise RuntimeError(
            f"{run}: threshold changed"
        )

    if float(summary["alpha"]) != 0.1:
        raise RuntimeError(
            f"{run}: alpha changed"
        )

    if float(summary["lambda"]) != 0.8:
        raise RuntimeError(
            f"{run}: lambda changed"
        )

    if bool(
        summary.get(
            "policy_changed_during_session",
            False,
        )
    ):
        raise RuntimeError(
            f"{run}: policy changed"
        )

    if bool(
        summary.get(
            "live_training",
            False,
        )
    ):
        raise RuntimeError(
            f"{run}: live training detected"
        )

    # --------------------------------------------------------
    # Receiver audit
    # --------------------------------------------------------

    r = pd.read_csv(
        receiver_file
    )

    r["seq_num"] = pd.to_numeric(
        r["seq"],
        errors="coerce",
    )

    r["timestamp_utc"] = pd.to_datetime(
        r["timestamp_utc"],
        utc=True,
    )

    zero_idx = list(
        r.index[
            r["seq_num"] == 0
        ]
    )

    if not zero_idx:
        raise RuntimeError(
            f"{run}: seq=0 not found"
        )

    # Last seq=0 = start of final experiment.
    start_idx = zero_idx[-1]

    exp = (
        r.loc[start_idx:]
        .copy()
        .reset_index(drop=True)
    )

    seqs = (
        exp["seq_num"]
        .astype(int)
        .tolist()
    )

    sequence_continuous = (
        seqs
        ==
        list(
            range(len(seqs))
        )
    )

    missing_seq = sorted(
        set(
            range(
                min(seqs),
                max(seqs) + 1,
            )
        )
        -
        set(seqs)
    )

    duplicate_seq = int(
        exp["seq_num"]
        .duplicated()
        .sum()
    )

    phase_counts = (
        exp["phase"]
        .value_counts()
        .to_dict()
    )

    receiver_audit.append({
        "run":
            run,

        "raw_receiver_rows":
            len(r),

        "pre_experiment_rows":
            start_idx,

        "experiment_messages":
            len(exp),

        "seq_min":
            min(seqs),

        "seq_max":
            max(seqs),

        "sequence_continuous":
            sequence_continuous,

        "missing_seq_count":
            len(missing_seq),

        "duplicate_seq_count":
            duplicate_seq,

        "warmup_messages":
            phase_counts.get(
                "WARMUP",
                0,
            ),

        "baseline_messages":
            phase_counts.get(
                "BASELINE",
                0,
            ),

        "variation_messages":
            phase_counts.get(
                "VARIATION",
                0,
            ),

        "burst_messages":
            phase_counts.get(
                "BURST",
                0,
            ),
    })

    print(
        "receiver experiment messages =",
        len(exp),
    )

    print(
        "sequence continuous =",
        sequence_continuous,
    )

    print(
        "missing seq =",
        len(missing_seq),
    )

    print(
        "duplicate seq =",
        duplicate_seq,
    )

    if (
        not sequence_continuous
        or
        missing_seq
        or
        duplicate_seq
    ):

        raise RuntimeError(
            f"{run}: receiver sequence audit failed"
        )

    # --------------------------------------------------------
    # Exact per-second phase map from actual receiver
    #
    # A second containing two phases is marked MIXED and
    # excluded from phase-specific scientific summaries.
    # --------------------------------------------------------

    exp["second"] = (
        exp["timestamp_utc"]
        .dt.floor("s")
    )

    second_phase = {}

    for second, g in exp.groupby(
        "second"
    ):

        phases_here = sorted(
            set(
                g["phase"]
                .dropna()
                .astype(str)
            )
        )

        if len(phases_here) == 1:

            second_phase[second] = (
                phases_here[0]
            )

        elif len(phases_here) > 1:

            second_phase[second] = (
                "MIXED"
            )

        else:

            second_phase[second] = (
                "UNLABELED"
            )

    # --------------------------------------------------------
    # Phase timing
    # --------------------------------------------------------

    for phase in PHASES:

        g = exp[
            exp["phase"] == phase
        ]

        if len(g) == 0:
            continue

        start = (
            g["timestamp_utc"]
            .min()
        )

        end = (
            g["timestamp_utc"]
            .max()
        )

        phase_boundary_rows.append({
            "run":
                run,

            "phase":
                phase,

            "messages":
                len(g),

            "seq_start":
                int(
                    g["seq_num"].min()
                ),

            "seq_end":
                int(
                    g["seq_num"].max()
                ),

            "start_utc":
                start.isoformat(),

            "end_utc":
                end.isoformat(),

            "span_s":
                (
                    end - start
                ).total_seconds(),
        })

    # --------------------------------------------------------
    # Gateway files
    # --------------------------------------------------------

    w = pd.read_csv(
        gateway_dir /
        "window_metrics.csv"
    )

    f = pd.read_csv(
        gateway_dir /
        "flow_decisions.csv"
    )

    w["run"] = run
    f["run"] = run

    w["pcap_time"] = (
        w["pcap"]
        .map(pcap_time)
    )

    f["pcap_time"] = (
        f["pcap"]
        .map(pcap_time)
    )

    w["phase"] = (
        w["pcap_time"]
        .map(
            lambda t:
                second_phase.get(
                    t,
                    "UNLABELED",
                )
        )
    )

    f["phase"] = (
        f["pcap_time"]
        .map(
            lambda t:
                second_phase.get(
                    t,
                    "UNLABELED",
                )
        )
    )

    all_windows.append(w)
    all_flows.append(f)

    # --------------------------------------------------------
    # Completeness
    # --------------------------------------------------------

    pcap_files = sorted(
        p.name
        for p in pcap_dir.glob(
            "*.pcap"
        )
    )

    processed = set(
        w["pcap"].astype(str)
    )

    pcap_set = set(
        pcap_files
    )

    unprocessed = sorted(
        pcap_set
        -
        processed
    )

    processed_missing_file = sorted(
        processed
        -
        pcap_set
    )

    part_files = list(
        pcap_dir.glob(
            "*.part"
        )
    )

    completeness.append({
        "run":
            run,

        "pcap_files":
            len(pcap_files),

        "processed_windows":
            len(w),

        "unprocessed_pcaps":
            len(unprocessed),

        "unprocessed_names":
            ";".join(
                unprocessed
            ),

        "processed_missing_file":
            len(
                processed_missing_file
            ),

        "remaining_part_files":
            len(part_files),

        "flow_rows":
            len(f),

        "complete":
            (
                len(unprocessed) == 0
                and
                len(processed_missing_file) == 0
                and
                len(part_files) == 0
            ),
    })

    print(
        "PCAP / processed =",
        len(pcap_files),
        "/",
        len(w),
    )

    print(
        "unprocessed =",
        unprocessed,
    )

    # --------------------------------------------------------
    # Run overview
    # --------------------------------------------------------

    run_overview.append({
        "run":
            run,

        "session_id":
            summary["session_id"],

        "threshold":
            summary["threshold"],

        "alpha":
            summary["alpha"],

        "lambda":
            summary["lambda"],

        "session_windows":
            summary["windows"],

        "session_flows":
            summary["flows"],

        "normal_flows":
            summary["normal_flows"],

        "risk_flows":
            summary["risk_flows"],

        "risk_fraction":
            summary["risk_fraction"],

        "mean_argus_ra_ms":
            summary[
                "mean_argus_ra_ms"
            ],

        "mean_ml_inference_ms":
            summary[
                "mean_ml_inference_ms"
            ],

        "mean_decision_after_window_close_ms":
            summary[
                "mean_decision_after_window_close_ms"
            ],

        "policy_changed":
            summary[
                "policy_changed_during_session"
            ],

        "live_training":
            summary[
                "live_training"
            ],
    })

    # --------------------------------------------------------
    # Provenance
    # --------------------------------------------------------

    provenance[run] = {
        "receiver_sha256":
            sha256_file(
                receiver_file
            ),

        "window_metrics_sha256":
            sha256_file(
                gateway_dir /
                "window_metrics.csv"
            ),

        "flow_decisions_sha256":
            sha256_file(
                gateway_dir /
                "flow_decisions.csv"
            ),

        "session_summary_sha256":
            sha256_file(
                gateway_dir /
                "session_summary.json"
            ),

        "session_metadata_sha256":
            sha256_file(
                gateway_dir /
                "session_metadata.json"
            ),
    }


# ============================================================
# Concatenate
# ============================================================

flows = pd.concat(
    all_flows,
    ignore_index=True,
)

windows = pd.concat(
    all_windows,
    ignore_index=True,
)

receiver_audit_df = pd.DataFrame(
    receiver_audit
)

completeness_df = pd.DataFrame(
    completeness
)

run_overview_df = pd.DataFrame(
    run_overview
)

phase_boundaries_df = pd.DataFrame(
    phase_boundary_rows
)


# ============================================================
# Frozen model/policy provenance
# ============================================================

frozen_files = {
    "model":
        RESULTS /
        "best_online_gatv2.pt",

    "scaler":
        RESULTS /
        "online_train_only_scaler.joblib",

    "policy":
        RESULTS /
        "deployment_policy_frozen_0512.json",

    "extractor_policy":
        RESULTS /
        "deployment_extractor_frozen_argus5.json",

    "argus5":
        ROOT /
        "tools/argus5/src/argus/bin/argus",

    "ra5":
        ROOT /
        "tools/argus5/src/clients/bin/ra",
}

provenance["frozen_artifacts"] = {}

for name, path in frozen_files.items():

    if path.exists():

        provenance[
            "frozen_artifacts"
        ][name] = {
            "path":
                str(path),

            "sha256":
                sha256_file(path),
        }


# ============================================================
# Phase-level flow statistics
# ============================================================

FLOW_METRICS = [
    "gat_probability",
    "coggat_score",
    "pkts",
    "bytes",
    "dur",
]

phase_rows = []

for (run, phase), g in flows.groupby(
    [
        "run",
        "phase",
    ],
    dropna=False,
):

    row = {
        "run":
            run,

        "phase":
            phase,

        "flows":
            len(g),

        "normal":
            int(
                (
                    g["decision"]
                    ==
                    "NORMAL"
                ).sum()
            ),

        "risk":
            int(
                (
                    g["decision"]
                    ==
                    "RISK"
                ).sum()
            ),
    }

    row["risk_fraction"] = (
        row["risk"]
        /
        row["flows"]
        if row["flows"]
        else np.nan
    )

    for metric in FLOW_METRICS:

        if metric not in g:
            continue

        st = metric_stats(
            g[metric]
        )

        for k in [
            "mean",
            "median",
            "p95",
            "max",
        ]:

            row[
                f"{metric}_{k}"
            ] = st[k]

    phase_rows.append(row)

phase_by_run_df = pd.DataFrame(
    phase_rows
)


# ============================================================
# Pooled phase statistics across all 3 runs
# Exclude WARMUP / MIXED / UNLABELED.
# ============================================================

pooled_phase_rows = []

for phase in PUBLISHED_PHASES:

    g = flows[
        flows["phase"] == phase
    ]

    row = {
        "phase":
            phase,

        "runs":
            int(
                g["run"].nunique()
            ),

        "flows":
            len(g),

        "normal":
            int(
                (
                    g["decision"]
                    ==
                    "NORMAL"
                ).sum()
            ),

        "risk":
            int(
                (
                    g["decision"]
                    ==
                    "RISK"
                ).sum()
            ),
    }

    row["risk_fraction"] = (
        row["risk"]
        /
        row["flows"]
        if row["flows"]
        else np.nan
    )

    for metric in FLOW_METRICS:

        st = metric_stats(
            g[metric]
        )

        for k in [
            "mean",
            "sd",
            "median",
            "p95",
            "min",
            "max",
        ]:

            row[
                f"{metric}_{k}"
            ] = st[k]

    pooled_phase_rows.append(
        row
    )

pooled_phase_df = pd.DataFrame(
    pooled_phase_rows
)


# ============================================================
# Experimental window selection
#
# Only BASELINE, VARIATION, BURST.
# WARMUP, MIXED, UNLABELED excluded from manuscript latency.
# ============================================================

experimental_windows = windows[
    windows["phase"].isin(
        PUBLISHED_PHASES
    )
].copy()


# ============================================================
# Pooled latency/resources
# ============================================================

WINDOW_METRICS = [
    "argus_ra_ms",
    "ml_inference_ms",
    "processing_start_to_decision_ms",
    "pcap_finalized_to_decision_ms",
    "window_start_to_decision_est_ms",
    "pipeline_cpu_percent",
    "host_cpu_percent",
    "python_rss_after_mb",
    "observed_flows_per_s",
    "processing_throughput_flows_s",
]

latency_rows = []

for metric in WINDOW_METRICS:

    if metric not in experimental_windows:
        continue

    st = metric_stats(
        experimental_windows[
            metric
        ]
    )

    latency_rows.append({
        "metric":
            metric,

        **st,
    })

pooled_latency_df = pd.DataFrame(
    latency_rows
)


# ============================================================
# Per-run experimental latency
# ============================================================

run_latency_rows = []

for run in RUNS:

    g = experimental_windows[
        experimental_windows["run"]
        ==
        run
    ]

    row = {
        "run":
            run,

        "windows":
            len(g),
    }

    for metric in [
        "argus_ra_ms",
        "ml_inference_ms",
        "processing_start_to_decision_ms",
        "pcap_finalized_to_decision_ms",
        "window_start_to_decision_est_ms",
        "pipeline_cpu_percent",
        "host_cpu_percent",
        "python_rss_after_mb",
    ]:

        st = metric_stats(
            g[metric]
        )

        row[
            f"{metric}_mean"
        ] = st["mean"]

        row[
            f"{metric}_median"
        ] = st["median"]

        row[
            f"{metric}_p95"
        ] = st["p95"]

        row[
            f"{metric}_max"
        ] = st["max"]

    run_latency_rows.append(
        row
    )

run_latency_df = pd.DataFrame(
    run_latency_rows
)


# ============================================================
# Cross-run means
# ============================================================

cross_run_rows = []

for metric in [
    "argus_ra_ms_mean",
    "ml_inference_ms_mean",
    "processing_start_to_decision_ms_mean",
    "pcap_finalized_to_decision_ms_mean",
    "window_start_to_decision_est_ms_mean",
]:

    x = pd.to_numeric(
        run_latency_df[
            metric
        ],
        errors="coerce",
    ).dropna()

    cross_run_rows.append({
        "metric":
            metric,

        "mean_of_run_means":
            float(x.mean()),

        "sd_between_runs":
            float(
                x.std(ddof=1)
                if len(x) > 1
                else 0.0
            ),

        "min_run_mean":
            float(x.min()),

        "max_run_mean":
            float(x.max()),
    })

cross_run_df = pd.DataFrame(
    cross_run_rows
)


# ============================================================
# Global outcome
# ============================================================

published_flows = flows[
    flows["phase"].isin(
        PUBLISHED_PHASES
    )
]

global_result = {
    "runs":
        len(RUNS),

    "policy": {
        "threshold":
            0.512,

        "alpha":
            0.1,

        "lambda":
            0.8,

        "live_training":
            False,

        "retuning_during_live_experiment":
            False,
    },

    "receiver_experiment_messages_total":
        int(
            receiver_audit_df[
                "experiment_messages"
            ].sum()
        ),

    "receiver_missing_sequences_total":
        int(
            receiver_audit_df[
                "missing_seq_count"
            ].sum()
        ),

    "receiver_duplicate_sequences_total":
        int(
            receiver_audit_df[
                "duplicate_seq_count"
            ].sum()
        ),

    "pcap_files_total":
        int(
            completeness_df[
                "pcap_files"
            ].sum()
        ),

    "processed_windows_total":
        int(
            completeness_df[
                "processed_windows"
            ].sum()
        ),

    "unprocessed_pcaps_total":
        int(
            completeness_df[
                "unprocessed_pcaps"
            ].sum()
        ),

    "all_gateway_flows_total":
        int(len(flows)),

    "all_gateway_risk_total":
        int(
            (
                flows["decision"]
                ==
                "RISK"
            ).sum()
        ),

    "published_phase_flows":
        int(
            len(
                published_flows
            )
        ),

    "published_phase_risk":
        int(
            (
                published_flows[
                    "decision"
                ]
                ==
                "RISK"
            ).sum()
        ),

    "experimental_windows_for_latency":
        int(
            len(
                experimental_windows
            )
        ),
}


# ============================================================
# Save CSVs
# ============================================================

receiver_audit_df.to_csv(
    OUT / "receiver_audit.csv",
    index=False,
)

completeness_df.to_csv(
    OUT / "pcap_gateway_completeness.csv",
    index=False,
)

run_overview_df.to_csv(
    OUT / "run_overview.csv",
    index=False,
)

phase_boundaries_df.to_csv(
    OUT / "phase_boundaries.csv",
    index=False,
)

phase_by_run_df.to_csv(
    OUT / "phase_results_by_run.csv",
    index=False,
)

pooled_phase_df.to_csv(
    OUT / "phase_results_pooled.csv",
    index=False,
)

pooled_latency_df.to_csv(
    OUT / "latency_resources_pooled.csv",
    index=False,
)

run_latency_df.to_csv(
    OUT / "latency_resources_by_run.csv",
    index=False,
)

cross_run_df.to_csv(
    OUT / "cross_run_statistics.csv",
    index=False,
)

flows.to_csv(
    OUT / "all_flow_decisions_annotated.csv",
    index=False,
)

windows.to_csv(
    OUT / "all_window_metrics_annotated.csv",
    index=False,
)


# ============================================================
# Save JSON
# ============================================================

with (
    OUT /
    "final_online_experiment_summary.json"
).open(
    "w",
    encoding="utf-8",
) as f:

    json.dump(
        global_result,
        f,
        indent=2,
    )


with (
    OUT /
    "provenance_sha256.json"
).open(
    "w",
    encoding="utf-8",
) as f:

    json.dump(
        provenance,
        f,
        indent=2,
    )


# ============================================================
# Markdown manuscript-ready summary
# ============================================================

def fmt(x, digits=3):

    if pd.isna(x):
        return "NA"

    return f"{x:.{digits}f}"


proc = pooled_latency_df.set_index(
    "metric"
)

baseline = pooled_phase_df[
    pooled_phase_df["phase"]
    ==
    "BASELINE"
].iloc[0]

variation = pooled_phase_df[
    pooled_phase_df["phase"]
    ==
    "VARIATION"
].iloc[0]

burst = pooled_phase_df[
    pooled_phase_df["phase"]
    ==
    "BURST"
].iloc[0]

md = []

md.append(
    "# Final Three-Run Online Gateway Analysis"
)

md.append("")

md.append(
    "Frozen deployment policy: "
    "Cog-GAT mode=src, alpha=0.1, lambda=0.8, "
    "threshold=0.512. No live training or live retuning."
)

md.append("")

md.append(
    "## Run completeness"
)

md.append("")

md.append(
    completeness_df.to_markdown(
        index=False
    )
)

md.append("")

md.append(
    "## Receiver audit"
)

md.append("")

md.append(
    receiver_audit_df.to_markdown(
        index=False
    )
)

md.append("")

md.append(
    "## Pooled behavioral results"
)

md.append("")

keep_phase_cols = [
    "phase",
    "flows",
    "normal",
    "risk",
    "risk_fraction",
    "gat_probability_mean",
    "coggat_score_mean",
    "coggat_score_median",
    "coggat_score_p95",
    "coggat_score_max",
    "pkts_mean",
    "bytes_mean",
    "dur_mean",
]

md.append(
    pooled_phase_df[
        keep_phase_cols
    ].to_markdown(
        index=False
    )
)

md.append("")

md.append(
    "## Pooled latency and resource statistics"
)

md.append("")

md.append(
    pooled_latency_df.to_markdown(
        index=False
    )
)

md.append("")

md.append(
    "## Conservative interpretation"
)

md.append("")

md.append(
    f"- Baseline Cog-GAT mean: "
    f"{fmt(baseline['coggat_score_mean'], 6)}."
)

md.append(
    f"- Benign variation Cog-GAT mean: "
    f"{fmt(variation['coggat_score_mean'], 6)}."
)

md.append(
    f"- Controlled burst Cog-GAT mean: "
    f"{fmt(burst['coggat_score_mean'], 6)}."
)

md.append(
    f"- Threshold remained fixed at 0.512."
)

md.append(
    f"- Published-phase flows classified RISK: "
    f"{global_result['published_phase_risk']} / "
    f"{global_result['published_phase_flows']}."
)

md.append(
    "- The controlled burst is a high-rate benign "
    "perturbation and must not be described as a "
    "cyberattack or as an attack-detection recall test."
)

md.append(
    "- The online experiment evaluates prospective "
    "physical gateway feasibility, latency, resource "
    "stability, and behavior under controlled traffic "
    "conditions."
)

md.append("")

md.append(
    "## Key operational result"
)

md.append("")

for metric in [
    "argus_ra_ms",
    "ml_inference_ms",
    "processing_start_to_decision_ms",
    "pcap_finalized_to_decision_ms",
    "window_start_to_decision_est_ms",
]:

    if metric not in proc.index:
        continue

    x = proc.loc[metric]

    md.append(
        f"- {metric}: "
        f"mean={fmt(x['mean'])} ms, "
        f"median={fmt(x['median'])} ms, "
        f"p95={fmt(x['p95'])} ms, "
        f"max={fmt(x['max'])} ms."
    )


(OUT / "FINAL_ONLINE_ANALYSIS.md").write_text(
    "\n".join(md),
    encoding="utf-8",
)


# ============================================================
# Console summary
# ============================================================

print()
print("=" * 72)
print("FINAL THREE-RUN SUMMARY")
print("=" * 72)

print()
print("===== RECEIVER AUDIT =====")
print(
    receiver_audit_df.to_string(
        index=False
    )
)

print()
print("===== COMPLETENESS =====")
print(
    completeness_df.to_string(
        index=False
    )
)

print()
print(
    "===== POOLED PHASE RESULTS ====="
)

print(
    pooled_phase_df[
        keep_phase_cols
    ].to_string(
        index=False
    )
)

print()
print(
    "===== POOLED LATENCY / RESOURCES ====="
)

print(
    pooled_latency_df.to_string(
        index=False
    )
)

print()
print("===== GLOBAL RESULT =====")

print(
    json.dumps(
        global_result,
        indent=2,
    )
)

print()
print("OUTPUT DIRECTORY:")
print(OUT)

print()
print(
    "FINAL_3RUN_ANALYSIS_OK"
)
