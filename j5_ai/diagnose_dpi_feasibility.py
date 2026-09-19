from pathlib import Path
import numpy as np
import pandas as pd

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
VAL_PATH = BASE / "results/gatv2/gatv2_val_predictions.parquet"

ALPHA = 0.10
LAMBDA = 0.50


def add_causal_src_history(df):
    work = df.sort_values(
        ["source_file", "stime", "source_row"]
    ).copy().reset_index(drop=True)

    history = np.full(len(work), np.nan)

    for _, idxs in work.groupby(
        "source_file", sort=False
    ).groups.items():

        state = {}

        for pos in idxs:
            src = str(work.at[pos, "saddr"])
            p = float(work.at[pos, "gat_probability"])

            if src in state:
                history[pos] = state[src]

            if src not in state:
                state[src] = p
            else:
                state[src] = (
                    ALPHA * p +
                    (1 - ALPHA) * state[src]
                )

    p = work["gat_probability"].to_numpy()
    h = np.where(np.isnan(history), p, history)

    work["cog_gat_score"] = (
        (1 - LAMBDA) * p +
        LAMBDA * h
    )

    return work


val = add_causal_src_history(
    pd.read_parquet(VAL_PATH)
)

benign = val.loc[
    val["attack"] == 0, "cog_gat_score"
].to_numpy()

attack = val.loc[
    val["attack"] == 1, "cog_gat_score"
].to_numpy()

print("=== VAL SCORE DISTRIBUTION ===")
print("N benign =", len(benign))
print("N attack =", len(attack))

for name, x in [
    ("BENIGN", benign),
    ("ATTACK", attack)
]:
    print()
    print(name)

    for q in [
        0, .01, .05, .10, .25,
        .50, .75, .90, .95, .99, 1
    ]:
        print(
            f"q={q:>4.2f}: "
            f"{np.quantile(x,q):.6f}"
        )


# --------------------------------------------------
# FAST-PATH feasibility
#
# For each maximum permitted attack-fast-path rate,
# find the largest tau1 satisfying it and report
# resulting benign fast-path rate.
# --------------------------------------------------

print()
print("=== FAST-PATH SECURITY FRONTIER ===")

thresholds = np.unique(
    np.concatenate([benign, attack])
)

for attack_budget in [
    .001, .005, .01, .02, .05,
    .10, .15, .20, .25
]:
    feasible = []

    for t in thresholds:
        afr = np.mean(attack < t)

        if afr <= attack_budget:
            bfr = np.mean(benign < t)
            feasible.append((bfr, afr, t))

    if feasible:
        bfr, afr, t = max(
            feasible,
            key=lambda z: z[0]
        )

        print(
            f"attack_FAST<={100*attack_budget:5.1f}% "
            f"=> tau1={t:.6f} "
            f"benign_FAST={100*bfr:6.2f}% "
            f"attack_FAST={100*afr:6.2f}%"
        )
    else:
        print(
            f"attack_FAST<={100*attack_budget:5.1f}% "
            "=> NONE"
        )


# --------------------------------------------------
# RESTRICT feasibility
#
# For each maximum permitted benign restriction,
# find the smallest tau2 satisfying it and report
# attack restriction.
# --------------------------------------------------

print()
print("=== RESTRICTION FRONTIER ===")

for benign_budget in [
    .001, .005, .01, .02, .05,
    .10, .15, .20, .25
]:
    feasible = []

    for t in thresholds:
        brr = np.mean(benign >= t)

        if brr <= benign_budget:
            arr = np.mean(attack >= t)
            feasible.append((arr, brr, t))

    if feasible:
        arr, brr, t = max(
            feasible,
            key=lambda z: z[0]
        )

        print(
            f"benign_RESTRICT<={100*benign_budget:5.1f}% "
            f"=> tau2={t:.6f} "
            f"attack_RESTRICT={100*arr:6.2f}% "
            f"benign_RESTRICT={100*brr:6.2f}%"
        )
    else:
        print(
            f"benign_RESTRICT<={100*benign_budget:5.1f}% "
            "=> NONE"
        )


# --------------------------------------------------
# Check specifically why 5% / 5% fails
# --------------------------------------------------

tau1_candidates = [
    t for t in thresholds
    if np.mean(attack < t) <= .05
]

tau2_candidates = [
    t for t in thresholds
    if np.mean(benign >= t) <= .05
]

print()
print("=== 5% / 5% COMPATIBILITY ===")

if tau1_candidates:
    tau1_max = max(tau1_candidates)
    print("maximum feasible tau1 =", tau1_max)
else:
    tau1_max = None
    print("No tau1 feasible")

if tau2_candidates:
    tau2_min = min(tau2_candidates)
    print("minimum feasible tau2 =", tau2_min)
else:
    tau2_min = None
    print("No tau2 feasible")

if tau1_max is not None and tau2_min is not None:
    print("tau1 < tau2 =", tau1_max < tau2_min)

    if tau1_max < tau2_min:
        dpi = np.mean(
            (val["cog_gat_score"] >= tau1_max) &
            (val["cog_gat_score"] < tau2_min)
        )

        print(
            "DPI rate at boundary =",
            dpi
        )
        print(
            "DPI workload reduction =",
            1 - dpi
        )

print()
print("J5_DPI_FEASIBILITY_OK")
