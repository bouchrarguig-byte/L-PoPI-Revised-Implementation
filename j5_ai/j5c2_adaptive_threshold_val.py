from pathlib import Path
import hashlib
import numpy as np
import pandas as pd

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
VAL = BASE / "results/j5b/j5b_val_cog_scores.parquet"
OUT = BASE / "results/j5c"
OUT.mkdir(parents=True, exist_ok=True)

df = pd.read_parquet(VAL).copy()

df = df.sort_values(
    ["source_file", "stime", "source_row"],
    kind="mergesort"
).reset_index(drop=True)

print("=== J5-C2 ADAPTIVE THRESHOLD — VAL ONLY ===")
print("N =", len(df))
print("files =", df.source_file.nunique())
print(
    "data_2 present =",
    bool((df.source_file == "data_2.csv").any())
)
print()

# ------------------------------------------------------
# Frozen J5-B Cog score is the instantaneous risk.
#
# J5-C2 changes routing only. No model retraining.
# ------------------------------------------------------

BASE_TAU = 0.3502524895843741

# Candidate causal trust dynamics.
BETAS = [0.05, 0.10, 0.20, 0.40]

# Number of PRIOR observations required before privilege.
MIN_HIST = [2, 3, 5, 10, 20]

# Trust required for elevated Fast threshold.
TRUST_TAUS = np.arange(
    0.50,
    0.951,
    0.025
)

# Elevated instantaneous-risk threshold.
# BASE_TAU remains the default for untrusted/new sources.
ELEVATED_TAUS = np.arange(
    0.36,
    0.801,
    0.01
)

y = df["attack"].astype(int).to_numpy()
risk = df["cog_score"].astype(float).to_numpy()

benign = y == 0
attack = y == 1

rows = []

for beta in BETAS:

    # Build causal state once per beta.
    trust_before = np.zeros(len(df))
    count_before = np.zeros(
        len(df),
        dtype=int
    )

    pos = 0

    for _, g in df.groupby(
        "source_file",
        sort=False
    ):

        trust = {}
        count = {}

        for _, row in g.iterrows():

            src = str(row["saddr"])
            r = float(row["cog_score"])

            old_n = count.get(src, 0)

            # New source has no routing privilege.
            old_t = trust.get(src, 0.0)

            trust_before[pos] = old_t
            count_before[pos] = old_n

            evidence = 1.0 - r

            if old_n == 0:
                new_t = evidence
            else:
                new_t = (
                    (1.0 - beta) * old_t
                    + beta * evidence
                )

            trust[src] = new_t
            count[src] = old_n + 1

            pos += 1

    for min_hist in MIN_HIST:

        mature = (
            count_before >= min_hist
        )

        for tau_trust in TRUST_TAUS:

            privileged = (
                mature
                &
                (trust_before >= tau_trust)
            )

            for elevated_tau in ELEVATED_TAUS:

                # Default J5-B rule.
                #
                # Trusted/mature source receives a larger
                # instantaneous-risk allowance.
                effective_tau = np.where(
                    privileged,
                    elevated_tau,
                    BASE_TAU
                )

                fast = (
                    risk < effective_tau
                )

                rows.append({
                    "beta":
                        float(beta),

                    "min_history":
                        int(min_hist),

                    "tau_trust":
                        float(tau_trust),

                    "elevated_tau":
                        float(elevated_tau),

                    "benign_fast":
                        float(
                            fast[benign].mean()
                        ),

                    "attack_fast":
                        float(
                            fast[attack].mean()
                        ),

                    "total_fast":
                        float(fast.mean()),

                    "dpi_rate":
                        float(1-fast.mean()),

                    "privileged_fraction":
                        float(privileged.mean())
                })

res = pd.DataFrame(rows)

path = (
    OUT /
    "j5c2_adaptive_threshold_val_grid.csv"
)

res.to_csv(path, index=False)

# ------------------------------------------------------
# Baseline
# ------------------------------------------------------

base_fast = risk < BASE_TAU

print("=== J5-B VAL REFERENCE ===")
print(
    "benign_FAST =",
    f"{100*base_fast[benign].mean():.6f}%"
)
print(
    "attack_FAST =",
    f"{100*base_fast[attack].mean():.6f}%"
)
print(
    "total_FAST =",
    f"{100*base_fast.mean():.6f}%"
)
print()

# ------------------------------------------------------
# Pareto-like best operating points.
# ------------------------------------------------------

print(
    "=== BEST ADAPTIVE CONFIGS BY SECURITY BUDGET ==="
)

budgets = [
    0.001,
    0.0025,
    0.005,
    0.0075,
    0.010,
    0.020
]

for budget in budgets:

    feasible = res[
        res.attack_fast <= budget
    ].copy()

    print()
    print(
        f"ATTACK FAST <= {100*budget:.2f}%"
    )

    if feasible.empty:
        print("NO FEASIBLE CONFIG")
        continue

    best = feasible.sort_values(
        [
            "benign_fast",
            "attack_fast",
            "total_fast"
        ],
        ascending=[
            False,
            True,
            False
        ]
    ).iloc[0]

    print(best.to_string())

# ------------------------------------------------------
# Main predeclared target: <=1%.
# ------------------------------------------------------

feasible = res[
    res.attack_fast <= 0.01
].copy()

best = feasible.sort_values(
    [
        "benign_fast",
        "attack_fast",
        "total_fast"
    ],
    ascending=[
        False,
        True,
        False
    ]
).iloc[0]

print()
print("=== J5-C2 CANDIDATE UNDER 1% ===")
print(best.to_string())

improvement = (
    best.benign_fast
    - base_fast[benign].mean()
)

print(
    "absolute benign FAST gain =",
    f"{100*improvement:.6f} percentage points"
)

if base_fast[benign].mean() > 0:
    rel = (
        improvement /
        base_fast[benign].mean()
    )

    print(
        "relative benign FAST gain =",
        f"{100*rel:.6f}%"
    )

sha = hashlib.sha256(
    path.read_bytes()
).hexdigest()

print()
print("GRID_SHA256 =", sha)
print("J5C2_ADAPTIVE_VAL_SEARCH_OK")
