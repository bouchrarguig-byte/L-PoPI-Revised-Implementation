from pathlib import Path
import pandas as pd
import numpy as np
import json
import hashlib

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
OUT = BASE / "results/j5c3"
GAT = OUT / "gatv2"

VAL_PATH = GAT / "gatv2_j5c3_val_predictions.parquet"
POLICY_PATH = OUT / "j5c3_frozen_dpi_policies.json"
GRID_PATH = OUT / "j5c3_adaptive_val_grid.csv"

BUDGET = 0.01
ALPHA = 0.10
LAMBDA = 0.50

BETAS = [0.05, 0.10, 0.20, 0.40]
MIN_HIST = [2, 3, 5, 10, 20]
TRUST_TAUS = np.arange(0.50, 0.951, 0.025)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()

df = pd.read_parquet(VAL_PATH).copy()

required = {
    "source_file", "stime", "source_row",
    "saddr", "attack"
}
missing = required - set(df.columns)
assert not missing, missing

# Find GAT probability column robustly.
candidates = [
    "gat_probability",
    "prob_attack",
    "attack_prob",
    "prob",
    "score",
    "y_prob"
]

prob_col = next(
    (c for c in candidates if c in df.columns),
    None
)

if prob_col is None:
    raise RuntimeError(
        f"Cannot identify GAT probability column. "
        f"Columns={list(df.columns)}"
    )

df = df.sort_values(
    ["source_file", "stime", "source_row"],
    kind="mergesort"
).reset_index(drop=True)

# -------------------------------------------------------
# Frozen causal Cog mechanism.
# Same semantics as J5-B:
# source history of PRIOR GAT scores only.
# -------------------------------------------------------

gat = df[prob_col].astype(float).to_numpy()
cog = np.zeros(len(df), dtype=float)

pos = 0

for _, g in df.groupby("source_file", sort=False):
    state = {}

    for _, row in g.iterrows():
        src = str(row["saddr"])
        gscore = float(row[prob_col])

        hist = state.get(src, gscore)

        cog[pos] = (
            (1.0 - LAMBDA) * gscore
            + LAMBDA * hist
        )

        state[src] = (
            (1.0 - ALPHA) * hist
            + ALPHA * gscore
        )

        pos += 1

df["cog_score"] = cog

y = df["attack"].astype(int).to_numpy()
benign = y == 0
attack = y == 1

# -------------------------------------------------------
# Baseline threshold:
# largest observed Cog score satisfying attack FAST <=1%.
# FAST iff score < threshold.
# -------------------------------------------------------

attack_scores = np.sort(
    np.unique(cog[attack])
)

threshold_candidates = np.concatenate([
    [np.nextafter(cog.min(), -np.inf)],
    attack_scores,
    [np.nextafter(cog.max(), np.inf)]
])

baseline_rows = []

for tau in threshold_candidates:
    fast = cog < tau
    af = float(fast[attack].mean())

    if af <= BUDGET:
        baseline_rows.append((
            float(tau),
            float(fast[benign].mean()),
            af,
            float(fast.mean())
        ))

if not baseline_rows:
    raise RuntimeError("No baseline feasible threshold")

# Maximize benign FAST, then minimize attack FAST.
baseline_rows.sort(
    key=lambda z: (z[1], -z[2], z[3]),
    reverse=True
)

base_tau, base_bf, base_af, base_tf = baseline_rows[0]

print("=== J5-C3 VAL BASELINE ===")
print("tau_fast =", base_tau)
print("benign_FAST =", f"{100*base_bf:.6f}%")
print("attack_FAST =", f"{100*base_af:.6f}%")
print("total_FAST  =", f"{100*base_tf:.6f}%")
print("DPI         =", f"{100*(1-base_tf):.6f}%")

# -------------------------------------------------------
# Adaptive threshold.
#
# Unprivileged sources retain baseline threshold.
# Mature/trusted sources may receive an elevated threshold.
# Elevated thresholds are derived from observed VAL scores
# rather than an arbitrary hard-coded upper bound.
# -------------------------------------------------------

quantiles = np.arange(0.50, 1.00, 0.01)
elevated_taus = np.unique(
    np.quantile(cog, quantiles)
)

elevated_taus = elevated_taus[
    elevated_taus > base_tau
]

rows = []

for beta in BETAS:

    trust_before = np.zeros(len(df))
    count_before = np.zeros(len(df), dtype=int)

    pos = 0

    for _, g in df.groupby("source_file", sort=False):
        trust = {}
        count = {}

        for _, row in g.iterrows():
            src = str(row["saddr"])
            risk = float(row["cog_score"])

            old_t = trust.get(src, 0.0)
            old_n = count.get(src, 0)

            trust_before[pos] = old_t
            count_before[pos] = old_n

            evidence = 1.0 - risk

            if old_n == 0:
                new_t = evidence
            else:
                new_t = (
                    (1.0-beta)*old_t
                    + beta*evidence
                )

            trust[src] = new_t
            count[src] = old_n + 1
            pos += 1

    for min_hist in MIN_HIST:
        mature = count_before >= min_hist

        for tau_trust in TRUST_TAUS:
            privileged = (
                mature
                & (trust_before >= tau_trust)
            )

            for elevated_tau in elevated_taus:

                effective_tau = np.where(
                    privileged,
                    elevated_tau,
                    base_tau
                )

                fast = cog < effective_tau

                rows.append({
                    "beta": float(beta),
                    "min_history": int(min_hist),
                    "tau_trust": float(tau_trust),
                    "elevated_tau": float(elevated_tau),
                    "benign_fast":
                        float(fast[benign].mean()),
                    "attack_fast":
                        float(fast[attack].mean()),
                    "total_fast":
                        float(fast.mean()),
                    "dpi_rate":
                        float(1-fast.mean()),
                    "privileged_fraction":
                        float(privileged.mean())
                })

grid = pd.DataFrame(rows)
grid.to_csv(GRID_PATH, index=False)

feasible = grid[
    grid.attack_fast <= BUDGET
].copy()

if feasible.empty:
    raise RuntimeError(
        "No adaptive policy satisfies 1% budget"
    )

best = feasible.sort_values(
    ["benign_fast", "attack_fast", "total_fast"],
    ascending=[False, True, False]
).iloc[0]

print()
print("=== J5-C3 VAL ADAPTIVE ===")
print(best.to_string())

gain_pp = (
    float(best.benign_fast) - base_bf
) * 100

print()
print(
    "Benign FAST gain vs baseline =",
    f"{gain_pp:.6f} percentage points"
)

policy = {
    "experiment": "J5-C3",
    "status": "FROZEN_BEFORE_TEST_C",

    "security_budget_attack_fast": BUDGET,

    "cog": {
        "alpha": ALPHA,
        "lambda": LAMBDA,
        "history": "causal prior source scores only",
        "state_reset": "per source_file"
    },

    "baseline": {
        "tau_fast": base_tau,
        "val_benign_fast": base_bf,
        "val_attack_fast": base_af,
        "val_total_fast": base_tf
    },

    "adaptive": {
        "base_tau": base_tau,
        "beta": float(best.beta),
        "min_history": int(best.min_history),
        "tau_trust": float(best.tau_trust),
        "elevated_tau": float(best.elevated_tau),
        "val_benign_fast": float(best.benign_fast),
        "val_attack_fast": float(best.attack_fast),
        "val_total_fast": float(best.total_fast),
        "val_privileged_fraction":
            float(best.privileged_fraction)
    },

    "test_c_rule": (
        "No policy parameter may be changed after "
        "TEST-C is opened."
    ),

    "model_sha256":
        sha256(GAT / "best_gatv2.pt"),

    "val_predictions_sha256":
        sha256(VAL_PATH),

    "split_manifest_sha256":
        sha256(OUT / "j5c3_manifest.json"),

    "test_c_sealed_sha256":
        sha256(OUT / "j5c3_test_SEALED.parquet")
}

with open(POLICY_PATH, "w") as f:
    json.dump(
        policy,
        f,
        indent=2,
        sort_keys=True
    )

print()
print("GRID_SHA256 =", sha256(GRID_PATH))
print("POLICY_SHA256 =", sha256(POLICY_PATH))
print(
    "TEST_C_SEALED_SHA256 =",
    sha256(OUT / "j5c3_test_SEALED.parquet")
)

print()
print("TEST-C remains unopened.")
print("J5C3_DPI_POLICIES_FROZEN_OK")
