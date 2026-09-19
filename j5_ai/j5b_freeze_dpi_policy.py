from pathlib import Path
import json
import hashlib
import numpy as np
import pandas as pd

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
INP = BASE / "results/j5b/gatv2_shift/gatv2_j5b_val_predictions.parquet"
OUT = BASE / "results/j5b"
OUT.mkdir(parents=True, exist_ok=True)

ALPHA = 0.10
LAMBDA = 0.50
ATTACK_FAST_BUDGET = 0.01

df = pd.read_parquet(INP).copy()

# Deterministic causal order.
df["_idx"] = np.arange(len(df))
w = df.sort_values(
    ["source_file", "stime", "source_row"],
    kind="mergesort"
).copy()

scores = []

for source_file, g in w.groupby("source_file", sort=False):
    state = {}

    for _, row in g.iterrows():
        src = str(row["saddr"])
        p = float(row["gat_probability"])

        hist = state.get(src, p)

        cog = (
            (1.0 - LAMBDA) * p
            + LAMBDA * hist
        )

        scores.append(cog)

        # causal update after current decision
        state[src] = (
            (1.0 - ALPHA) * hist
            + ALPHA * p
        )

w["cog_score"] = np.asarray(scores)
w = w.sort_values("_idx").reset_index(drop=True)

y = w["attack"].astype(int).to_numpy()
s = w["cog_score"].astype(float).to_numpy()

benign = y == 0
attack = y == 1

print("=== J5-B DPI POLICY CALIBRATION ===")
print("Challenge data_2 used = NO")
print("Original J5 TEST used = NO")
print("mode = src")
print("alpha =", ALPHA)
print("lambda =", LAMBDA)
print("attack_FAST_budget =", ATTACK_FAST_BUDGET)
print()

# ------------------------------------------------------
# Select largest threshold satisfying attack FAST <= 1%.
#
# Candidate thresholds are observed validation scores.
# FAST iff score < tau.
# ------------------------------------------------------

candidates = np.unique(s)
best_tau = None

for tau in candidates:
    fast = s < tau
    afr = fast[attack].mean()

    if afr <= ATTACK_FAST_BUDGET:
        best_tau = float(tau)

if best_tau is None:
    raise RuntimeError("No feasible threshold")

fast = s < best_tau

benign_fast = fast[benign].mean()
attack_fast = fast[attack].mean()
total_fast = fast.mean()

print("=== FROZEN SCORE-ONLY POLICY ===")
print(f"tau_fast = {best_tau:.12f}")
print(f"benign_FAST = {100*benign_fast:.6f}%")
print(f"attack_FAST = {100*attack_fast:.6f}%")
print(f"total_FAST = {100*total_fast:.6f}%")
print(f"DPI = {100*(1-total_fast):.6f}%")
print()

# ------------------------------------------------------
# Uncertainty guard.
# We pre-declared u <= 0.70 from the previous VAL-only
# diagnostic. It is NOT selected using data_2.
# ------------------------------------------------------

U_LIMIT = 0.70
uncertainty = 1.0 - np.abs(2.0*s - 1.0)

fast_u = (
    (s < best_tau)
    & (uncertainty <= U_LIMIT)
)

print("=== PREDECLARED UNCERTAINTY GUARD ===")
print("u_limit =", U_LIMIT)
print(
    "benign_FAST =",
    f"{100*fast_u[benign].mean():.6f}%"
)
print(
    "attack_FAST =",
    f"{100*fast_u[attack].mean():.6f}%"
)
print(
    "total_FAST =",
    f"{100*fast_u.mean():.6f}%"
)
print(
    "DPI =",
    f"{100*(1-fast_u.mean()):.6f}%"
)
print()

policy = {
    "experiment": "J5-B",
    "challenge_opened": False,
    "challenge_file": "data_2.csv",
    "cognitive_history": {
        "mode": "src",
        "alpha": ALPHA,
        "lambda": LAMBDA
    },
    "dpi_policy": {
        "fast_condition": "cog_score < tau_fast",
        "validation_attack_fast_budget": ATTACK_FAST_BUDGET,
        "tau_fast": best_tau
    },
    "uncertainty_guard": {
        "predeclared": True,
        "limit": U_LIMIT,
        "condition": "uncertainty <= limit"
    },
    "validation": {
        "n": int(len(w)),
        "benign_fast_score_only": float(benign_fast),
        "attack_fast_score_only": float(attack_fast),
        "total_fast_score_only": float(total_fast),
        "benign_fast_with_uncertainty":
            float(fast_u[benign].mean()),
        "attack_fast_with_uncertainty":
            float(fast_u[attack].mean()),
        "total_fast_with_uncertainty":
            float(fast_u.mean())
    }
}

path = OUT / "j5b_frozen_dpi_policy.json"

with open(path, "w") as f:
    json.dump(policy, f, indent=2)

sha = hashlib.sha256(path.read_bytes()).hexdigest()

scores_path = OUT / "j5b_val_cog_scores.parquet"
w.drop(columns=["_idx"]).to_parquet(
    scores_path,
    index=False
)

scores_sha = hashlib.sha256(
    scores_path.read_bytes()
).hexdigest()

print("POLICY_SHA256 =", sha)
print("VAL_COG_SHA256 =", scores_sha)
print()
print("J5B_DPI_POLICY_FROZEN_OK")
