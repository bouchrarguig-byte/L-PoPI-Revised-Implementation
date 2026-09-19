from pathlib import Path
import json
import hashlib
import numpy as np
import pandas as pd

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
COG = BASE / "results/cog_gat"
OUT = BASE / "results/dpi_gating"
OUT.mkdir(parents=True, exist_ok=True)

VAL_PATH = BASE / "results/gatv2/gatv2_val_predictions.parquet"
TEST_PATH = COG / "cog_gat_test_predictions.parquet"

# Cog-GAT selected on validation:
ALPHA = 0.10
LAMBDA = 0.50

# ------------------------------------------------------------
# Reconstruct the already-frozen Cog-GAT score on VAL.
# Causal source history only.
# ------------------------------------------------------------

def add_causal_src_history(df, alpha):
    work = df.sort_values(
        ["source_file", "stime", "source_row"]
    ).copy()

    history = np.full(len(work), np.nan, dtype=float)

    for _, idxs in work.groupby("source_file", sort=False).groups.items():
        state = {}

        for idx in idxs:
            pos = work.index.get_loc(idx)

            src = str(work.at[idx, "saddr"])
            p = float(work.at[idx, "gat_probability"])

            if src in state:
                history[pos] = state[src]

            if src not in state:
                state[src] = p
            else:
                state[src] = (
                    alpha * p +
                    (1.0 - alpha) * state[src]
                )

    work["h_src"] = history

    # Same fallback used in the Cog-GAT ablation:
    # unseen endpoint -> instantaneous GAT score.
    h = work["h_src"].to_numpy()
    p = work["gat_probability"].to_numpy()

    effective_h = np.where(np.isnan(h), p, h)

    work["cog_gat_score"] = (
        (1.0 - LAMBDA) * p +
        LAMBDA * effective_h
    )

    return work


def policy_counts(df, tau1, tau2):
    score = df["cog_gat_score"].to_numpy()
    y = df["attack"].to_numpy().astype(int)

    fast = score < tau1
    dpi = (score >= tau1) & (score < tau2)
    restrict = score >= tau2

    benign = y == 0
    attack = y == 1

    def rate(mask, population):
        n = int(population.sum())
        return float((mask & population).sum() / n) if n else np.nan

    return {
        "tau1": float(tau1),
        "tau2": float(tau2),

        "fast_path_rate": float(fast.mean()),
        "dpi_trigger_rate": float(dpi.mean()),
        "restrict_rate": float(restrict.mean()),

        "benign_fast_path_rate": rate(fast, benign),
        "benign_dpi_rate": rate(dpi, benign),
        "benign_restrict_rate": rate(restrict, benign),

        "attack_fast_path_rate": rate(fast, attack),
        "attack_dpi_rate": rate(dpi, attack),
        "attack_restrict_rate": rate(restrict, attack),

        # Relative to full-DPI baseline.
        # Restricted traffic is treated as blocked before DPI.
        "dpi_workload_reduction": float(1.0 - dpi.mean()),
    }


# ------------------------------------------------------------
# VALIDATION-ONLY policy selection
#
# Security constraint:
# <= 5% of validation attacks may enter FAST PATH.
#
# Among feasible policies:
# maximize benign FAST-PATH rate.
#
# tau2 is then chosen to maximize direct attack restriction
# while constraining benign restriction to <= 5%.
#
# These rules are frozen BEFORE TEST.
# ------------------------------------------------------------

val_raw = pd.read_parquet(VAL_PATH)
val = add_causal_src_history(val_raw, ALPHA)

scores = val["cog_gat_score"].to_numpy()

candidates = np.unique(
    np.quantile(scores, np.linspace(0.01, 0.99, 199))
)

rows = []

for tau1 in candidates:
    for tau2 in candidates:
        if tau2 <= tau1:
            continue

        m = policy_counts(val, tau1, tau2)

        if (
            m["attack_fast_path_rate"] <= 0.05
            and m["benign_restrict_rate"] <= 0.05
        ):
            rows.append(m)

if not rows:
    raise RuntimeError("No feasible validation policy found.")

grid = pd.DataFrame(rows)

# Primary objective:
# maximize benign traffic bypassing DPI.
#
# Tie-break:
# maximize attack restriction,
# then minimize total DPI invocation.
grid = grid.sort_values(
    [
        "benign_fast_path_rate",
        "attack_restrict_rate",
        "dpi_trigger_rate",
    ],
    ascending=[False, False, True]
).reset_index(drop=True)

selected = grid.iloc[0].to_dict()

grid.to_csv(
    OUT / "dpi_validation_policy_grid.csv",
    index=False
)

print("=== DPI GATING: SELECTED ON VALIDATION ONLY ===")
for k, v in selected.items():
    print(f"{k} = {v}")

# ------------------------------------------------------------
# LOCK POLICY, THEN TEST ONCE
# ------------------------------------------------------------

test = pd.read_parquet(TEST_PATH)

required = {"attack", "cog_gat_score", "category"}
missing = required - set(test.columns)
if missing:
    raise RuntimeError(f"Missing TEST columns: {missing}")

tau1 = selected["tau1"]
tau2 = selected["tau2"]

test_metrics = policy_counts(test, tau1, tau2)

score = test["cog_gat_score"].to_numpy()
y = test["attack"].to_numpy().astype(int)

path = np.where(
    score < tau1,
    "FAST_PATH",
    np.where(score < tau2, "DPI", "RESTRICT")
)

out_test = test.copy()
out_test["dpi_policy_path"] = path

out_test.to_parquet(
    OUT / "dpi_test_decisions.parquet",
    index=False
)

# Per attack category
category_results = {}

for category in sorted(out_test.loc[y == 1, "category"].dropna().unique()):
    mask = (y == 1) & (out_test["category"].to_numpy() == category)

    category_results[str(category)] = {
        "n": int(mask.sum()),
        "fast_path_rate": float(
            (path[mask] == "FAST_PATH").mean()
        ),
        "dpi_rate": float(
            (path[mask] == "DPI").mean()
        ),
        "restrict_rate": float(
            (path[mask] == "RESTRICT").mean()
        ),
    }

result = {
    "selection": {
        "dataset": "validation only",
        "alpha": ALPHA,
        "lambda": LAMBDA,
        "attack_fast_path_constraint": 0.05,
        "benign_restrict_constraint": 0.05,
        "objective": (
            "maximize benign fast-path rate; "
            "tie-break maximize attack restriction; "
            "then minimize DPI invocation"
        ),
        "tau1": tau1,
        "tau2": tau2,
    },
    "test": test_metrics,
    "attack_category_test": category_results,
    "interpretation": {
        "baseline": "full DPI on every eligible flow",
        "fast_path": "DPI bypass",
        "dpi": "DPI invoked",
        "restrict": "blocked/restricted before normal DPI",
        "dpi_workload_reduction_definition":
            "1 - N_DPI / N_total"
    }
}

json_path = OUT / "dpi_gating_test_metrics.json"
json_path.write_text(
    json.dumps(result, indent=2)
)

print()
print("=== LOCKED TEST DPI GATING ===")

for k, v in test_metrics.items():
    print(f"{k} = {v}")

print()
print("=== ATTACK CATEGORY PATHS ===")

for cat, m in category_results.items():
    print(
        f"{cat}: N={m['n']} "
        f"FAST={m['fast_path_rate']:.6f} "
        f"DPI={m['dpi_rate']:.6f} "
        f"RESTRICT={m['restrict_rate']:.6f}"
    )

print()
for p in [
    OUT / "dpi_validation_policy_grid.csv",
    OUT / "dpi_test_decisions.parquet",
    OUT / "dpi_gating_test_metrics.json",
]:
    sha = hashlib.sha256(p.read_bytes()).hexdigest()
    print("SHA256", p.name, sha)

print()
print("J5_DPI_GATING_OK")
