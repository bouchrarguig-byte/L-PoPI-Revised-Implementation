from pathlib import Path
import json
import hashlib
import numpy as np
import pandas as pd

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
IN = BASE / "results/cog_gat/cog_gat_test_predictions.parquet"
OUT = BASE / "results/dpi_gating"
OUT.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------
# FROZEN BEFORE TEST
#
# Selected from VALIDATION only:
# largest validation Fast Path satisfying approximately
# <= 1% attack exposure.
#
# Validation result:
# tau_fast       = 0.416452
# benign FAST    = 59.60%
# attack FAST    = 0.98%
#
# DO NOT modify after observing TEST.
# ---------------------------------------------------------

TAU_FAST = 0.416452

df = pd.read_parquet(IN)

required = {
    "attack",
    "cog_gat_score",
    "category",
}

missing = required - set(df.columns)

if missing:
    raise RuntimeError(
        f"Missing required columns: {sorted(missing)}"
    )

y = df["attack"].to_numpy().astype(int)
score = df["cog_gat_score"].to_numpy(dtype=float)

fast = score < TAU_FAST
dpi = ~fast

benign = y == 0
attack = y == 1


def safe_rate(mask, population):
    n = int(population.sum())

    if n == 0:
        return float("nan")

    return float(
        (mask & population).sum() / n
    )


n_total = len(df)
n_fast = int(fast.sum())
n_dpi = int(dpi.sum())

metrics = {
    "policy": "two_path_cog_gat_dpi_gating",
    "tau_fast": TAU_FAST,
    "threshold_source": "validation_only",
    "validation_attack_fast_budget": 0.01,

    "n_total": n_total,
    "n_fast_path": n_fast,
    "n_dpi": n_dpi,

    "fast_path_rate": float(fast.mean()),
    "dpi_trigger_rate": float(dpi.mean()),

    # Relative to full-DPI baseline:
    "dpi_workload_reduction": float(
        1.0 - n_dpi / n_total
    ),

    "n_benign": int(benign.sum()),
    "n_attack": int(attack.sum()),

    "benign_fast_path_rate":
        safe_rate(fast, benign),

    "benign_dpi_rate":
        safe_rate(dpi, benign),

    "attack_fast_path_rate":
        safe_rate(fast, attack),

    "attack_dpi_rate":
        safe_rate(dpi, attack),

    "n_benign_fast":
        int((fast & benign).sum()),

    "n_benign_dpi":
        int((dpi & benign).sum()),

    "n_attack_fast":
        int((fast & attack).sum()),

    "n_attack_dpi":
        int((dpi & attack).sum()),
}


# ---------------------------------------------------------
# Attack-category analysis
# ---------------------------------------------------------

category_results = {}

categories = df["category"].astype(str).to_numpy()

for category in sorted(
    df.loc[attack, "category"]
      .dropna()
      .astype(str)
      .unique()
):

    population = (
        attack &
        (categories == category)
    )

    n = int(population.sum())

    category_results[category] = {
        "n": n,
        "fast_path_n":
            int((fast & population).sum()),

        "dpi_n":
            int((dpi & population).sum()),

        "fast_path_rate":
            safe_rate(fast, population),

        "dpi_rate":
            safe_rate(dpi, population),
    }


# ---------------------------------------------------------
# Save individual decisions
# ---------------------------------------------------------

out = df.copy()

out["dpi_policy_path"] = np.where(
    fast,
    "FAST_PATH",
    "DPI"
)

out_path = OUT / "locked_dpi_test_decisions.parquet"

out.to_parquet(
    out_path,
    index=False
)


# ---------------------------------------------------------
# Save metrics
# ---------------------------------------------------------

result = {
    "selection_protocol": {
        "selected_on": "validation only",
        "tau_fast": TAU_FAST,
        "validation_security_constraint":
            "attack fast-path rate approximately <= 1%",
        "test_threshold_adjustment": False,
    },

    "test": metrics,

    "attack_category_test":
        category_results,

    "interpretation": {
        "baseline":
            "DPI applied to every eligible flow",

        "fast_path":
            "Cog-GAT bypasses DPI",

        "dpi":
            "flow escalated to Deep Packet Inspection",

        "dpi_workload_reduction_definition":
            "1 - N_DPI / N_total",

        "important_limitation":
            "flow-count reduction, not measured CPU, energy, or latency reduction"
    }
}

json_path = (
    OUT /
    "locked_dpi_test_metrics.json"
)

json_path.write_text(
    json.dumps(
        result,
        indent=2
    )
)


# ---------------------------------------------------------
# Output
# ---------------------------------------------------------

print("=== FROZEN DPI POLICY ===")
print("tau_fast =", TAU_FAST)
print(
    "threshold selected using VALIDATION only"
)
print(
    "no TEST-dependent threshold adjustment"
)

print()
print("=== LOCKED TEST DPI GATING ===")

for k, v in metrics.items():
    print(f"{k} = {v}")

print()
print("=== ATTACK CATEGORY TEST ===")

for cat, m in category_results.items():
    print(
        f"{cat}: "
        f"N={m['n']} "
        f"FAST={m['fast_path_n']} "
        f"({100*m['fast_path_rate']:.3f}%) "
        f"DPI={m['dpi_n']} "
        f"({100*m['dpi_rate']:.3f}%)"
    )


print()
print("=== SHA256 ===")

for p in [
    json_path,
    out_path,
]:
    sha = hashlib.sha256(
        p.read_bytes()
    ).hexdigest()

    print(
        p.name,
        sha
    )

print()
print("J5_LOCKED_DPI_POLICY_OK")
