from pathlib import Path
import pandas as pd
import numpy as np

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"

VAL = BASE / "results/j5b/j5b_val_cog_scores.parquet"
OUT = BASE / "results/j5c"
OUT.mkdir(parents=True, exist_ok=True)

df = pd.read_parquet(VAL).copy()

df = df.sort_values(
    ["source_file", "stime", "source_row"],
    kind="mergesort"
).reset_index(drop=True)

print("=== J5-C STATEFUL TRUST — VAL ONLY ===")
print("N =", len(df))
print("files =", df.source_file.nunique())
print("data_2 present =", bool((df.source_file == "data_2.csv").any()))
print()

BETAS = [0.05, 0.10, 0.20, 0.40]
MIN_HIST = [2, 3, 5, 10]
TRUST_THRESHOLDS = np.arange(0.50, 0.991, 0.005)

rows = []

for beta in BETAS:
    for min_hist in MIN_HIST:

        trust_before = np.zeros(len(df))
        count_before = np.zeros(len(df), dtype=int)

        # State is reset for every original CSV.
        pos = 0

        for _, g in df.groupby("source_file", sort=False):

            trust = {}
            count = {}

            for _, row in g.iterrows():

                src = str(row["saddr"])
                risk = float(row["cog_score"])

                # Unknown source is conservative.
                old_t = trust.get(src, 0.0)
                old_n = count.get(src, 0)

                trust_before[pos] = old_t
                count_before[pos] = old_n

                # Update only AFTER current routing state
                # has been recorded: causal history.
                benign_evidence = 1.0 - risk

                if old_n == 0:
                    new_t = benign_evidence
                else:
                    new_t = (
                        (1.0 - beta) * old_t
                        + beta * benign_evidence
                    )

                trust[src] = new_t
                count[src] = old_n + 1
                pos += 1

        y = df["attack"].astype(int).to_numpy()
        risk = df["cog_score"].astype(float).to_numpy()

        benign = y == 0
        attack = y == 1

        for tau_t in TRUST_THRESHOLDS:

            # Important:
            # retain J5-B instantaneous safety condition.
            #
            # Stateful trust can only REMOVE Fast decisions,
            # never override a high current Cog risk.
            fast = (
                (risk < 0.3502524895843741)
                &
                (count_before >= min_hist)
                &
                (trust_before >= tau_t)
            )

            rows.append({
                "beta": beta,
                "min_history": min_hist,
                "tau_trust": float(tau_t),

                "benign_fast":
                    float(fast[benign].mean()),

                "attack_fast":
                    float(fast[attack].mean()),

                "total_fast":
                    float(fast.mean()),

                "dpi_rate":
                    float(1.0 - fast.mean())
            })

res = pd.DataFrame(rows)

path = OUT / "j5c_stateful_val_grid.csv"
res.to_csv(path, index=False)

print("=== BEST VAL CONFIGS UNDER SECURITY BUDGETS ===")

for budget in [0.001, 0.005, 0.01]:

    feasible = res[
        res.attack_fast <= budget
    ].copy()

    print()
    print(
        f"ATTACK FAST <= {100*budget:.1f}%"
    )

    if len(feasible) == 0:
        print("NO FEASIBLE CONFIG")
        continue

    best = feasible.sort_values(
        [
            "benign_fast",
            "attack_fast",
            "total_fast"
        ],
        ascending=[False, True, False]
    ).iloc[0]

    print(best.to_string())

print()
print("=== TOP 20 UNDER 1% ATTACK FAST ===")

top = (
    res[res.attack_fast <= 0.01]
    .sort_values(
        ["benign_fast", "attack_fast"],
        ascending=[False, True]
    )
    .head(20)
)

print(top.to_string(index=False))

print()
print("Saved:", path)
print("J5C_STATEFUL_VAL_SEARCH_OK")
