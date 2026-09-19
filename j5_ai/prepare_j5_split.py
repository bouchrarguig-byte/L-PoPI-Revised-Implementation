from pathlib import Path
import pandas as pd
import numpy as np
import json
import hashlib

SEED = 20260916

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
SRC = BASE / "results/botiot_file_distribution.csv"
OUT = BASE / "results"
OUT.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(SRC)

# Fixed partition sizes: 52 / 11 / 11 files
sizes = {"train": 52, "val": 11, "test": 11}

# Desired benign proportions
targets = {
    "train": 0.70 * df["benign"].sum(),
    "val":   0.15 * df["benign"].sum(),
    "test":  0.15 * df["benign"].sum(),
}

rng = np.random.default_rng(SEED)

def score(assign):
    s = 0.0

    for split in ("train", "val", "test"):
        idx = assign[split]
        benign = df.loc[idx, "benign"].sum()

        # Relative benign-count deviation
        s += ((benign - targets[split]) /
              max(targets[split], 1)) ** 2

    return float(s)

best = None
best_score = float("inf")

# Randomized grouped search.
# No rows are split: only complete CSV files move.
for _ in range(200_000):
    perm = rng.permutation(len(df))

    assign = {
        "train": perm[:52],
        "val":   perm[52:63],
        "test":  perm[63:74],
    }

    sc = score(assign)

    if sc < best_score:
        best_score = sc
        best = {
            k: np.array(v, copy=True)
            for k, v in assign.items()
        }

manifest = {
    "seed": SEED,
    "group_unit": "complete BoT-IoT CSV file",
    "target_file_counts": sizes,
    "optimization_target":
        "approximately 70/15/15 percent of benign flows",
    "splits": {}
}

print("=== FINAL GROUPED SPLIT ===")

for split in ("train", "val", "test"):
    part = df.loc[best[split]].copy()
    part = part.sort_values("file")

    benign = int(part["benign"].sum())
    attack = int(part["attack"].sum())
    rows = int(part["rows"].sum())

    manifest["splits"][split] = {
        "files": part["file"].tolist(),
        "file_count": len(part),
        "rows": rows,
        "benign": benign,
        "attack": attack,
        "benign_fraction_of_global":
            benign / df["benign"].sum(),
        "attack_fraction":
            attack / rows
    }

    print(f"\n{split.upper()}")
    print("files:", len(part))
    print("rows:", f"{rows:,}")
    print("benign:", f"{benign:,}")
    print("attack:", f"{attack:,}")
    print(
        "global benign share:",
        f"{100*benign/df['benign'].sum():.3f}%"
    )
    print("file list:")
    print(", ".join(part["file"].tolist()))

manifest_path = OUT / "j5_split_manifest.json"

with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=2)

digest = hashlib.sha256(
    manifest_path.read_bytes()
).hexdigest()

(OUT / "j5_split_manifest.sha256").write_text(
    f"{digest}  {manifest_path.name}\n"
)

print("\nOptimization score:", best_score)
print("Manifest:", manifest_path)
print("SHA256:", digest)
