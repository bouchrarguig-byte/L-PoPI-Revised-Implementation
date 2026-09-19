from pathlib import Path
import pandas as pd
import json
import re

ROOT = Path.home() / "BoT-IoT"
OUT = Path.home() / "esp/sram_puf_clean/j5_ai/results"
OUT.mkdir(parents=True, exist_ok=True)

def number(p):
    m = re.search(r"data_(\d+)\.csv$", p.name)
    return int(m.group(1))

files = sorted(
    [p for p in ROOT.glob("data_*.csv")
     if p.name != "data_names.csv"],
    key=number
)

rows = []

for i, p in enumerate(files, 1):
    total = 0
    benign = 0
    attack = 0
    categories = {}

    for chunk in pd.read_csv(
        p,
        usecols=["attack", "category"],
        chunksize=250_000,
        low_memory=False
    ):
        a = pd.to_numeric(
            chunk["attack"], errors="coerce"
        ).fillna(0).astype(int)

        total += len(chunk)
        benign += int((a == 0).sum())
        attack += int((a == 1).sum())

        vc = chunk["category"].astype(str).value_counts()
        for k, v in vc.items():
            categories[k] = categories.get(k, 0) + int(v)

    rows.append({
        "file": p.name,
        "rows": total,
        "benign": benign,
        "attack": attack,
        "attack_fraction": attack / total if total else 0,
        "categories": json.dumps(
            categories, sort_keys=True
        )
    })

    print(
        f"[{i:02d}/{len(files)}] {p.name}: "
        f"N={total:,} benign={benign:,} "
        f"attack={attack:,} attack%={100*attack/total:.2f}"
    )

df = pd.DataFrame(rows)
df.to_csv(OUT / "botiot_file_distribution.csv", index=False)

print("\n=== GLOBAL ===")
print("files:", len(df))
print("rows:", f"{df.rows.sum():,}")
print("benign:", f"{df.benign.sum():,}")
print("attack:", f"{df.attack.sum():,}")
print(
    "attack fraction:",
    f"{100*df.attack.sum()/df.rows.sum():.4f}%"
)

print("\nSaved:")
print(OUT / "botiot_file_distribution.csv")
