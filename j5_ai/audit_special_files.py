from pathlib import Path
import pandas as pd
import numpy as np

ROOT = Path.home() / "BoT-IoT"
OUT = Path("results")
OUT.mkdir(exist_ok=True)

for name in ["data_1.csv", "data_2.csv"]:
    path = ROOT / name

    print("\n" + "=" * 72)
    print(name)
    print("=" * 72)

    df = pd.read_csv(
        path,
        usecols=["stime", "attack", "category"],
        low_memory=False
    )

    df["stime"] = pd.to_numeric(df["stime"], errors="coerce")
    df["attack"] = pd.to_numeric(
        df["attack"], errors="coerce"
    ).fillna(0).astype(int)

    df = df.dropna(subset=["stime"]).sort_values("stime").reset_index(drop=True)

    print("rows:", len(df))
    print("stime min:", df.stime.min())
    print("stime max:", df.stime.max())
    print("monotonic after sort:", df.stime.is_monotonic_increasing)

    # Ten non-overlapping chronological blocks
    block = np.floor(
        np.arange(len(df)) * 10 / len(df)
    ).astype(int)
    block = np.minimum(block, 9)
    df["block"] = block

    rows = []

    print("\nChronological deciles:")

    for b, g in df.groupby("block"):
        counts = g["category"].value_counts().to_dict()

        row = {
            "file": name,
            "block": int(b),
            "rows": len(g),
            "stime_min": g.stime.min(),
            "stime_max": g.stime.max(),
            "benign": int((g.attack == 0).sum()),
            "attack": int((g.attack == 1).sum()),
            **{
                f"cat_{k}": int(v)
                for k, v in counts.items()
            }
        }

        rows.append(row)

        print(
            f"B{b}: N={len(g):,} "
            f"benign={row['benign']:,} "
            f"attack={row['attack']:,} "
            f"categories={counts}"
        )

    pd.DataFrame(rows).to_csv(
        OUT / f"{name[:-4]}_temporal_blocks.csv",
        index=False
    )
