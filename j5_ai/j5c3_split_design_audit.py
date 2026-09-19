from pathlib import Path
import pandas as pd
import numpy as np

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"

FILES = [
    BASE / "prepared/j5_train.parquet",
    BASE / "prepared/j5_val.parquet",
    BASE / "prepared/j5_test.parquet",
]

# Reconstruct the complete controlled cohort.
df = pd.concat(
    [
        pd.read_parquet(
            p,
            columns=["source_file", "category", "attack"]
        )
        for p in FILES
    ],
    ignore_index=True
)

def file_num(x):
    return int(
        str(x)
        .replace("data_", "")
        .replace(".csv", "")
    )

df["file_num"] = df["source_file"].map(file_num)

print("=== J5-C3 SPLIT DESIGN AUDIT ===")
print("Rows =", len(df))
print("Files =", df["source_file"].nunique())
print("Range =", df.file_num.min(), "..", df.file_num.max())

assert df["source_file"].nunique() == 74
assert df.file_num.nunique() == 74

# -------------------------------------------------------
# Candidate chronological/block splits.
#
# No predictions are read.
# No model performance is evaluated.
# -------------------------------------------------------

CANDIDATES = [
    # train_end, val_end
    (50, 62),   # 50 / 12 / 12 files
    (48, 61),   # 48 / 13 / 13
    (52, 63),   # 52 / 11 / 11
    (46, 60),   # 46 / 14 / 14
]

for train_end, val_end in CANDIDATES:

    print()
    print("=" * 70)
    print(
        f"CANDIDATE: "
        f"TRAIN-C data_1..data_{train_end}, "
        f"VAL-C data_{train_end+1}..data_{val_end}, "
        f"TEST-C data_{val_end+1}..data_74"
    )

    split = np.where(
        df.file_num <= train_end,
        "TRAIN-C",
        np.where(
            df.file_num <= val_end,
            "VAL-C",
            "TEST-C"
        )
    )

    tmp = df.assign(split=split)

    for name in ["TRAIN-C", "VAL-C", "TEST-C"]:
        g = tmp[tmp.split == name]

        print()
        print(name)
        print(" files =", g.source_file.nunique())
        print(" rows  =", len(g))
        print(
            " benign =",
            int((g.attack == 0).sum())
        )
        print(
            " attack =",
            int((g.attack == 1).sum())
        )

        print(" categories:")
        print(
            g.category.value_counts()
            .sort_index()
            .to_string()
        )

print()
print("J5C3_SPLIT_DESIGN_AUDIT_OK")
