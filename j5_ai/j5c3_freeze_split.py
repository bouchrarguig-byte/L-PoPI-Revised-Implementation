from pathlib import Path
import pandas as pd
import json
import hashlib

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
OUT = BASE / "results/j5c3"
OUT.mkdir(parents=True, exist_ok=True)

INPUTS = [
    BASE / "prepared/j5_train.parquet",
    BASE / "prepared/j5_val.parquet",
    BASE / "prepared/j5_test.parquet",
]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()

def file_num(x):
    return int(
        str(x)
        .replace("data_", "")
        .replace(".csv", "")
    )

# Full controlled cohort. This does not recreate the 73M-row raw corpus;
# it repartitions the already frozen controlled cohort.
df = pd.concat(
    [pd.read_parquet(p) for p in INPUTS],
    ignore_index=True
)

df["__file_num"] = df["source_file"].map(file_num)

assert df["source_file"].nunique() == 74
assert len(df) == 104973

train = df[df["__file_num"] <= 50].copy()
val = df[
    (df["__file_num"] >= 51)
    & (df["__file_num"] <= 62)
].copy()
test = df[df["__file_num"] >= 63].copy()

for x in (train, val, test):
    x.drop(columns=["__file_num"], inplace=True)

# Deterministic row order.
SORT = ["source_file", "stime", "source_row"]

for x in (train, val, test):
    x.sort_values(
        SORT,
        kind="mergesort",
        inplace=True
    )
    x.reset_index(drop=True, inplace=True)

TRAIN_PATH = OUT / "j5c3_train.parquet"
VAL_PATH = OUT / "j5c3_val.parquet"
TEST_PATH = OUT / "j5c3_test_SEALED.parquet"

train.to_parquet(TRAIN_PATH, index=False)
val.to_parquet(VAL_PATH, index=False)
test.to_parquet(TEST_PATH, index=False)

# Verify strict file separation.
tf = set(train.source_file.unique())
vf = set(val.source_file.unique())
sf = set(test.source_file.unique())

assert not (tf & vf)
assert not (tf & sf)
assert not (vf & sf)

assert len(tf) == 50
assert len(vf) == 12
assert len(sf) == 12

manifest = {
    "experiment": "J5-C3",
    "status": "split-frozen-before-training",

    "purpose": (
        "Controlled late-file DDoS-dominant evaluation "
        "of baseline versus adaptive DPI gating."
    ),

    "source_population": (
        "Previously constructed 104,973-flow controlled "
        "BoT-IoT cohort; this is a new deterministic "
        "repartition, not a new external dataset."
    ),

    "split_rule": {
        "unit": "source_file",
        "ordering": "numeric data_i.csv index",
        "train_c": "data_1.csv through data_50.csv",
        "val_c": "data_51.csv through data_62.csv",
        "test_c": "data_63.csv through data_74.csv"
    },

    "selection_rule": (
        "No model predictions were used to choose "
        "the 50/12/12 block split."
    ),

    "primary_policy_objective": (
        "Maximize benign Fast-Path rate on VAL-C "
        "subject to attack Fast-Path rate <= 1%."
    ),

    "comparison": [
        "global Cog-GAT threshold baseline",
        "causal adaptive-trust threshold policy"
    ],

    "test_opening_rule": (
        "TEST-C predictions and performance must not "
        "be computed until the model, Cog mechanism, "
        "baseline policy, adaptive policy, and their "
        "artifact hashes have been frozen."
    ),

    "limitations_declared_before_training": [
        (
            "TEST-C contains only Normal and DDoS "
            "within this controlled cohort."
        ),
        (
            "J5-C3 therefore evaluates a late-file/"
            "distribution shift, not held-out "
            "Reconnaissance or universal OOD generalization."
        ),
        (
            "The underlying 74 source files were used "
            "in earlier J5 experiments; TEST-C is a "
            "newly pre-specified evaluation fold, not "
            "a previously unseen external dataset."
        )
    ],

    "counts": {
        "train_c": {
            "files": int(train.source_file.nunique()),
            "rows": int(len(train)),
            "benign": int((train.attack == 0).sum()),
            "attack": int((train.attack == 1).sum())
        },
        "val_c": {
            "files": int(val.source_file.nunique()),
            "rows": int(len(val)),
            "benign": int((val.attack == 0).sum()),
            "attack": int((val.attack == 1).sum())
        },
        "test_c": {
            "files": int(test.source_file.nunique()),
            "rows": int(len(test)),
            "benign": int((test.attack == 0).sum()),
            "attack": int((test.attack == 1).sum())
        }
    }
}

MANIFEST = OUT / "j5c3_manifest.json"

with open(MANIFEST, "w") as f:
    json.dump(
        manifest,
        f,
        indent=2,
        sort_keys=True
    )

print("=== J5-C3 SPLIT FREEZE ===")

for name, path, part in [
    ("TRAIN-C", TRAIN_PATH, train),
    ("VAL-C", VAL_PATH, val),
    ("TEST-C SEALED", TEST_PATH, test)
]:
    print()
    print(name)
    print("rows =", len(part))
    print("files =", part.source_file.nunique())
    print("SHA256 =", sha256(path))

print()
print("MANIFEST_SHA256 =", sha256(MANIFEST))

freeze = {
    "manifest_sha256": sha256(MANIFEST),
    "train_sha256": sha256(TRAIN_PATH),
    "val_sha256": sha256(VAL_PATH),
    "test_sealed_sha256": sha256(TEST_PATH)
}

FREEZE = OUT / "j5c3_split_freeze.json"

with open(FREEZE, "w") as f:
    json.dump(
        freeze,
        f,
        indent=2,
        sort_keys=True
    )

print("FREEZE_SHA256 =", sha256(FREEZE))

print()
print("TEST-C STATUS = SEALED")
print("NO TEST-C PREDICTIONS COMPUTED")
print("J5C3_SPLIT_FROZEN_OK")
