from pathlib import Path
import json
import pandas as pd

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"

MANIFEST = BASE / "results/j5_split_manifest.json"
TRAIN = BASE / "prepared/j5_train.parquet"
VAL   = BASE / "prepared/j5_val.parquet"
TEST  = BASE / "prepared/j5_test.parquet"

print("=== J5-C CONFIRMATORY AVAILABILITY AUDIT ===")

with open(MANIFEST, "r") as f:
    manifest = json.load(f)

print("\nManifest keys:", list(manifest.keys()))

dfs = {
    "TRAIN": pd.read_parquet(
        TRAIN,
        columns=["source_file", "category"]
    ),
    "VAL": pd.read_parquet(
        VAL,
        columns=["source_file", "category"]
    ),
    "TEST": pd.read_parquet(
        TEST,
        columns=["source_file", "category"]
    ),
}

sets = {}

for split, df in dfs.items():
    files = sorted(df["source_file"].astype(str).unique())
    sets[split] = set(files)

    print(f"\n=== {split} ===")
    print("files =", len(files))
    print("rows  =", len(df))
    print("file list:")
    for x in files:
        print(" ", x)

    print("categories:")
    print(
        df["category"]
        .value_counts()
        .to_string()
    )

print("\n=== OVERLAP AUDIT ===")

for a, b in [
    ("TRAIN", "VAL"),
    ("TRAIN", "TEST"),
    ("VAL", "TEST")
]:
    inter = sets[a] & sets[b]
    print(
        f"{a} ∩ {b}:",
        len(inter),
        sorted(inter)
    )

# -------------------------------------------------------
# Experimental-use history
# -------------------------------------------------------
#
# J5-B model:
#   TRAIN minus data_2.csv
#
# J5-B/C2 development:
#   VAL used for model/policy selection
#
# Previously observed:
#   original TEST already evaluated in J5-A
#   data_2.csv already opened in J5-B challenge
# -------------------------------------------------------

j5b_model_files = sets["TRAIN"] - {"data_2.csv"}

already_observed_for_results = (
    sets["TEST"]
    | {"data_2.csv"}
)

used_for_tuning = sets["VAL"]

all_controlled = (
    sets["TRAIN"]
    | sets["VAL"]
    | sets["TEST"]
)

candidate_unused = (
    all_controlled
    - j5b_model_files
    - used_for_tuning
    - already_observed_for_results
)

print("\n=== EXPERIMENTAL PROVENANCE ===")
print(
    "J5-B model-fitting files =",
    len(j5b_model_files)
)
print(
    "J5-C2 tuning files =",
    len(used_for_tuning)
)
print(
    "previously observed result files =",
    len(already_observed_for_results)
)

print("\n=== STRICT UNUSED CANDIDATES ===")
print("count =", len(candidate_unused))
print(sorted(candidate_unused))

if len(candidate_unused) == 0:
    print(
        "\nCONCLUSION: NO STRICTLY INDEPENDENT "
        "CONFIRMATORY FILE REMAINS IN THE "
        "CURRENT CONTROLLED SPLIT."
    )
else:
    print(
        "\nCONCLUSION: UNUSED CANDIDATES EXIST; "
        "DO NOT OPEN THEIR LABEL/PREDICTION "
        "PERFORMANCE YET."
    )

print("\nJ5C_CONFIRMATORY_AVAILABILITY_AUDIT_OK")
