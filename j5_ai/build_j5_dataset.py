from pathlib import Path
import pandas as pd
import numpy as np
import json
import hashlib
import joblib
from sklearn.preprocessing import StandardScaler

SEED = 20260916
ATTACK_RATIO = 10

ROOT = Path.home() / "BoT-IoT"
BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
RESULTS = BASE / "results"
DATAOUT = BASE / "prepared"
DATAOUT.mkdir(parents=True, exist_ok=True)

FEATURES = ["pkts", "bytes", "seq", "dur"]
USECOLS = [
    "pkSeqID", "stime", "saddr", "daddr",
    *FEATURES, "attack", "category", "subcategory "
]

manifest = json.loads(
    (RESULTS / "j5_split_manifest.json").read_text()
)

def deterministic_score(file_name, row_id):
    s = f"{SEED}|{file_name}|{row_id}".encode()
    return hashlib.sha256(s).digest()

def load_file(path):
    parts = []

    for chunk in pd.read_csv(
        path,
        usecols=USECOLS,
        chunksize=250_000,
        low_memory=False
    ):
        chunk["attack"] = pd.to_numeric(
            chunk["attack"], errors="coerce"
        ).fillna(0).astype(np.int8)

        for c in FEATURES:
            chunk[c] = pd.to_numeric(
                chunk[c], errors="coerce"
            ).replace([np.inf, -np.inf], np.nan).fillna(0)

        parts.append(chunk)

    return pd.concat(parts, ignore_index=True)

def build_split(split):
    benign_parts = []
    attack_parts = []

    files = manifest["splits"][split]["files"]

    print(f"\n=== {split.upper()} ===")

    for i, name in enumerate(files, 1):
        df = load_file(ROOT / name)

        df["source_file"] = name
        df["source_row"] = np.arange(len(df), dtype=np.int64)

        benign = df[df.attack == 0].copy()
        attack = df[df.attack == 1].copy()

        benign_parts.append(benign)

        # Keep a bounded deterministic candidate set per file.
        # Final split-wide selection happens below.
        max_candidate = max(5000, len(benign) * ATTACK_RATIO * 4)

        if len(attack) > max_candidate:
            rng = np.random.default_rng(
                SEED + int(
                    hashlib.sha256(name.encode()).hexdigest()[:8], 16
                )
            )
            idx = rng.choice(
                len(attack),
                size=max_candidate,
                replace=False
            )
            attack = attack.iloc[idx].copy()

        attack_parts.append(attack)

        print(
            f"[{i:02d}/{len(files)}] {name}: "
            f"benign={len(benign):,} "
            f"attack_candidates={len(attack):,}"
        )

    benign = pd.concat(benign_parts, ignore_index=True)
    attacks = pd.concat(attack_parts, ignore_index=True)

    target_attack = min(
        len(attacks),
        ATTACK_RATIO * len(benign)
    )

    # Stable deterministic ordering independent of dataframe order.
    keys = [
        deterministic_score(f, r)
        for f, r in zip(
            attacks["source_file"],
            attacks["source_row"]
        )
    ]

    order = np.argsort(
        np.array(
            [int.from_bytes(k[:8], "big") for k in keys],
            dtype=np.uint64
        )
    )

    attacks = attacks.iloc[
        order[:target_attack]
    ].copy()

    cohort = pd.concat(
        [benign, attacks],
        ignore_index=True
    )

    rng = np.random.default_rng(SEED)
    cohort = cohort.iloc[
        rng.permutation(len(cohort))
    ].reset_index(drop=True)

    print(
        f"{split}: final benign={len(benign):,}, "
        f"attack={len(attacks):,}, "
        f"total={len(cohort):,}"
    )

    return cohort

datasets = {}

for split in ["train", "val", "test"]:
    datasets[split] = build_split(split)

# -------------------------------------------------
# Fit preprocessing on TRAIN ONLY
# -------------------------------------------------

scaler = StandardScaler()
scaler.fit(datasets["train"][FEATURES].values)

joblib.dump(
    scaler,
    RESULTS / "j5_train_only_scaler.joblib"
)

for split, df in datasets.items():
    scaled = scaler.transform(df[FEATURES].values)

    for j, c in enumerate(FEATURES):
        df[f"z_{c}"] = scaled[:, j]

    out = DATAOUT / f"j5_{split}.parquet"
    df.to_parquet(out, index=False)

    digest = hashlib.sha256(out.read_bytes()).hexdigest()

    print(
        f"{split}: {out.name} "
        f"rows={len(df):,} SHA256={digest}"
    )

# Metadata
meta = {
    "seed": SEED,
    "attack_to_benign_ratio_cap": ATTACK_RATIO,
    "features": FEATURES,
    "split_manifest_sha256":
        hashlib.sha256(
            (RESULTS / "j5_split_manifest.json").read_bytes()
        ).hexdigest(),
    "preprocessing":
        "StandardScaler fitted exclusively on TRAIN",
    "smote": False,
    "synthetic_samples": False,
    "evaluation_note":
        "Controlled evaluation cohort; natural BoT-IoT prevalence "
        "is reported separately."
}

meta_path = RESULTS / "j5_dataset_metadata.json"
meta_path.write_text(json.dumps(meta, indent=2))

print("\nMETADATA SHA256:",
      hashlib.sha256(meta_path.read_bytes()).hexdigest())

print("\nJ5_DATASET_BUILD_OK")
