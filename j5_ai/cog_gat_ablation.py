from pathlib import Path
import json
import hashlib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
    matthews_corrcoef,
    roc_auc_score,
    average_precision_score,
    precision_recall_fscore_support,
    confusion_matrix,
)

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
ROOT = BASE / "results/gatv2"
OUT = BASE / "results/cog_gat"
OUT.mkdir(parents=True, exist_ok=True)

VAL_PATH = ROOT / "gatv2_val_predictions.parquet"
TEST_PATH = ROOT / "gatv2_test_predictions.parquet"

# ---------------------------------------------------------
# Causal endpoint history
# ---------------------------------------------------------

def causal_history(df, alpha):
    """
    For each flow i:
      h_src(i) = EWMA of PREVIOUS GAT scores for saddr
      h_dst(i) = EWMA of PREVIOUS GAT scores for daddr

    The current flow updates state only AFTER its historical
    features have been emitted.

    State is reset at every original CSV file boundary.
    """

    work = df.sort_values(
        ["source_file", "stime", "source_row"]
    ).copy()

    hsrc = np.zeros(len(work), dtype=np.float64)
    hdst = np.zeros(len(work), dtype=np.float64)

    seen_src = np.zeros(len(work), dtype=np.int8)
    seen_dst = np.zeros(len(work), dtype=np.int8)

    # Position in the sorted dataframe
    position = {
        idx: pos
        for pos, idx in enumerate(work.index)
    }

    for _, g in work.groupby("source_file", sort=False):
        src_state = {}
        dst_state = {}

        for idx, row in g.iterrows():
            pos = position[idx]

            s = str(row["saddr"])
            d = str(row["daddr"])
            p = float(row["gat_probability"])

            if s in src_state:
                hsrc[pos] = src_state[s]
                seen_src[pos] = 1
            else:
                # Neutral prior for unseen endpoint.
                hsrc[pos] = 0.5

            if d in dst_state:
                hdst[pos] = dst_state[d]
                seen_dst[pos] = 1
            else:
                hdst[pos] = 0.5

            # Update only AFTER historical values are emitted.
            if s in src_state:
                src_state[s] = (
                    alpha * p +
                    (1.0 - alpha) * src_state[s]
                )
            else:
                src_state[s] = p

            if d in dst_state:
                dst_state[d] = (
                    alpha * p +
                    (1.0 - alpha) * dst_state[d]
                )
            else:
                dst_state[d] = p

    work["h_src"] = hsrc
    work["h_dst"] = hdst
    work["seen_src"] = seen_src
    work["seen_dst"] = seen_dst

    return work


def fuse(work, mode, lam):
    p = work["gat_probability"].to_numpy(
        dtype=np.float64
    )

    hs = work["h_src"].to_numpy(dtype=np.float64)
    hd = work["h_dst"].to_numpy(dtype=np.float64)

    ss = work["seen_src"].to_numpy(dtype=np.float64)
    sd = work["seen_dst"].to_numpy(dtype=np.float64)

    if mode == "gat":
        return p

    if mode == "src":
        # If source unseen, history contributes zero weight.
        hist = np.where(ss > 0, hs, p)
        return (1.0 - lam) * p + lam * hist

    if mode == "srcdst":
        # Average only available endpoint histories.
        denom = ss + sd

        hist = np.where(
            denom > 0,
            (ss * hs + sd * hd) /
            np.maximum(denom, 1.0),
            p
        )

        return (1.0 - lam) * p + lam * hist

    raise ValueError(mode)


def threshold_search(y, score):
    best_t = None
    best_f1 = -1.0

    for t in np.linspace(0.01, 0.99, 981):
        pred = (score >= t).astype(int)

        m = f1_score(
            y,
            pred,
            average="macro",
            zero_division=0
        )

        if m > best_f1:
            best_f1 = float(m)
            best_t = float(t)

    return best_t, best_f1


# ---------------------------------------------------------
# VALIDATION ONLY model selection
# ---------------------------------------------------------

val_raw = pd.read_parquet(VAL_PATH)

alphas = [0.05, 0.10, 0.20, 0.40, 0.60, 0.80]
lambdas = [
    0.00, 0.10, 0.20, 0.30, 0.40,
    0.50, 0.60, 0.70, 0.80
]

candidates = []

# GAT-only reference
y_val_ref = val_raw["attack"].to_numpy(dtype=int)
p_val_ref = val_raw["gat_probability"].to_numpy()

t, mf1 = threshold_search(y_val_ref, p_val_ref)

candidates.append({
    "mode": "gat",
    "alpha": None,
    "lambda": 0.0,
    "threshold": t,
    "val_macro_f1": mf1,
    "val_roc_auc": roc_auc_score(
        y_val_ref, p_val_ref
    )
})

# Cognitive variants
for alpha in alphas:
    val = causal_history(val_raw, alpha)

    y = val["attack"].to_numpy(dtype=int)

    for mode in ["src", "srcdst"]:
        for lam in lambdas[1:]:
            score = fuse(val, mode, lam)

            t, mf1 = threshold_search(y, score)

            candidates.append({
                "mode": mode,
                "alpha": alpha,
                "lambda": lam,
                "threshold": t,
                "val_macro_f1": mf1,
                "val_roc_auc":
                    roc_auc_score(y, score)
            })

results = pd.DataFrame(candidates)

# Selection criterion fixed a priori:
# maximize validation macro-F1.
# Tie-break: validation ROC-AUC.
results = results.sort_values(
    ["val_macro_f1", "val_roc_auc"],
    ascending=[False, False]
).reset_index(drop=True)

results.to_csv(
    OUT / "validation_ablation_grid.csv",
    index=False
)

print("=== TOP VALIDATION CONFIGURATIONS ===")
print(results.head(15).to_string(index=False))

best = results.iloc[0].to_dict()

print("\n=== SELECTED ON VALIDATION ONLY ===")
print(best)


# ---------------------------------------------------------
# TEST loaded only AFTER configuration selection
# ---------------------------------------------------------

test_raw = pd.read_parquet(TEST_PATH)

mode = best["mode"]
lam = float(best["lambda"])
threshold = float(best["threshold"])

if mode == "gat":
    test = test_raw.copy()
    test_score = test["gat_probability"].to_numpy()

else:
    alpha = float(best["alpha"])
    test = causal_history(test_raw, alpha)
    test_score = fuse(test, mode, lam)

y = test["attack"].to_numpy(dtype=int)
pred = (test_score >= threshold).astype(int)

tn, fp, fn, tp = confusion_matrix(
    y, pred, labels=[0, 1]
).ravel()

p, r, f, _ = precision_recall_fscore_support(
    y,
    pred,
    labels=[0, 1],
    zero_division=0
)

metrics = {
    "selection_rule":
        "maximum validation macro-F1; ROC-AUC tie-break",

    "mode": mode,
    "alpha":
        None if mode == "gat"
        else float(best["alpha"]),
    "lambda": lam,
    "threshold_validation_only": threshold,

    "val_macro_f1":
        float(best["val_macro_f1"]),
    "val_roc_auc":
        float(best["val_roc_auc"]),

    "test_accuracy":
        float(accuracy_score(y, pred)),
    "test_balanced_accuracy":
        float(balanced_accuracy_score(y, pred)),
    "test_macro_f1":
        float(f1_score(
            y, pred,
            average="macro",
            zero_division=0
        )),
    "test_mcc":
        float(matthews_corrcoef(y, pred)),
    "test_roc_auc":
        float(roc_auc_score(y, test_score)),
    "test_pr_auc_attack":
        float(average_precision_score(
            y, test_score
        )),

    "benign_precision": float(p[0]),
    "benign_recall": float(r[0]),
    "benign_f1": float(f[0]),

    "attack_precision": float(p[1]),
    "attack_recall": float(r[1]),
    "attack_f1": float(f[1]),

    "tn": int(tn),
    "fp": int(fp),
    "fn": int(fn),
    "tp": int(tp),

    "fpr": float(fp / (fp + tn)),
    "fnr": float(fn / (fn + tp)),
}

print("\n=== LOCKED COG-GAT TEST ===")
for k, v in metrics.items():
    print(k, "=", v)


# ---------------------------------------------------------
# Category recall
# ---------------------------------------------------------

print("\n=== TEST ATTACK RECALL BY CATEGORY ===")

cats = test["category"].to_numpy()

category_results = {}

for cat in sorted(
    test.loc[
        test.attack == 1,
        "category"
    ].unique()
):
    mask = (y == 1) & (cats == cat)

    rec = float(
        (pred[mask] == 1).mean()
    )

    category_results[cat] = {
        "n": int(mask.sum()),
        "attack_recall": rec
    }

    print(
        f"{cat}: "
        f"N={mask.sum()} "
        f"attack_recall={rec:.6f}"
    )

metrics["category_attack_recall"] = category_results


# ---------------------------------------------------------
# Save predictions + provenance
# ---------------------------------------------------------

out_pred = test[
    [
        "source_file",
        "source_row",
        "stime",
        "saddr",
        "daddr",
        "attack",
        "category"
    ]
].copy()

out_pred["cog_gat_score"] = test_score
out_pred["prediction"] = pred

out_pred.to_parquet(
    OUT / "cog_gat_test_predictions.parquet",
    index=False
)

with open(
    OUT / "cog_gat_test_metrics.json",
    "w"
) as f:
    json.dump(metrics, f, indent=2)

for pth in [
    OUT / "validation_ablation_grid.csv",
    OUT / "cog_gat_test_metrics.json",
    OUT / "cog_gat_test_predictions.parquet",
]:
    print(
        "SHA256",
        pth.name,
        hashlib.sha256(
            pth.read_bytes()
        ).hexdigest()
    )

print("\nJ5_COG_GAT_ABLATION_OK")
