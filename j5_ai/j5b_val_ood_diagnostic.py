from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
VAL = BASE / "results/gatv2/gatv2_val_predictions.parquet"

ALPHA = 0.10
LAMBDA = 0.50

# Frozen J5-A DPI threshold.
# We do NOT optimize this threshold here.
TAU_FAST = 0.416452

print("=== J5-B VALIDATION-ONLY OOD DIAGNOSTIC ===")
print("TEST data are NOT used.")
print("GAT VAL =", VAL)
print(f"Frozen Cog-GAT: mode=src alpha={ALPHA} lambda={LAMBDA}")
print(f"Frozen J5-A tau_fast={TAU_FAST}")
print()

df = pd.read_parquet(VAL).copy()

required = [
    "source_file",
    "source_row",
    "stime",
    "saddr",
    "attack",
    "category",
    "gat_probability",
]

missing = [c for c in required if c not in df.columns]
if missing:
    raise RuntimeError(f"Missing columns: {missing}")

# Preserve original row identity so reconstructed scores can be
# returned to exactly the original prediction order.
df["_original_index"] = np.arange(len(df))

# ------------------------------------------------------------
# Reconstruct the frozen causal source-history Cog-GAT score.
#
# State is reset for every source CSV.
#
# IMPORTANT:
# history for flow t uses ONLY scores observed before t.
# No labels are used in the state.
# ------------------------------------------------------------

ordered = df.sort_values(
    ["source_file", "stime", "source_row"],
    kind="mergesort"
).copy()

cog_score = np.empty(len(ordered), dtype=float)
history_used = np.empty(len(ordered), dtype=float)

out_pos = 0

for source_file, group in ordered.groupby(
    "source_file", sort=False
):
    state = {}

    for _, row in group.iterrows():
        src = str(row["saddr"])
        gat = float(row["gat_probability"])

        # For a previously unseen source, use current GAT score
        # as neutral initialization. This prevents artificial
        # zero-history bias on the first retained flow.
        hist = state.get(src, gat)

        score = (
            (1.0 - LAMBDA) * gat
            + LAMBDA * hist
        )

        history_used[out_pos] = hist
        cog_score[out_pos] = score

        # Causal EWMA update AFTER scoring current flow.
        state[src] = (
            (1.0 - ALPHA) * hist
            + ALPHA * gat
        )

        out_pos += 1

ordered["history_src"] = history_used
ordered["cog_score"] = cog_score

# Restore original GAT prediction order.
ordered = ordered.sort_values("_original_index")

y = ordered["attack"].astype(int).to_numpy()
gat = ordered["gat_probability"].astype(float).to_numpy()
s = ordered["cog_score"].astype(float).to_numpy()

benign = y == 0
attack = y == 1

print("N =", len(ordered))
print("benign =", int(benign.sum()))
print("attack =", int(attack.sum()))
print()

print("=== SCORE AUDIT ===")
print(f"GAT ROC-AUC     = {roc_auc_score(y, gat):.9f}")
print(f"Cog-GAT ROC-AUC = {roc_auc_score(y, s):.9f}")
print()

# Expected from frozen J5:
# approximately 0.737303642 Cog-GAT VAL ROC-AUC.
EXPECTED_COG_AUC = 0.7373036418
auc = roc_auc_score(y, s)

print(
    "Cog-GAT AUC difference from frozen J5 =",
    f"{auc - EXPECTED_COG_AUC:+.12f}"
)

if abs(auc - EXPECTED_COG_AUC) > 1e-6:
    print()
    print("WARNING:")
    print("Reconstructed score does not match frozen J5 AUC.")
    print("STOP before interpreting the guard frontier.")
    print("J5B_RECONSTRUCTION_MISMATCH")
    raise SystemExit(2)

print("J5 frozen score reconstruction: PASS")
print()

# ------------------------------------------------------------
# J5-A routing on VAL, reconstructed independently.
# ------------------------------------------------------------

fast_a = s < TAU_FAST

benign_fast_a = fast_a[benign].mean()
attack_fast_a = fast_a[attack].mean()
total_fast_a = fast_a.mean()

print("=== FROZEN J5-A VAL ROUTING ===")
print(f"benign_FAST = {100*benign_fast_a:.4f}%")
print(f"attack_FAST = {100*attack_fast_a:.4f}%")
print(f"total_FAST  = {100*total_fast_a:.4f}%")
print(f"DPI rate    = {100*(1-total_fast_a):.4f}%")
print()

# ------------------------------------------------------------
# Simple ambiguity guard.
#
# uncertainty=1 near score=0.5
# uncertainty=0 near score=0 or 1
#
# Diagnostic only.
# ------------------------------------------------------------

uncertainty = 1.0 - np.abs(2.0 * s - 1.0)

print("=== COG-GAT UNCERTAINTY QUANTILES ===")

for mask, name in [
    (benign, "BENIGN"),
    (attack, "ATTACK"),
]:
    x = uncertainty[mask]
    print(name)

    for q in [
        0, .01, .05, .10, .25,
        .50, .75, .90, .95, .99, 1
    ]:
        print(
            f"  q={q:>4}: "
            f"{np.quantile(x, q):.6f}"
        )

print()

# ------------------------------------------------------------
# Candidate uncertainty guard:
#
# FAST iff:
#     cog_score < frozen tau_fast
# AND uncertainty <= u_limit
#
# Everything else goes to DPI.
#
# No TEST data.
# ------------------------------------------------------------

print("=== VALIDATION UNCERTAINTY-GUARD FRONTIER ===")

for u_limit in np.arange(0.10, 1.01, 0.05):

    fast = (
        (s < TAU_FAST)
        & (uncertainty <= u_limit)
    )

    benign_fast = fast[benign].mean()
    attack_fast = fast[attack].mean()
    total_fast = fast.mean()

    print(
        f"u<={u_limit:4.2f} | "
        f"benign_FAST={100*benign_fast:6.2f}% | "
        f"attack_FAST={100*attack_fast:6.2f}% | "
        f"total_FAST={100*total_fast:6.2f}% | "
        f"DPI={100*(1-total_fast):6.2f}%"
    )

print()

# ------------------------------------------------------------
# Category diagnostic on VAL only.
# This tells us which attack families are represented in VAL.
# ------------------------------------------------------------

print("=== VAL ATTACK CATEGORY ROUTING AT J5-A THRESHOLD ===")

attack_df = ordered[ordered["attack"] == 1].copy()
attack_df["fast"] = (
    attack_df["cog_score"] < TAU_FAST
)

for category, g in attack_df.groupby("category"):
    print(
        f"{str(category):20s} "
        f"N={len(g):5d} | "
        f"FAST={100*g['fast'].mean():7.3f}% | "
        f"DPI={100*(1-g['fast'].mean()):7.3f}%"
    )

print()

# Save reconstruction for audit/reproducibility.
OUT = BASE / "results/j5b"
OUT.mkdir(parents=True, exist_ok=True)

out_file = OUT / "j5b_val_reconstructed_scores.parquet"

ordered.drop(
    columns=["_original_index"]
).to_parquet(
    out_file,
    index=False
)

print("Saved:", out_file)
print()
print("J5B_VAL_OOD_DIAGNOSTIC_OK")
