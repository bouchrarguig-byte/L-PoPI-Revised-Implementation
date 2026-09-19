from pathlib import Path
import json
import hashlib
import numpy as np
import pandas as pd

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
TRAIN = BASE / "prepared/j5_train.parquet"
OUT = BASE / "results/j5b"
OUT.mkdir(parents=True, exist_ok=True)

FEATURES = ["z_pkts", "z_bytes", "z_seq", "z_dur"]

# Pre-declared: data_2 is excluded completely from calibration.
EXCLUDED_FILE = "data_2.csv"

# Conservative regularization, fixed before challenge evaluation.
EPS = 1e-6

df = pd.read_parquet(TRAIN)

cal = df[df["source_file"] != EXCLUDED_FILE].copy()
benign = cal[cal["attack"] == 0].copy()

print("=== J5-B OOD GUARD CALIBRATION ===")
print("Challenge file excluded:", EXCLUDED_FILE)
print("Challenge rows used in calibration: 0")
print()
print("Calibration N =", len(cal))
print("Calibration files =", cal["source_file"].nunique())
print("Benign reference N =", len(benign))
print("Features =", FEATURES)
print()

Xb = benign[FEATURES].to_numpy(dtype=float)

mu = Xb.mean(axis=0)
cov = np.cov(Xb, rowvar=False)

cov_reg = cov + EPS * np.eye(len(FEATURES))
inv_cov = np.linalg.inv(cov_reg)

def mahal(X):
    delta = X - mu
    d2 = np.einsum(
        "ij,jk,ik->i",
        delta,
        inv_cov,
        delta
    )
    return np.sqrt(np.maximum(d2, 0.0))

d_b = mahal(Xb)

print("=== BENIGN REFERENCE DISTANCE ===")
for q in [
    .50, .75, .90, .95,
    .975, .99, .995, .999
]:
    print(
        f"q={q:>5}: "
        f"{np.quantile(d_b, q):.9f}"
    )

# ---------------------------------------------------------
# Pre-declared candidate thresholds:
# benign-reference quantiles only.
#
# We are NOT selecting using attack labels and NOT using
# data_2 challenge observations.
# ---------------------------------------------------------

quantiles = [.90, .95, .975, .99, .995, .999]

thresholds = {
    str(q): float(np.quantile(d_b, q))
    for q in quantiles
}

print()
print("=== PRE-DECLARED OOD THRESHOLDS ===")
for q, tau in thresholds.items():
    print(f"benign quantile {q}: tau_D={tau:.9f}")

# Diagnostic on calibration set, not challenge.
Xcal = cal[FEATURES].to_numpy(dtype=float)
d_cal = mahal(Xcal)

cal["ood_distance"] = d_cal

print()
print("=== CALIBRATION-SET ROUTING BY DISTANCE ONLY ===")

for q in quantiles:
    tau = thresholds[str(q)]
    known = d_cal <= tau

    b = cal["attack"].to_numpy() == 0
    a = ~b

    print(
        f"q={q:>5} | "
        f"benign_in={100*known[b].mean():6.2f}% | "
        f"attack_in={100*known[a].mean():6.2f}%"
    )

artifact = {
    "method": "benign_reference_mahalanobis",
    "features": FEATURES,
    "excluded_challenge_file": EXCLUDED_FILE,
    "regularization_epsilon": EPS,
    "n_calibration": int(len(cal)),
    "n_benign_reference": int(len(benign)),
    "mean": mu.tolist(),
    "covariance_regularized": cov_reg.tolist(),
    "thresholds_from_benign_quantiles": thresholds,
}

json_path = OUT / "j5b_ood_calibration.json"

with open(json_path, "w") as f:
    json.dump(artifact, f, indent=2)

sha = hashlib.sha256(
    json_path.read_bytes()
).hexdigest()

print()
print("Saved:", json_path)
print("SHA256:", sha)
print()
print("J5B_OOD_CALIBRATION_OK")
