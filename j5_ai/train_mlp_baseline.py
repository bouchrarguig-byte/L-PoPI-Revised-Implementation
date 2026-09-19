from pathlib import Path
import json
import random
import time
import hashlib

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
    f1_score,
    matthews_corrcoef,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)

SEED = 20260916
EPOCHS = 100
PATIENCE = 12
BATCH = 1024

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
PREP = BASE / "prepared"
OUT = BASE / "results/mlp"
OUT.mkdir(parents=True, exist_ok=True)

FEATURES = ["z_pkts", "z_bytes", "z_seq", "z_dur"]

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
torch.cuda.manual_seed_all(SEED)

torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark = False

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

print("DEVICE:", device)

def load(split):
    df = pd.read_parquet(PREP / f"j5_{split}.parquet")

    X = torch.tensor(
        df[FEATURES].to_numpy(dtype=np.float32)
    )

    y = torch.tensor(
        df["attack"].to_numpy(dtype=np.float32)
    )

    return df, X, y

train_df, Xtr, ytr = load("train")
val_df, Xva, yva = load("val")
test_df, Xte, yte = load("test")

class MLP(nn.Module):
    def __init__(self):
        super().__init__()

        self.net = nn.Sequential(
            nn.Linear(4, 64),
            nn.ReLU(),
            nn.Dropout(0.2),

            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),

            nn.Linear(32, 1)
        )

    def forward(self, x):
        return self.net(x).squeeze(1)

model = MLP().to(device)

# Cohort is already 10:1 attack:benign.
# Weight positive ATTACK class so total class contribution is balanced.
n0 = int((ytr == 0).sum())
n1 = int((ytr == 1).sum())

pos_weight = torch.tensor(
    [n0 / n1],
    dtype=torch.float32,
    device=device
)

print("TRAIN benign:", n0)
print("TRAIN attack:", n1)
print("pos_weight:", pos_weight.item())

criterion = nn.BCEWithLogitsLoss(
    pos_weight=pos_weight
)

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=1e-3,
    weight_decay=1e-5
)

generator = torch.Generator()
generator.manual_seed(SEED)

dataset = torch.utils.data.TensorDataset(
    Xtr, ytr
)

loader = torch.utils.data.DataLoader(
    dataset,
    batch_size=BATCH,
    shuffle=True,
    generator=generator,
    num_workers=0
)

def probabilities(X):
    model.eval()

    out = []

    with torch.no_grad():
        for i in range(0, len(X), 4096):
            xb = X[i:i+4096].to(device)
            out.append(
                torch.sigmoid(model(xb)).cpu().numpy()
            )

    return np.concatenate(out)

best_val_auc = -1
best_epoch = -1
wait = 0

for epoch in range(1, EPOCHS + 1):
    model.train()

    total_loss = 0.0

    for xb, yb in loader:
        xb = xb.to(device)
        yb = yb.to(device)

        optimizer.zero_grad()

        logits = model(xb)
        loss = criterion(logits, yb)

        loss.backward()
        optimizer.step()

        total_loss += loss.item() * len(xb)

    val_prob = probabilities(Xva)

    val_auc = roc_auc_score(
        yva.numpy(), val_prob
    )

    mean_loss = total_loss / len(dataset)

    print(
        f"epoch={epoch:03d} "
        f"loss={mean_loss:.6f} "
        f"val_auc={val_auc:.6f}"
    )

    if val_auc > best_val_auc + 1e-6:
        best_val_auc = val_auc
        best_epoch = epoch
        wait = 0

        torch.save(
            model.state_dict(),
            OUT / "best_mlp.pt"
        )

    else:
        wait += 1

        if wait >= PATIENCE:
            print("EARLY_STOP")
            break

model.load_state_dict(
    torch.load(
        OUT / "best_mlp.pt",
        map_location=device,
        weights_only=True
    )
)

# -------------------------------------------------
# Validation-only threshold selection
# -------------------------------------------------

val_prob = probabilities(Xva)
val_y = yva.numpy().astype(int)

thresholds = np.linspace(
    0.01, 0.99, 981
)

best_threshold = None
best_macro_f1 = -1

for t in thresholds:
    pred = (val_prob >= t).astype(int)

    score = f1_score(
        val_y,
        pred,
        average="macro",
        zero_division=0
    )

    if score > best_macro_f1:
        best_macro_f1 = score
        best_threshold = float(t)

print("\nBEST_EPOCH:", best_epoch)
print("VAL_ROC_AUC:", best_val_auc)
print("VAL_THRESHOLD:", best_threshold)
print("VAL_MACRO_F1:", best_macro_f1)

# -------------------------------------------------
# Locked TEST evaluation
# -------------------------------------------------

test_prob = probabilities(Xte)
test_y = yte.numpy().astype(int)

test_pred = (
    test_prob >= best_threshold
).astype(int)

cm = confusion_matrix(
    test_y,
    test_pred,
    labels=[0, 1]
)

tn, fp, fn, tp = cm.ravel()

p, r, f, support = precision_recall_fscore_support(
    test_y,
    test_pred,
    labels=[0, 1],
    zero_division=0
)

metrics = {
    "seed": SEED,
    "best_epoch": best_epoch,
    "threshold_selected_on_validation":
        best_threshold,

    "test_accuracy":
        accuracy_score(test_y, test_pred),

    "test_balanced_accuracy":
        balanced_accuracy_score(test_y, test_pred),

    "test_macro_f1":
        f1_score(
            test_y,
            test_pred,
            average="macro"
        ),

    "test_mcc":
        matthews_corrcoef(
            test_y,
            test_pred
        ),

    "test_roc_auc":
        roc_auc_score(
            test_y,
            test_prob
        ),

    "test_pr_auc_attack":
        average_precision_score(
            test_y,
            test_prob
        ),

    "benign_precision": p[0],
    "benign_recall": r[0],
    "benign_f1": f[0],

    "attack_precision": p[1],
    "attack_recall": r[1],
    "attack_f1": f[1],

    "tn": int(tn),
    "fp": int(fp),
    "fn": int(fn),
    "tp": int(tp),

    # Here FPR = benign incorrectly classified as attack.
    "fpr": fp / (fp + tn),

    # FNR = attack incorrectly classified as benign.
    "fnr": fn / (fn + tp)
}

print("\n=== LOCKED TEST METRICS ===")

for k, v in metrics.items():
    print(k, "=", v)

with open(
    OUT / "mlp_test_metrics.json",
    "w"
) as f:
    json.dump(
        metrics,
        f,
        indent=2
    )

pred_df = test_df[
    [
        "source_file",
        "source_row",
        "attack",
        "category"
    ]
].copy()

pred_df["attack_probability"] = test_prob
pred_df["prediction"] = test_pred

pred_df.to_parquet(
    OUT / "mlp_test_predictions.parquet",
    index=False
)

# Category-specific binary detection
print("\n=== TEST ATTACK RECALL BY CATEGORY ===")

for cat in sorted(
    test_df.loc[
        test_df.attack == 1,
        "category"
    ].unique()
):
    mask = (
        (test_df.attack.to_numpy() == 1) &
        (test_df.category.to_numpy() == cat)
    )

    recall = (
        test_pred[mask] == 1
    ).mean()

    print(
        f"{cat}: "
        f"N={mask.sum()} "
        f"attack_recall={recall:.6f}"
    )

# -------------------------------------------------
# Inference latency
# -------------------------------------------------

Xbench = Xte[:4096].to(device)

model.eval()

with torch.no_grad():
    for _ in range(20):
        _ = model(Xbench)

if device.type == "cuda":
    torch.cuda.synchronize()

times = []

with torch.no_grad():
    for _ in range(100):
        if device.type == "cuda":
            torch.cuda.synchronize()

        t0 = time.perf_counter()
        _ = model(Xbench)

        if device.type == "cuda":
            torch.cuda.synchronize()

        times.append(
            time.perf_counter() - t0
        )

latency = {
    "batch_size": len(Xbench),
    "mean_batch_ms":
        1000 * float(np.mean(times)),
    "median_batch_ms":
        1000 * float(np.median(times)),
    "mean_us_per_flow":
        1e6 * float(np.mean(times)) /
        len(Xbench)
}

print("\n=== INFERENCE LATENCY ===")
print(latency)

with open(
    OUT / "mlp_latency.json",
    "w"
) as f:
    json.dump(latency, f, indent=2)

model_sha = hashlib.sha256(
    (OUT / "best_mlp.pt").read_bytes()
).hexdigest()

print("\nMODEL_SHA256:", model_sha)
print("J5_MLP_BASELINE_OK")
