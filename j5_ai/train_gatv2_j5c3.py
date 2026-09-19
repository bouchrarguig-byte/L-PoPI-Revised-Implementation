from pathlib import Path
import json
import random
import time
import hashlib

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F

from torch_geometric.data import Data
from torch_geometric.nn import GATv2Conv

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

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
PREP = BASE / "prepared"
OUT = BASE / "results/j5c3/gatv2"
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


# ---------------------------------------------------------
# Graph construction
# ---------------------------------------------------------

def build_graph(split):
    # J5-C3 sealed protocol:
    # training code can access TRAIN-C and VAL-C only.
    # TEST-C is intentionally absent from this mapping.
    paths = {
        "train": BASE / "results/j5c3/j5c3_train.parquet",
        "val": BASE / "results/j5c3/j5c3_val.parquet",
    }

    if split not in paths:
        raise ValueError(
            f"J5-C3 permits only train/val here, got: {split}"
        )

    df = pd.read_parquet(
        paths[split]
    ).copy()

    # Restore deterministic temporal ordering inside each source file.
    df = df.sort_values(
        ["source_file", "stime", "source_row"]
    ).reset_index(drop=True)

    src = []
    dst = []

    # Never connect across original CSV files.
    for _, g in df.groupby(
        "source_file",
        sort=False
    ):
        previous_src = {}
        previous_dst = {}

        for idx in g.index:
            s = str(df.at[idx, "saddr"])
            d = str(df.at[idx, "daddr"])

            # Connect to previous flow from same source IP.
            if s in previous_src:
                j = previous_src[s]
                src.extend([j, idx])
                dst.extend([idx, j])

            # Connect to previous flow toward same destination IP.
            if d in previous_dst:
                j = previous_dst[d]

                if j != idx:
                    src.extend([j, idx])
                    dst.extend([idx, j])

            previous_src[s] = idx
            previous_dst[d] = idx

    # Self-loops are added internally by GATv2Conv.
    edge_index = torch.tensor(
        [src, dst],
        dtype=torch.long
    )

    x = torch.tensor(
        df[FEATURES].to_numpy(dtype=np.float32),
        dtype=torch.float32
    )

    y = torch.tensor(
        df["attack"].to_numpy(dtype=np.int64),
        dtype=torch.long
    )

    graph = Data(
        x=x,
        edge_index=edge_index,
        y=y
    )

    print(
        f"{split}: nodes={graph.num_nodes:,} "
        f"directed_edges={graph.num_edges:,} "
        f"files={df.source_file.nunique()}"
    )

    return df, graph


train_df, train_graph = build_graph("train")
val_df, val_graph = build_graph("val")

# J5-C3 TEST-C is deliberately sealed at this stage.
# No TEST-C graph or predictions are constructed here.
test_df = None
test_graph = None


# ---------------------------------------------------------
# Model
# ---------------------------------------------------------

class GATv2Baseline(torch.nn.Module):
    def __init__(self):
        super().__init__()

        self.conv1 = GATv2Conv(
            4,
            16,
            heads=4,
            concat=True,
            dropout=0.2
        )

        self.conv2 = GATv2Conv(
            16 * 4,
            16,
            heads=2,
            concat=True,
            dropout=0.2
        )

        self.out = GATv2Conv(
            16 * 2,
            2,
            heads=1,
            concat=False,
            dropout=0.0
        )

    def forward(self, data):
        x = data.x
        e = data.edge_index

        x = self.conv1(x, e)
        x = F.elu(x)
        x = F.dropout(
            x,
            p=0.2,
            training=self.training
        )

        x = self.conv2(x, e)
        x = F.elu(x)
        x = F.dropout(
            x,
            p=0.2,
            training=self.training
        )

        return self.out(x, e)


model = GATv2Baseline().to(device)

train_graph = train_graph.to(device)
val_graph = val_graph.to(device)

n0 = int((train_graph.y == 0).sum())
n1 = int((train_graph.y == 1).sum())

# CrossEntropy weights: equalize aggregate class contribution.
class_weights = torch.tensor(
    [
        1.0,
        n0 / n1
    ],
    dtype=torch.float32,
    device=device
)

print("CLASS_WEIGHTS:", class_weights.tolist())

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=1e-3,
    weight_decay=1e-5
)


def probs(graph):
    model.eval()

    with torch.no_grad():
        logits = model(graph)
        p = torch.softmax(
            logits,
            dim=1
        )[:, 1]

    return p.detach().cpu().numpy()


best_auc = -1
best_epoch = -1
wait = 0

for epoch in range(1, EPOCHS + 1):
    model.train()
    optimizer.zero_grad()

    logits = model(train_graph)

    loss = F.cross_entropy(
        logits,
        train_graph.y,
        weight=class_weights
    )

    loss.backward()
    optimizer.step()

    val_prob = probs(val_graph)

    val_y = (
        val_graph.y.detach()
        .cpu()
        .numpy()
    )

    auc = roc_auc_score(
        val_y,
        val_prob
    )

    print(
        f"epoch={epoch:03d} "
        f"loss={loss.item():.6f} "
        f"val_auc={auc:.6f}"
    )

    if auc > best_auc + 1e-6:
        best_auc = auc
        best_epoch = epoch
        wait = 0

        torch.save(
            model.state_dict(),
            OUT / "best_gatv2.pt"
        )

    else:
        wait += 1

        if wait >= PATIENCE:
            print("EARLY_STOP")
            break


model.load_state_dict(
    torch.load(
        OUT / "best_gatv2.pt",
        map_location=device,
        weights_only=True
    )
)


# ---------------------------------------------------------
# Validation-only threshold
# ---------------------------------------------------------

val_prob = probs(val_graph)
val_y = val_graph.y.cpu().numpy()

best_threshold = None
best_macro_f1 = -1

for t in np.linspace(
    0.01,
    0.99,
    981
):
    pred = (
        val_prob >= t
    ).astype(int)

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
print("VAL_ROC_AUC:", best_auc)
print("VAL_THRESHOLD:", best_threshold)
print("VAL_MACRO_F1:", best_macro_f1)



# ---------------------------------------------------------
# J5-B FREEZE -- validation only
# ---------------------------------------------------------

val_prob = probs(val_graph)
val_y = val_graph.y.cpu().numpy()

val_pred = (
    val_prob >= best_threshold
).astype(int)

val_auc_final = roc_auc_score(
    val_y,
    val_prob
)

val_macro_final = f1_score(
    val_y,
    val_pred,
    average="macro",
    zero_division=0
)

print()
print("=== J5-C3 PRE-TEST FREEZE ===")
print("TEST-C used in training = NO")
print("TEST-C predictions computed = NO")
print("train files =", train_df.source_file.nunique())
print("train nodes =", len(train_df))
print("val files =", val_df.source_file.nunique())
print("val nodes =", len(val_df))
print("best_epoch =", best_epoch)
print("val_roc_auc =", val_auc_final)
print("val_threshold =", best_threshold)
print("val_macro_f1 =", val_macro_final)

out_df = val_df[
    [
        "source_file",
        "source_row",
        "stime",
        "saddr",
        "daddr",
        "attack",
        "category",
    ]
].copy()

out_df["gat_probability"] = val_prob
out_df["gat_prediction"] = val_pred

val_path = OUT / "gatv2_j5c3_val_predictions.parquet"

out_df.to_parquet(
    val_path,
    index=False
)

freeze = {
    "experiment": "J5-B attack-family-shift",
    "seed": SEED,
    "test_c_used_for_training": False,
    "challenge_opened": False,
    "test_c_predictions_computed": False,
    "train_files": int(train_df.source_file.nunique()),
    "train_nodes": int(len(train_df)),
    "val_files": int(val_df.source_file.nunique()),
    "val_nodes": int(len(val_df)),
    "best_epoch": int(best_epoch),
    "val_roc_auc": float(val_auc_final),
    "val_threshold_macro_f1": float(best_threshold),
    "val_macro_f1": float(val_macro_final),
    "architecture": {
        "input_features": 4,
        "conv1_out": 16,
        "conv1_heads": 4,
        "conv2_out": 16,
        "conv2_heads": 2,
        "output_classes": 2,
        "dropout": 0.2,
    },
    "optimizer": {
        "name": "Adam",
        "lr": 1e-3,
        "weight_decay": 1e-5,
    },
}

freeze_path = OUT / "j5c3_pretest_freeze.json"

with open(freeze_path, "w") as f:
    json.dump(freeze, f, indent=2)

model_sha = hashlib.sha256(
    (OUT / "best_gatv2.pt").read_bytes()
).hexdigest()

freeze_sha = hashlib.sha256(
    freeze_path.read_bytes()
).hexdigest()

val_sha = hashlib.sha256(
    val_path.read_bytes()
).hexdigest()

print()
print("MODEL_SHA256 =", model_sha)
print("FREEZE_SHA256 =", freeze_sha)
print("VAL_PREDICTIONS_SHA256 =", val_sha)
print()
print("J5C3_PRETEST_FREEZE_OK")
