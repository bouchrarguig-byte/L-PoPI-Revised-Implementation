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
OUT = BASE / "results/gatv2"
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
    df = pd.read_parquet(
        PREP / f"j5_{split}.parquet"
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
test_df, test_graph = build_graph("test")


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
test_graph = test_graph.to(device)

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
# Locked TEST
# ---------------------------------------------------------

test_prob = probs(test_graph)
test_y = test_graph.y.cpu().numpy()

test_pred = (
    test_prob >= best_threshold
).astype(int)

cm = confusion_matrix(
    test_y,
    test_pred,
    labels=[0, 1]
)

tn, fp, fn, tp = cm.ravel()

p, r, f, _ = precision_recall_fscore_support(
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
        balanced_accuracy_score(
            test_y,
            test_pred
        ),

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

    "fpr": fp / (fp + tn),
    "fnr": fn / (fn + tp),

    "test_nodes":
        int(test_graph.num_nodes),

    "test_directed_edges":
        int(test_graph.num_edges)
}

print("\n=== LOCKED TEST METRICS ===")

for k, v in metrics.items():
    print(k, "=", v)

with open(
    OUT / "gatv2_test_metrics.json",
    "w"
) as f:
    json.dump(metrics, f, indent=2)



# ---------------------------------------------------------
# Save VAL/TEST probabilities for Cog-GAT ablation
# ---------------------------------------------------------

for split_name, frame, prob, pred in [
    (
        "val",
        val_df,
        val_prob,
        (val_prob >= best_threshold).astype(int)
    ),
    (
        "test",
        test_df,
        test_prob,
        test_pred
    ),
]:
    out_df = frame[
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

    out_df["gat_probability"] = prob
    out_df["gat_prediction"] = pred

    out_df.to_parquet(
        OUT / f"gatv2_{split_name}_predictions.parquet",
        index=False
    )


# ---------------------------------------------------------
# Category attack recall
# ---------------------------------------------------------

print("\n=== TEST ATTACK RECALL BY CATEGORY ===")

cats = test_df["category"].to_numpy()
labels = test_df["attack"].to_numpy()

for cat in sorted(
    test_df.loc[
        test_df.attack == 1,
        "category"
    ].unique()
):
    mask = (
        (labels == 1) &
        (cats == cat)
    )

    rec = (
        test_pred[mask] == 1
    ).mean()

    print(
        f"{cat}: "
        f"N={mask.sum()} "
        f"attack_recall={rec:.6f}"
    )


# ---------------------------------------------------------
# Inference latency: complete TEST graph
# ---------------------------------------------------------

model.eval()

with torch.no_grad():
    for _ in range(10):
        _ = model(test_graph)

if device.type == "cuda":
    torch.cuda.synchronize()

times = []

with torch.no_grad():
    for _ in range(50):
        if device.type == "cuda":
            torch.cuda.synchronize()

        t0 = time.perf_counter()

        _ = model(test_graph)

        if device.type == "cuda":
            torch.cuda.synchronize()

        times.append(
            time.perf_counter() - t0
        )

latency = {
    "nodes":
        int(test_graph.num_nodes),

    "directed_edges":
        int(test_graph.num_edges),

    "mean_graph_ms":
        1000 * float(np.mean(times)),

    "median_graph_ms":
        1000 * float(np.median(times)),

    "mean_us_per_node_amortized":
        1e6 * float(np.mean(times)) /
        test_graph.num_nodes
}

print("\n=== INFERENCE LATENCY ===")
print(latency)

with open(
    OUT / "gatv2_latency.json",
    "w"
) as f:
    json.dump(latency, f, indent=2)


model_sha = hashlib.sha256(
    (OUT / "best_gatv2.pt").read_bytes()
).hexdigest()

print("\nMODEL_SHA256:", model_sha)
print("J5_GATV2_BASELINE_OK")
