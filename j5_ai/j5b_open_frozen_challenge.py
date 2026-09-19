from pathlib import Path
import json
import hashlib
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F

from torch_geometric.data import Data
from torch_geometric.nn import GATv2Conv

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
TRAIN = BASE / "prepared/j5_train.parquet"
MODEL = BASE / "results/j5b/gatv2_shift/best_gatv2.pt"
POLICY = BASE / "results/j5b/j5b_frozen_dpi_policy.json"
OUT = BASE / "results/j5b/challenge"
OUT.mkdir(parents=True, exist_ok=True)

EXPECTED_MODEL_SHA = (
    "62abe9e985cadb5c4a5c09c76e3bd473"
    "6b0600e69428e32207856bd7db851211"
)

EXPECTED_POLICY_SHA = (
    "4f9c26e8e9f98e69a50bb2d399a411f"
    "6f3bf5d9eac7927f1de613e2a7e0216b9"
)

FEATURES = ["z_pkts", "z_bytes", "z_seq", "z_dur"]

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

print("=== J5-B FROZEN CHALLENGE ===")

model_sha = sha256(MODEL)
policy_sha = sha256(POLICY)

print("MODEL_SHA256 =", model_sha)
print("POLICY_SHA256 =", policy_sha)

if model_sha != EXPECTED_MODEL_SHA:
    raise RuntimeError("MODEL HASH MISMATCH")

if policy_sha != EXPECTED_POLICY_SHA:
    raise RuntimeError("POLICY HASH MISMATCH")

print("Frozen artifact hashes: PASS")
print()

with open(POLICY) as f:
    policy = json.load(f)

ALPHA = float(
    policy["cognitive_history"]["alpha"]
)
LAMBDA = float(
    policy["cognitive_history"]["lambda"]
)
TAU_FAST = float(
    policy["dpi_policy"]["tau_fast"]
)
U_LIMIT = float(
    policy["uncertainty_guard"]["limit"]
)

print("alpha =", ALPHA)
print("lambda =", LAMBDA)
print("tau_fast =", TAU_FAST)
print("u_limit =", U_LIMIT)
print()

# ------------------------------------------------------
# Open challenge only now.
# ------------------------------------------------------

df = pd.read_parquet(TRAIN)

df = df[
    df["source_file"] == "data_2.csv"
].copy()

df = df.sort_values(
    ["source_file", "stime", "source_row"],
    kind="mergesort"
).reset_index(drop=True)

print("Challenge N =", len(df))
print("Challenge categories:")
print(df["category"].value_counts().to_string())
print()

# ------------------------------------------------------
# Graph construction: identical semantics to J5-A/J5-B.
# ------------------------------------------------------

src = []
dst = []

for _, g in df.groupby("source_file", sort=False):

    previous_src = {}
    previous_dst = {}

    for idx in g.index:

        s = str(df.at[idx, "saddr"])
        d = str(df.at[idx, "daddr"])

        if s in previous_src:
            j = previous_src[s]
            src.extend([j, idx])
            dst.extend([idx, j])

        if d in previous_dst:
            j = previous_dst[d]

            if j != idx:
                src.extend([j, idx])
                dst.extend([idx, j])

        previous_src[s] = idx
        previous_dst[d] = idx

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
    "Challenge graph:",
    f"nodes={graph.num_nodes:,}",
    f"directed_edges={graph.num_edges:,}"
)
print()

# ------------------------------------------------------
# Exact frozen GATv2 architecture.
# ------------------------------------------------------

class GATv2Baseline(torch.nn.Module):

    def __init__(self):
        super().__init__()

        self.conv1 = GATv2Conv(
            4, 16,
            heads=4,
            concat=True,
            dropout=0.2
        )

        self.conv2 = GATv2Conv(
            16 * 4, 16,
            heads=2,
            concat=True,
            dropout=0.2
        )

        self.out = GATv2Conv(
            16 * 2, 2,
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

device = torch.device(
    "cuda" if torch.cuda.is_available()
    else "cpu"
)

model = GATv2Baseline().to(device)

model.load_state_dict(
    torch.load(
        MODEL,
        map_location=device,
        weights_only=True
    )
)

graph = graph.to(device)
model.eval()

with torch.no_grad():

    logits = model(graph)

    gat_prob = torch.softmax(
        logits,
        dim=1
    )[:, 1].cpu().numpy()

df["gat_probability"] = gat_prob

# ------------------------------------------------------
# Frozen causal Cog-GAT.
# Single source_file, state by source address.
# ------------------------------------------------------

state = {}
cog = []

for _, row in df.iterrows():

    src_addr = str(row["saddr"])
    p = float(row["gat_probability"])

    hist = state.get(src_addr, p)

    score = (
        (1.0 - LAMBDA) * p
        + LAMBDA * hist
    )

    cog.append(score)

    state[src_addr] = (
        (1.0 - ALPHA) * hist
        + ALPHA * p
    )

df["cog_score"] = np.asarray(cog)

df["uncertainty"] = (
    1.0 -
    np.abs(2.0 * df["cog_score"] - 1.0)
)

# ------------------------------------------------------
# Frozen policies.
#
# B1: score only.
# B2: score + predeclared uncertainty guard.
# ------------------------------------------------------

df["fast_B1"] = (
    df["cog_score"] < TAU_FAST
)

df["fast_B2"] = (
    (df["cog_score"] < TAU_FAST)
    &
    (df["uncertainty"] <= U_LIMIT)
)

def rate(mask):
    return float(mask.mean())

benign = df["attack"].to_numpy() == 0
attack = ~benign

metrics = {
    "challenge_file": "data_2.csv",
    "n": int(len(df)),
    "n_benign": int(benign.sum()),
    "n_attack": int(attack.sum()),
    "model_sha256": model_sha,
    "policy_sha256": policy_sha,
    "tau_fast": TAU_FAST,
    "u_limit": U_LIMIT,
}

print("=== PRIMARY FROZEN CHALLENGE RESULTS ===")

for name in ["B1", "B2"]:

    f = df[f"fast_{name}"].to_numpy()

    benign_fast = rate(f[benign])
    attack_fast = rate(f[attack])
    total_fast = rate(f)

    metrics[f"{name}_benign_fast"] = benign_fast
    metrics[f"{name}_attack_fast"] = attack_fast
    metrics[f"{name}_total_fast"] = total_fast
    metrics[f"{name}_dpi_rate"] = 1.0 - total_fast

    print()
    print(name)
    print(
        f"  benign_FAST = {100*benign_fast:.6f}%"
    )
    print(
        f"  attack_FAST = {100*attack_fast:.6f}%"
    )
    print(
        f"  total_FAST  = {100*total_fast:.6f}%"
    )
    print(
        f"  DPI         = {100*(1-total_fast):.6f}%"
    )

# ------------------------------------------------------
# Category-specific routing.
# ------------------------------------------------------

print()
print("=== CATEGORY ROUTING ===")

for category, g in df.groupby("category"):

    print()
    print(
        category,
        "N=",
        len(g)
    )

    for name in ["B1", "B2"]:

        r = g[f"fast_{name}"].mean()

        print(
            f"  {name}: "
            f"FAST={100*r:.6f}% "
            f"DPI={100*(1-r):.6f}%"
        )

        metrics[
            f"{name}_category_{category}_fast"
        ] = float(r)

# ------------------------------------------------------
# Recon subcategories.
# ------------------------------------------------------

print()
print("=== RECON SUBCATEGORY ROUTING ===")

recon = df[
    df["category"] == "Reconnaissance"
]

for sub, g in recon.groupby("subcategory "):

    print()
    print(sub, "N=", len(g))

    for name in ["B1", "B2"]:

        r = g[f"fast_{name}"].mean()

        print(
            f"  {name}: "
            f"FAST={100*r:.6f}% "
            f"DPI={100*(1-r):.6f}%"
        )

        metrics[
            f"{name}_recon_{sub}_fast"
        ] = float(r)

# ------------------------------------------------------
# Save immutable challenge artifacts.
# ------------------------------------------------------

pred_path = OUT / "j5b_frozen_challenge_predictions.parquet"
json_path = OUT / "j5b_frozen_challenge_metrics.json"

df.to_parquet(
    pred_path,
    index=False
)

with open(json_path, "w") as f:
    json.dump(
        metrics,
        f,
        indent=2
    )

pred_sha = sha256(pred_path)
metrics_sha = sha256(json_path)

print()
print("PREDICTIONS_SHA256 =", pred_sha)
print("METRICS_SHA256 =", metrics_sha)
print()
print("J5B_FROZEN_CHALLENGE_OPENED_OK")
