from pathlib import Path
import json
import hashlib

import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data
from torch_geometric.nn import GATv2Conv

# ---------------------------------------------------------
# Paths / frozen hashes
# ---------------------------------------------------------

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
ROOT = BASE / "results/j5c3"
GAT_OUT = ROOT / "gatv2"
CHALLENGE_OUT = ROOT / "sealed_test"
CHALLENGE_OUT.mkdir(parents=True, exist_ok=True)

MODEL_PATH = GAT_OUT / "best_gatv2.pt"
POLICY_PATH = ROOT / "j5c3_frozen_dpi_policies.json"
TEST_PATH = ROOT / "j5c3_test_SEALED.parquet"

EXPECTED_MODEL_SHA = (
    "00787a6ad095713d6ea3710a1166cdae"
    "3bbbdaa21f2208e7a8840b6b092ba6bc"
)

EXPECTED_POLICY_SHA = (
    "8ec219d8fe6031e94f4458cef92aa2c0"
    "3842747a91d5b75a4505f1176f497899"
)

EXPECTED_TEST_SHA = (
    "fd098dd3c5bdaffc0432101f32f657f5"
    "05dd4053072054979cdec8c334f2343c"
)

FEATURES = ["z_pkts", "z_bytes", "z_seq", "z_dur"]

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

# ---------------------------------------------------------
# 1. Verify frozen artifacts BEFORE opening TEST-C
# ---------------------------------------------------------

model_sha = sha256(MODEL_PATH)
policy_sha = sha256(POLICY_PATH)
test_sha = sha256(TEST_PATH)

print("=== J5-C3 SEALED TEST OPENING ===")
print("DEVICE =", device)
print()
print("MODEL_SHA256 =", model_sha)
print("POLICY_SHA256 =", policy_sha)
print("TEST_C_SHA256 =", test_sha)

assert model_sha == EXPECTED_MODEL_SHA, (
    "STOP: frozen model hash mismatch"
)
assert policy_sha == EXPECTED_POLICY_SHA, (
    "STOP: frozen policy hash mismatch"
)
assert test_sha == EXPECTED_TEST_SHA, (
    "STOP: sealed TEST-C hash mismatch"
)

print("Frozen artifact hashes: PASS")

# ---------------------------------------------------------
# 2. Load frozen policy
# ---------------------------------------------------------

with open(POLICY_PATH, "r") as f:
    policy = json.load(f)

alpha = float(policy["cog"]["alpha"])
lam = float(policy["cog"]["lambda"])

baseline_tau = float(
    policy["baseline"]["tau_fast"]
)

adaptive = policy["adaptive"]

base_tau = float(adaptive["base_tau"])
beta = float(adaptive["beta"])
min_history = int(adaptive["min_history"])
tau_trust = float(adaptive["tau_trust"])
elevated_tau = float(adaptive["elevated_tau"])

print()
print("=== FROZEN POLICY ===")
print("Cog alpha =", alpha)
print("Cog lambda =", lam)
print("Baseline tau =", baseline_tau)
print("Adaptive base tau =", base_tau)
print("Adaptive beta =", beta)
print("Adaptive min_history =", min_history)
print("Adaptive tau_trust =", tau_trust)
print("Adaptive elevated_tau =", elevated_tau)

# ---------------------------------------------------------
# 3. TEST-C is opened here for the first performance run
# ---------------------------------------------------------

df = pd.read_parquet(TEST_PATH).copy()

df = df.sort_values(
    ["source_file", "stime", "source_row"],
    kind="mergesort"
).reset_index(drop=True)

assert df.source_file.nunique() == 12
assert len(df) == 9332

print()
print("TEST-C OPENED")
print("nodes =", len(df))
print("files =", df.source_file.nunique())
print(
    "benign =",
    int((df.attack == 0).sum())
)
print(
    "attack =",
    int((df.attack == 1).sum())
)

# ---------------------------------------------------------
# 4. Build graph with EXACT J5-C3 semantics
# ---------------------------------------------------------

src = []
dst = []

for _, g in df.groupby(
    "source_file",
    sort=False
):
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
    "directed_edges =",
    f"{graph.num_edges:,}"
)

# ---------------------------------------------------------
# 5. Exact frozen architecture
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
        x, edge_index = (
            data.x,
            data.edge_index
        )

        x = self.conv1(
            x,
            edge_index
        )
        x = torch.relu(x)
        x = torch.nn.functional.dropout(
            x,
            p=0.2,
            training=self.training
        )

        x = self.conv2(
            x,
            edge_index
        )
        x = torch.relu(x)
        x = torch.nn.functional.dropout(
            x,
            p=0.2,
            training=self.training
        )

        return self.out(
            x,
            edge_index
        )

model = GATv2Baseline().to(device)

model.load_state_dict(
    torch.load(
        MODEL_PATH,
        map_location=device,
        weights_only=True
    )
)

model.eval()

graph = graph.to(device)

with torch.no_grad():
    logits = model(graph)

    gat_prob = (
        torch.softmax(
            logits,
            dim=1
        )[:, 1]
        .detach()
        .cpu()
        .numpy()
    )

# ---------------------------------------------------------
# 6. Frozen causal Cog score
# ---------------------------------------------------------

cog = np.zeros(
    len(df),
    dtype=float
)

pos = 0

for _, g in df.groupby(
    "source_file",
    sort=False
):
    state = {}

    for _, row in g.iterrows():
        src_id = str(row["saddr"])
        gscore = float(gat_prob[pos])

        hist = state.get(
            src_id,
            gscore
        )

        cog[pos] = (
            (1.0-lam) * gscore
            + lam * hist
        )

        state[src_id] = (
            (1.0-alpha) * hist
            + alpha * gscore
        )

        pos += 1

assert pos == len(df)

# ---------------------------------------------------------
# 7. Frozen baseline routing
# ---------------------------------------------------------

baseline_fast = (
    cog < baseline_tau
)

# ---------------------------------------------------------
# 8. Frozen adaptive routing
# ---------------------------------------------------------

trust_before = np.zeros(
    len(df),
    dtype=float
)

count_before = np.zeros(
    len(df),
    dtype=int
)

pos = 0

for _, g in df.groupby(
    "source_file",
    sort=False
):
    trust = {}
    count = {}

    for _, row in g.iterrows():
        src_id = str(row["saddr"])
        risk = float(cog[pos])

        old_t = trust.get(
            src_id,
            0.0
        )
        old_n = count.get(
            src_id,
            0
        )

        trust_before[pos] = old_t
        count_before[pos] = old_n

        evidence = 1.0-risk

        if old_n == 0:
            new_t = evidence
        else:
            new_t = (
                (1.0-beta)*old_t
                + beta*evidence
            )

        trust[src_id] = new_t
        count[src_id] = old_n + 1

        pos += 1

assert pos == len(df)

privileged = (
    (count_before >= min_history)
    &
    (trust_before >= tau_trust)
)

effective_tau = np.where(
    privileged,
    elevated_tau,
    base_tau
)

adaptive_fast = (
    cog < effective_tau
)

# ---------------------------------------------------------
# 9. Metrics
# ---------------------------------------------------------

labels = df["attack"].astype(int).to_numpy()

benign = labels == 0
attack = labels == 1

def metrics(fast):
    return {
        "benign_fast":
            float(fast[benign].mean()),

        "attack_fast":
            float(fast[attack].mean()),

        "total_fast":
            float(fast.mean()),

        "dpi_rate":
            float(1-fast.mean()),

        "benign_fast_n":
            int(fast[benign].sum()),

        "attack_fast_n":
            int(fast[attack].sum())
    }

baseline_metrics = metrics(
    baseline_fast
)

adaptive_metrics = metrics(
    adaptive_fast
)

print()
print("=== PRIMARY SEALED TEST-C RESULTS ===")

for name, m in [
    ("BASELINE", baseline_metrics),
    ("ADAPTIVE", adaptive_metrics)
]:
    print()
    print(name)
    print(
        "  benign_FAST =",
        f"{100*m['benign_fast']:.6f}%"
    )
    print(
        "  attack_FAST =",
        f"{100*m['attack_fast']:.6f}%"
    )
    print(
        "  total_FAST  =",
        f"{100*m['total_fast']:.6f}%"
    )
    print(
        "  DPI         =",
        f"{100*m['dpi_rate']:.6f}%"
    )
    print(
        "  benign FAST count =",
        m["benign_fast_n"]
    )
    print(
        "  attack FAST count =",
        m["attack_fast_n"]
    )

print()
print(
    "Adaptive benign FAST gain =",
    f"{100*(adaptive_metrics['benign_fast']-baseline_metrics['benign_fast']):.6f}",
    "percentage points"
)

print(
    "Adaptive attack FAST change =",
    f"{100*(adaptive_metrics['attack_fast']-baseline_metrics['attack_fast']):.6f}",
    "percentage points"
)

print()
print(
    "Adaptive privileged fraction =",
    f"{100*privileged.mean():.6f}%"
)

# ---------------------------------------------------------
# 10. Category-level routing
# ---------------------------------------------------------

print()
print("=== CATEGORY ROUTING ===")

category_metrics = {}

for cat in sorted(
    df["category"]
    .astype(str)
    .unique()
):
    mask = (
        df["category"].astype(str)
        .to_numpy() == cat
    )

    bfast = float(
        baseline_fast[mask].mean()
    )

    afast = float(
        adaptive_fast[mask].mean()
    )

    category_metrics[cat] = {
        "n": int(mask.sum()),
        "baseline_fast": bfast,
        "adaptive_fast": afast
    }

    print()
    print(
        cat,
        "N=",
        int(mask.sum())
    )

    print(
        "  BASELINE FAST =",
        f"{100*bfast:.6f}%"
    )

    print(
        "  ADAPTIVE FAST =",
        f"{100*afast:.6f}%"
    )

# ---------------------------------------------------------
# 11. Save immutable result artifacts
# ---------------------------------------------------------

out_df = df[
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

out_df["gat_probability"] = gat_prob
out_df["cog_score"] = cog
out_df["trust_before"] = trust_before
out_df["history_count_before"] = count_before
out_df["adaptive_privileged"] = privileged
out_df["adaptive_effective_tau"] = effective_tau
out_df["baseline_fast"] = baseline_fast
out_df["adaptive_fast"] = adaptive_fast

PRED_PATH = (
    CHALLENGE_OUT /
    "j5c3_sealed_test_predictions.parquet"
)

METRICS_PATH = (
    CHALLENGE_OUT /
    "j5c3_sealed_test_metrics.json"
)

out_df.to_parquet(
    PRED_PATH,
    index=False
)

result = {
    "experiment": "J5-C3",
    "evaluation": (
        "newly pre-specified late-file "
        "DDoS-dominant TEST-C fold"
    ),

    "model_sha256": model_sha,
    "policy_sha256": policy_sha,
    "test_c_sha256": test_sha,

    "test_rows": int(len(df)),
    "test_files": int(
        df.source_file.nunique()
    ),

    "baseline": baseline_metrics,
    "adaptive": adaptive_metrics,

    "adaptive_privileged_fraction":
        float(privileged.mean()),

    "category_metrics":
        category_metrics,

    "no_post_test_retuning": True
}

with open(METRICS_PATH, "w") as f:
    json.dump(
        result,
        f,
        indent=2,
        sort_keys=True
    )

pred_sha = sha256(PRED_PATH)
metrics_sha = sha256(METRICS_PATH)

print()
print(
    "PREDICTIONS_SHA256 =",
    pred_sha
)
print(
    "METRICS_SHA256 =",
    metrics_sha
)

print()
print(
    "J5C3_SEALED_TEST_OPENED_OK"
)
