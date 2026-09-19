from pathlib import Path
import json
import hashlib

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    roc_curve, precision_recall_curve,
    roc_auc_score, average_precision_score
)

BASE = Path.home() / "esp/sram_puf_clean/j5_ai"
RES = BASE / "results"
OUT = RES / "figures"
OUT.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------
# Locked metrics
# ---------------------------------------------------------

mlp = json.loads(
    (RES / "mlp/mlp_test_metrics.json").read_text()
)

gat = json.loads(
    (RES / "gatv2/gatv2_test_metrics.json").read_text()
)

cog = json.loads(
    (RES / "cog_gat/cog_gat_test_metrics.json").read_text()
)

models = ["MLP", "GATv2", "Cog-GAT"]

metric_names = [
    "Balanced accuracy",
    "Macro-F1",
    "MCC",
    "Benign recall",
    "Attack recall",
]

keys = [
    "test_balanced_accuracy",
    "test_macro_f1",
    "test_mcc",
    "benign_recall",
    "attack_recall",
]

values = np.array([
    [mlp[k] for k in keys],
    [gat[k] for k in keys],
    [cog[k] for k in keys],
])

# ---------------------------------------------------------
# Figure 1: metric comparison
# ---------------------------------------------------------

fig, ax = plt.subplots(figsize=(9, 5))

x = np.arange(len(metric_names))
width = 0.25

for i, model in enumerate(models):
    ax.bar(
        x + (i - 1) * width,
        values[i],
        width,
        label=model
    )

ax.set_ylabel("Score")
ax.set_ylim(0, 1.05)
ax.set_xticks(x)
ax.set_xticklabels(
    metric_names,
    rotation=15,
    ha="right"
)
ax.legend()
ax.grid(axis="y", alpha=0.25)

fig.tight_layout()

fig.savefig(
    OUT / "j5_model_metric_comparison.pdf",
    bbox_inches="tight"
)
fig.savefig(
    OUT / "j5_model_metric_comparison.png",
    dpi=300,
    bbox_inches="tight"
)
plt.close(fig)

# ---------------------------------------------------------
# Figure 2: confusion matrices
# normalized by true class, one file per model
# ---------------------------------------------------------

for name, m in [
    ("MLP", mlp),
    ("GATv2", gat),
    ("Cog-GAT", cog),
]:
    cm = np.array([
        [m["tn"], m["fp"]],
        [m["fn"], m["tp"]]
    ], dtype=float)

    cm_norm = cm / cm.sum(
        axis=1,
        keepdims=True
    )

    fig, ax = plt.subplots(figsize=(5.2, 4.5))
    im = ax.imshow(
        cm_norm,
        vmin=0,
        vmax=1
    )

    for i in range(2):
        for j in range(2):
            ax.text(
                j, i,
                f"{int(cm[i,j]):,}\n"
                f"{100*cm_norm[i,j]:.1f}%",
                ha="center",
                va="center"
            )

    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Benign", "Attack"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Benign", "Attack"])

    ax.set_xlabel("Predicted class")
    ax.set_ylabel("True class")
    ax.set_title(name)

    fig.colorbar(
        im,
        ax=ax,
        label="Row-normalized proportion"
    )

    fig.tight_layout()

    stem = name.lower().replace("-", "_")

    fig.savefig(
        OUT / f"j5_cm_{stem}.pdf",
        bbox_inches="tight"
    )
    fig.savefig(
        OUT / f"j5_cm_{stem}.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close(fig)

# ---------------------------------------------------------
# Figure 3: ROC and PR curves
# ---------------------------------------------------------

mlp_pred = pd.read_parquet(
    RES / "mlp/mlp_test_predictions.parquet"
)

gat_pred = pd.read_parquet(
    RES / "gatv2/gatv2_test_predictions.parquet"
)

cog_pred = pd.read_parquet(
    RES / "cog_gat/cog_gat_test_predictions.parquet"
)

series = [
    (
        "MLP",
        mlp_pred["attack"].to_numpy(),
        mlp_pred["attack_probability"].to_numpy()
    ),
    (
        "GATv2",
        gat_pred["attack"].to_numpy(),
        gat_pred["gat_probability"].to_numpy()
    ),
    (
        "Cog-GAT",
        cog_pred["attack"].to_numpy(),
        cog_pred["cog_gat_score"].to_numpy()
    ),
]

fig, ax = plt.subplots(figsize=(6, 5))

for name, y, score in series:
    fpr, tpr, _ = roc_curve(y, score)
    auc = roc_auc_score(y, score)

    ax.plot(
        fpr,
        tpr,
        label=f"{name} (AUC={auc:.3f})"
    )

ax.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
    linewidth=1
)

ax.set_xlabel("False-positive rate")
ax.set_ylabel("True-positive rate")
ax.set_xlim(0, 1)
ax.set_ylim(0, 1.02)
ax.legend()
ax.grid(alpha=0.25)

fig.tight_layout()
fig.savefig(
    OUT / "j5_roc_comparison.pdf",
    bbox_inches="tight"
)
fig.savefig(
    OUT / "j5_roc_comparison.png",
    dpi=300,
    bbox_inches="tight"
)
plt.close(fig)


fig, ax = plt.subplots(figsize=(6, 5))

for name, y, score in series:
    precision, recall, _ = precision_recall_curve(
        y, score
    )
    ap = average_precision_score(y, score)

    ax.plot(
        recall,
        precision,
        label=f"{name} (AP={ap:.3f})"
    )

ax.set_xlabel("Attack recall")
ax.set_ylabel("Attack precision")
ax.set_xlim(0, 1)
ax.set_ylim(0, 1.02)
ax.legend()
ax.grid(alpha=0.25)

fig.tight_layout()
fig.savefig(
    OUT / "j5_pr_comparison.pdf",
    bbox_inches="tight"
)
fig.savefig(
    OUT / "j5_pr_comparison.png",
    dpi=300,
    bbox_inches="tight"
)
plt.close(fig)

# ---------------------------------------------------------
# Hashes
# ---------------------------------------------------------

print("=== J5 FIGURES ===")

for p in sorted(OUT.glob("*")):
    sha = hashlib.sha256(
        p.read_bytes()
    ).hexdigest()

    print(
        p.name,
        p.stat().st_size,
        sha
    )

print("J5_FIGURES_OK")
