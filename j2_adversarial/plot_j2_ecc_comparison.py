from pathlib import Path
import csv
import matplotlib.pyplot as plt

ROOT = Path("j2_adversarial")

REP_CSV = ROOT / "controlled_noise_results.csv"
BCH_COARSE = ROOT / "bch_controlled_noise_results_coarse.csv"
BCH_FINE = ROOT / "bch_transition_results.csv"

OUT_PDF = ROOT / "j2_ecc_robustness_comparison.pdf"
OUT_PNG = ROOT / "j2_ecc_robustness_comparison.png"

PHYSICAL_BER = 0.3335  # percent


def load_csv(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def get_noise_percent(row):
    if row.get("noise_percent") not in (None, ""):
        return float(row["noise_percent"])

    if row.get("noise_rate") not in (None, ""):
        return float(row["noise_rate"]) * 100.0

    raise ValueError("No noise column found")


def get_success_percent(row):
    if row.get("success_percent") not in (None, ""):
        return float(row["success_percent"])

    if row.get("success_rate") not in (None, ""):
        return float(row["success_rate"]) * 100.0

    raise ValueError("No success column found")


# ------------------------------------------------------------
# Repetition-13
# ------------------------------------------------------------

rep_rows = load_csv(REP_CSV)

rep_points = sorted(
    [
        (
            get_noise_percent(row),
            get_success_percent(row)
        )
        for row in rep_rows
    ]
)


# ------------------------------------------------------------
# BCH coarse + fine
#
# Fine sweep replaces coarse point if same percentage exists.
# ------------------------------------------------------------

bch_points = {
    "BCH-A": {},
    "BCH-C": {},
}

for row in load_csv(BCH_COARSE):
    scheme = row["scheme"]

    if scheme in bch_points:
        x = get_noise_percent(row)
        y = get_success_percent(row)
        bch_points[scheme][x] = y

for row in load_csv(BCH_FINE):
    scheme = row["scheme"]

    if scheme in bch_points:
        x = get_noise_percent(row)
        y = get_success_percent(row)

        # Fine result intentionally overrides coarse result.
        bch_points[scheme][x] = y


# ------------------------------------------------------------
# Plot
# ------------------------------------------------------------

fig, ax = plt.subplots(figsize=(8.0, 5.2))

rep_x = [p[0] for p in rep_points]
rep_y = [p[1] for p in rep_points]

ax.plot(
    rep_x,
    rep_y,
    marker="o",
    linewidth=1.8,
    label="Repetition-13 (1664 bits)"
)

BCH_LABELS = {
    "BCH-A": "BCH (m=8, t=8; 192 bits)",
    "BCH-C": "BCH (m=9, t=16; 272 bits)",
}

for scheme in ["BCH-A", "BCH-C"]:

    points = sorted(
        bch_points[scheme].items()
    )

    x = [p[0] for p in points]
    y = [p[1] for p in points]

    ax.plot(
        x,
        y,
        marker="o",
        linewidth=1.8,
        label=BCH_LABELS[scheme]
    )


ax.axvline(
    PHYSICAL_BER,
    linestyle="--",
    linewidth=1.4,
    label="Physical held-out BER reference (0.3335%)"
)

ax.set_xlabel(
    "Additional synthetic injected bit-flip rate (%)"
)

ax.set_ylabel(
    "Successful key reconstruction (%)"
)

ax.set_xlim(left=0)
ax.set_ylim(-2, 102)

ax.grid(True, alpha=0.25)
ax.legend(frameon=True)

fig.tight_layout()

fig.savefig(
    OUT_PDF,
    bbox_inches="tight"
)

fig.savefig(
    OUT_PNG,
    dpi=300,
    bbox_inches="tight"
)

print(f"PDF written to: {OUT_PDF}")
print(f"PNG written to: {OUT_PNG}")
