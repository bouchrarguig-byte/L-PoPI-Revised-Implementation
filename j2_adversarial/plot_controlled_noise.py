import csv
import matplotlib.pyplot as plt

csv_path = "j2_adversarial/controlled_noise_results.csv"
output_pdf = "j2_adversarial/controlled_noise_robustness.pdf"
output_png = "j2_adversarial/controlled_noise_robustness.png"

x = []
y = []
low = []
high = []

with open(csv_path, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        x.append(float(row["noise_percent"]))
        y.append(float(row["success_percent"]))
        low.append(float(row["ci95_low_percent"]))
        high.append(float(row["ci95_high_percent"]))

yerr_low = [a - b for a, b in zip(y, low)]
yerr_high = [b - a for a, b in zip(y, high)]

fig, ax = plt.subplots(figsize=(7.2, 4.8))

ax.errorbar(
    x,
    y,
    yerr=[yerr_low, yerr_high],
    marker="o",
    capsize=3,
    linewidth=1.5
)

# Physical held-out selected-bit BER: context only.
physical_ber = 0.3335
ax.axvline(
    physical_ber,
    linestyle="--",
    linewidth=1.2,
    label="Measured held-out selected-bit BER (0.3335%)"
)

ax.set_xlabel("Synthetic injected bit-flip rate (%)")
ax.set_ylabel("Successful key reconstruction (%)")
ax.set_xlim(0, 50)
ax.set_ylim(-2, 102)
ax.grid(True, alpha=0.25)
ax.legend(loc="lower left", fontsize=8)

fig.tight_layout()

fig.savefig(output_pdf, bbox_inches="tight")
fig.savefig(output_png, dpi=300, bbox_inches="tight")

print("Generated:")
print(output_pdf)
print(output_png)
