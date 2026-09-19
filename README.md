# L-PoPI — Revised Implementation and Reproducibility Artifacts

This repository contains the implementation and experimental artifacts
supporting the revised evaluation of L-PoPI.

The repository accompanies the revised manuscript:

**L-PoPI: A Lightweight Four-Layer Architecture Anchoring Silicon
Fingerprints, Zero-Knowledge Proofs, and Behavioral AI for DePIN IoT
Attestation**

## Scope

The revised evaluation is organized into five validation stages:

- **J1 — Physical SRAM-PUF characterization**
- **J2 — BCH-C fuzzy extractor and physical reproduction**
- **J3 — Physical FE-to-ZK binding and Groth16 evaluation**
- **J4 — EVM verification, freshness, replay protection, and gas evaluation**
- **J5 — Behavioral Cog-GAT/AE evaluation and risk-adaptive DPI gating**

J1–J4 form the experimentally linked physical-to-ledger validation path.

J5 is a separately evaluated behavioral branch intended to complement,
rather than replace, cryptographic attestation.

The repository does **not** claim a single physically continuous
end-to-end deployment integrating all five stages.

---

## J1 — Physical SRAM-PUF Characterization

### Platform

- ESP32
- 4 MB flash
- CPU frequency: 160 MHz
- ESP-IDF experimental environment
- SRAM capture region: `0x3FFF2000`
- Capture size: 256 bytes / 2048 bits

SRAM is captured through an early boot hook before normal application
initialization.

### Cold-Power Experiment

Thirty cold-power captures were collected.

The first 20 captures were used for enrollment and captures 21–30 were
held out for evaluation.

Observed results include:

- mean per-bit reliability: 96.1442%
- median per-bit reliability: 100%
- 1643 / 2048 cells with reliability >= 97%
- pairwise BER mean: 5.5452%
- pairwise BER maximum: 6.8848%

For the enrollment-selected stable cells, the held-out BER was:

- mean: 0.3335%
- maximum: 0.7743%

The 0.3335% value refers specifically to enrollment-selected cells and
must not be interpreted as the raw SRAM-PUF BER.

### Limitations

The physical characterization was performed on one ESP32 prototype.
Population-level uniqueness, inter-device Hamming distance, bit aliasing,
and environmental temperature/voltage/aging characterization are not
claimed.

---

## J2 — BCH-C Fuzzy Extractor

The revised fuzzy-extractor backend uses a shortened BCH configuration:

- `m = 9`
- `t = 16`
- `n = 511`
- 144 parity bits
- 16-byte secret
- shortened codeword: 272 bits

The helper construction combines enrollment-selected SRAM-PUF bits with
the BCH codeword. Successful reproduction additionally requires the
derived-key commitment check.

### Prospective Physical Cold-Power Validation

Ten prospectively recorded cold-power trials were evaluated using the
frozen enrollment/helper configuration.

Decoder error counts:

`1, 1, 1, 2, 1, 2, 1, 3, 5, 0`

Results:

- 10 / 10 BCH decoding successes
- 10 / 10 commitment checks passed
- 10 / 10 key reproductions passed
- corrected errors: 0–5
- mean corrected errors: 1.7
- BCH correction capability: `t = 16`

These results characterize the evaluated ESP32 prototype only.

### Adversarial Checks

The repository also contains controlled helper/salt/commitment
perturbation experiments.

Important interpretation:

- correctable helper perturbations can still decode successfully;
- helper data are therefore not described as universally authenticated;
- salt or commitment perturbations were rejected by the final key
  validation in the tested experiments.

Synthetic independent bit-flip experiments are provided separately and
must not be interpreted as physical BER measurements.

---

## J3 — Physical FE-to-ZK Binding

The fuzzy-extractor-derived key is deterministically mapped to the
BN254 scalar field using domain-separated HKDF-based rejection sampling.

The resulting scalar is used as the private witness of the Groth16
circuit.

The optimized circuit uses:

Private input:

- `k`

Public inputs:

- `deviceID`
- `nonce`
- `enrollmentCommitment`
- `sessionCommitment`

Commitments:

- `C_E = Poseidon(k, deviceID)`
- `C_S = Poseidon(C_E, nonce)`

The evaluated circuit contains:

- 1038 wires
- 4 public inputs
- 1 private input
- 1034 constraints

A physical ESP32 run was also used to verify cross-implementation
agreement of the FE-to-BN254 derivation.

This demonstrates deterministic cross-layer binding; it is **not**
presented as a production-secure witness transport mechanism.

### Host Benchmark

For runs 2–30, after treating the first run as initialization/warm-up:

- witness mean: 24.137 ms
- witness median: 23.538 ms
- proving mean: 64.367 ms
- proving median: 64.156 ms
- verification mean: 10.108 ms
- verification median: 10.084 ms

These are host-side measurements. They are not ESP32 proving times.

---

## J4 — EVM Verification and Freshness

The final FE-derived Groth16 proof was evaluated with the actual
verifier and stateful freshness wrapper.

Final gas measurements using `gasleft()` instrumentation:

- verifier-only FE proof: 215,569 gas
- first stateful FE verification: 241,121 gas
- subsequent stateful verification: 212,179 gas
- stale replay rejection: 3,241 gas

The replay rejection is provided by protocol state and nonce tracking;
it is not an intrinsic property of Groth16.

Historical optimization experiments are retained separately from the
final FE-derived measurement path.

---

## J5 — Behavioral Evaluation and Adaptive DPI

The behavioral experiments use BoT-IoT data with disjoint CSV-file
groups for training, validation, and testing.

The controlled cohort retains all available benign records and applies
deterministic attack undersampling. No SMOTE is used.

Reported metrics include:

- balanced accuracy
- macro-F1
- MCC
- ROC-AUC
- class-specific recall
- false-positive rate

The repository includes MLP, GATv2, and causal-history Cog-GAT
experiments.

The behavioral model is not used as a substitute for cryptographic
authentication.

Cryptographic proof/freshness failure remains a hard rejection
condition. Behavioral risk is evaluated after the hard cryptographic
gate and can drive additional monitoring, challenge, restriction, or
quarantine decisions.

### DPI Gating

The repository includes validation-selected DPI-gating experiments and
distribution-shift tests.

The reported DPI reductions refer to flow-count reduction in the
evaluated cohorts. They must not be interpreted as direct energy
measurements.

The late-file challenge is an internal BoT-IoT split and is not claimed
to be an external or pristine dataset.

---

## Repository Organization

Key directories include:

```text
main/                    ESP32 SRAM-PUF and fuzzy-extractor firmware
puf_analysis*/           Physical SRAM-PUF analysis
puf_results*/            Physical capture artifacts
j2_adversarial/          BCH-C, physical FE, and adversarial validation
j3_cross_layer/          FE-to-ZK binding artifacts
j3_zk/                   Circom/Groth16/EVM experiments
j5_ai/                   Behavioral AI, CLSE, and DPI experiments
