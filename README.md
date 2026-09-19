# L-PoPI — Revised Implementation and Reproducibility Artifacts

This repository contains the implementation and experimental artifacts supporting the revised evaluation of L-PoPI.

The repository accompanies the revised manuscript:

**L-PoPI: Cross-Layer Physical, Zero-Knowledge, and Behavioral Attestation for DePIN IoT**

## Scope

The revised evaluation is organized around five complementary experimental components:

- **Physical SRAM-PUF characterization**
- **BCH-C fuzzy extraction and physical key reproduction**
- **Physical fuzzy-extractor-to-zero-knowledge binding and Groth16 evaluation**
- **EVM verification, freshness, replay protection, and gas evaluation**
- **Behavioral Cog-GAT/autoencoder evaluation and risk-adaptive DPI gating**

The physical SRAM-PUF, fuzzy-extractor, zero-knowledge, and EVM components form the experimentally linked physical-to-ledger attestation path.

The behavioral-security component is evaluated separately and is intended to complement, rather than replace, cryptographic attestation.

The repository does **not** claim a single physically continuous end-to-end deployment integrating all experimental components.

---

## Physical SRAM-PUF Characterization

### Platform

- ESP32
- 4 MB flash
- CPU frequency: 160 MHz
- ESP-IDF experimental environment
- SRAM capture region: `0x3FFF2000`
- Capture size: 256 bytes / 2,048 bits

SRAM is captured through an early boot hook before normal application initialization.

### Cold-Power Experiment

Thirty cold-power captures were collected.

The first 20 captures were used for enrollment, and captures 21–30 were held out for evaluation.

Observed results include:

- mean per-bit reliability: 96.1442%
- median per-bit reliability: 100%
- 1,643 / 2,048 cells with reliability >= 97%
- pairwise BER mean: 5.5452%
- pairwise BER maximum: 6.8848%

For the enrollment-selected stable cells, the held-out BER was:

- mean: 0.3335%
- maximum: 0.7743%

The 0.3335% value refers specifically to enrollment-selected cells and must not be interpreted as the raw SRAM-PUF BER.

### Limitations

The physical characterization was performed on one ESP32 prototype.

Population-level uniqueness, inter-device Hamming distance, bit aliasing, and environmental temperature/voltage/aging characterization are not claimed.

---

## BCH-C Fuzzy Extractor

The revised fuzzy-extractor backend uses a shortened BCH configuration:

- `m = 9`
- `t = 16`
- `n = 511`
- 144 parity bits
- 16-byte secret
- shortened codeword: 272 bits

The helper construction combines enrollment-selected SRAM-PUF bits with the BCH codeword.

Successful reproduction additionally requires the derived-key commitment check.

### Prospective Physical Cold-Power Validation

Ten prospectively recorded cold-power trials were evaluated using the frozen enrollment/helper configuration.

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

The repository also contains controlled helper-data, salt, and commitment perturbation experiments.

Important interpretation:

- correctable helper-data perturbations can still decode successfully;
- helper data are therefore not described as universally authenticated;
- salt or commitment perturbations were rejected by the final key validation in the tested experiments.

Synthetic independent bit-flip experiments are provided separately and must not be interpreted as physical BER measurements.

---

## Physical Fuzzy-Extractor-to-Zero-Knowledge Binding

The fuzzy-extractor-derived key is deterministically mapped to the BN254 scalar field using domain-separated HKDF-based rejection sampling.

The resulting scalar is used as the private witness of the Groth16 circuit.

The evaluated circuit uses:

### Private input

- `k`

### Public inputs

- `deviceID`
- `nonce`
- `enrollmentCommitment`
- `sessionCommitment`

### Commitments

- `C_E = Poseidon(k, deviceID)`
- `C_S = Poseidon(C_E, nonce)`

The evaluated circuit contains:

- 1,038 wires
- 4 public inputs
- 1 private input
- 1,034 constraints

A physical ESP32 run was also used to verify cross-implementation agreement of the fuzzy-extractor-to-BN254 derivation.

This demonstrates deterministic cross-layer binding; it is **not** presented as a production-secure witness transport mechanism.

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

## EVM Verification, Freshness, and Replay Protection

The final fuzzy-extractor-derived Groth16 proof was evaluated with the actual verifier and stateful freshness wrapper.

Final gas measurements using `gasleft()` instrumentation:

- verifier-only fuzzy-extractor-derived proof: 215,569 gas
- first stateful verification: 241,121 gas
- subsequent stateful verification: 212,179 gas
- stale replay rejection: 3,241 gas

Replay rejection is provided by protocol state and nonce tracking; it is not an intrinsic property of Groth16.

Historical optimization experiments are retained separately from the final fuzzy-extractor-derived measurement path.

---

## Behavioral Evaluation and Adaptive DPI

The behavioral experiments use BoT-IoT data with disjoint CSV-file groups for training, validation, and testing.

The controlled cohort retains all available benign records and applies deterministic attack undersampling. No SMOTE is used.

Reported metrics include:

- accuracy
- balanced accuracy
- macro-F1
- MCC
- ROC-AUC
- benign recall
- attack recall
- false-positive rate
- false-negative rate

The repository includes MLP, GATv2, and causal-history Cog-GAT experiments, together with autoencoder-based reconstruction evidence.

The behavioral model is not used as a substitute for cryptographic authentication.

Cryptographic proof or freshness failure remains a hard rejection condition. Behavioral risk is evaluated after the hard cryptographic gate and can drive additional monitoring, challenge, restriction, or quarantine decisions.

The controlled evaluation shows trade-offs rather than universal superiority of one behavioral model.

### Adaptive DPI Gating

The repository includes validation-selected DPI-gating experiments and distribution-shift tests.

The reported DPI reductions refer to flow-count reduction in the evaluated cohorts. They must not be interpreted as direct energy measurements.

The late-file challenge is an internal BoT-IoT split and is not claimed to be an external or pristine dataset.

The experiments show that DPI-gating effectiveness depends on attack-family coverage and distribution shift.

---

## Cross-Layer Acceptance Policy

The evaluated L-PoPI policy treats hardware-backed cryptographic validity and freshness as hard prerequisites.

A failed proof, public-input mismatch, or stale nonce is rejected before behavioral evidence is considered.

Behavioral evidence therefore cannot rescue an invalid cryptographic attestation.

For cryptographically valid sessions, behavioral risk can influence post-authentication actions such as:

- monitoring,
- challenge,
- restriction,
- quarantine,
- adaptive DPI intensity.

This separation preserves the role of the physical and cryptographic trust path while allowing behavioral evidence to provide complementary runtime risk information.

---

## Repository Organization

Key directories include:

```text
main/                    ESP32 SRAM-PUF and fuzzy-extractor firmware
puf_analysis*/           Physical SRAM-PUF analysis
puf_results*/            Physical capture artifacts
j2_adversarial/          BCH-C, physical fuzzy-extractor, and adversarial validation
j3_cross_layer/          Fuzzy-extractor-to-zero-knowledge binding artifacts
j3_zk/                   Circom, Groth16, and EVM experiments
j5_ai/                   Behavioral AI, CLSE, and adaptive DPI experiments
```

The `j2_*`, `j3_*`, and `j5_*` directory names are retained as internal artifact identifiers for reproducibility and compatibility with the existing experimental scripts. They are not manuscript-stage labels.

---

## Reproducibility Scope

The repository separates evidence according to the environment in which it was measured:

- physical ESP32 measurements for SRAM-PUF acquisition and fuzzy-extractor reconstruction;
- host-side measurements for Groth16 witness generation, proving, and verification;
- EVM/Foundry measurements for verifier, freshness, replay, and gas evaluation;
- BoT-IoT-based controlled experiments for behavioral and DPI-gating evaluation.

Measurements from different environments are not summed into a fabricated end-to-end latency or energy figure.

The repository does not claim:

- population-level PUF uniqueness from the single evaluated ESP32;
- environmental temperature, voltage, or aging robustness;
- production-secure witness transport;
- on-device ESP32 Groth16 proving;
- production gateway capacity;
- measured energy per attestation;
- universal behavioral-model superiority;
- external-dataset behavioral generalization;
- a formal compositional security proof;
- end-to-end post-quantum security.

---

## Artifact Interpretation

Physical, synthetic, host-side cryptographic, EVM, and behavioral measurements should be interpreted within their respective experimental boundaries.

In particular:

- synthetic bit-flip sweeps are stress tests, not physical BER measurements;
- correctable helper-data perturbations are not necessarily rejected by the BCH decoder;
- final key validation is distinct from error correction;
- Groth16 verification does not itself provide replay protection;
- freshness is enforced by protocol state;
- behavioral evidence does not replace cryptographic authentication;
- adaptive DPI reduction is a flow-count metric, not an energy measurement.

---

## Citation

If you use this repository, please cite the accompanying manuscript:

**L-PoPI: Cross-Layer Physical, Zero-Knowledge, and Behavioral Attestation for DePIN IoT**

Citation metadata will be updated after publication.

---

## Repository Status

This repository contains the implementation and reproducibility artifacts associated with the revised manuscript.

For peer-review reproducibility, a specific Git commit should be cited in the manuscript and Response to Reviewers after this README revision is committed.
