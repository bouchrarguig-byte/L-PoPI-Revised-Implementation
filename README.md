# L-PoPI — Revised Implementation and Reproducibility Artifacts

This repository contains the implementation and experimental artifacts supporting the revised manuscript:

**L-PoPI: Cross-Layer Physical-to-EVM Attestation for DePIN IoT**

## Scope

L-PoPI is evaluated as a cross-layer physical-to-EVM attestation framework linking:

- early-boot ESP32 SRAM-PUF acquisition;
- BCH-C fuzzy extraction and key reproduction;
- fuzzy-extractor-derived BN254/Groth16/Poseidon binding;
- freshness-aware EVM verification and replay rejection.

A Cognitive Graph Attention Network (Cog-GAT)/autoencoder branch is evaluated separately as a complementary post-attestation risk layer. It does not replace or bypass the physical/cryptographic attestation path.

The repository separates measurements by experimental environment rather than combining them into an artificial single latency figure.

## Public reproducibility release

The six-device SRAM-PUF validation is frozen in the release:

**Tag:** `r1-multidevice-validation-2026-10-06`  
**Release:** https://github.com/bouchrarguig-byte/L-PoPI-Revised-Implementation/releases/tag/r1-multidevice-validation-2026-10-06  
**Frozen release commit:** `0708a4ef7cc3bbbac9d4e864198ed966edddf7a7`

The cold-power acquisition firmware used for the final D0-D5 campaign was frozen at:

**Firmware commit:** `8670f38`

The release contains the anonymized raw SRAM captures, acquisition protocol, integrity manifests, analysis scripts, reproduced results, and BCH-C replay artifacts.

## Physical SRAM-PUF characterization

### Original integrated ESP32 campaign

The original integrated campaign used one ESP32 board and 30 cold-power acquisitions from a 256-byte SRAM region captured through an early-boot hook.

Observed raw SRAM-PUF results included:

- mean per-bit reliability: **96.14%**;
- mean pairwise intra-device BER: **5.55%**;
- enrollment-selected held-out BER: **0.33%**;
- BCH-C key reproduction: **10/10 prospective held-out trials**;
- corrected errors: **0–5**, with BCH correction capability `t = 16`.

The 0.33% value refers only to enrollment-selected stable cells and is not the raw SRAM-PUF BER.

### Six-device follow-up campaign

To directly evaluate inter-device differentiation on physical hardware, a separate campaign collected:

- **6 physical ESP32 boards (D0-D5)**;
- **30 cold-power acquisitions per board**;
- **180/180 valid captures**;
- captures **1–20** for enrollment;
- captures **21–30** held out for evaluation.

The homogeneous rev-v3.1 cohort D1-D5 produced:

- **N = 5 devices**;
- **10 independent device pairs**;
- mean inter-device normalized Hamming distance: **49.2188%**;
- observed range: approximately **48.10–50.93%**.

The extended D0-D5 cohort produced:

- **N = 6 devices**;
- **15 independent device pairs**;
- mean inter-device normalized Hamming distance: **49.0885%**;
- observed range: approximately **47.75–50.98%**.

Across the six boards:

- mean raw per-bit reliability: approximately **95.80%**;
- all **60/60 held-out BCH-C reconstructions succeeded**;
- only **0–4 errors** were corrected per 272-bit shortened BCH packet;
- a common-mask stress test also produced **60/60 successful reconstructions**;
- **547** enrollment-stable positions were common to all six devices.

These results constitute a **six-device pilot characterization** of physical ESP32 uniqueness and reproducibility; they are not presented as a large-scale population proof.

## BCH-C fuzzy extractor

The evaluated fuzzy-extractor backend uses a shortened BCH configuration:

- `m = 9`;
- `t = 16`;
- `n = 511`;
- `128` data bits;
- `144` parity bits;
- shortened packet length: `272` bits.

For the linear `[272,128]` helper construction, the helper-data exposure is bounded by the `144` parity/coset bits rather than by the full serialized helper length. The revised manuscript therefore uses the conditional leakage bound

`I(R_S ; W | S) <= 144 bits`

and the corresponding conditional min-entropy reduction bound.

The public selected-cell set, helper data, HKDF salt, and final key commitment are treated separately in the security analysis. The commitment acts as a candidate verifier and is not counted as extra secret entropy.

The deterministic benchmark secret retained in the repository is a reproducibility fixture for conformance testing; it is not a production secret-generation procedure.

## Physical fuzzy-extractor-to-zero-knowledge binding

The fuzzy-extractor-derived key is deterministically mapped into the BN254 scalar field using domain-separated HKDF-based rejection sampling.

The resulting scalar is used as the private witness of the Groth16 attestation circuit.

The evaluated circuit uses:

- private witness: `k`;
- public inputs: `deviceID`, `nonce`, `enrollmentCommitment`, `sessionCommitment`;
- enrollment commitment: `C_E = Poseidon(k, deviceID)`;
- session commitment: `C_S = Poseidon(C_E, nonce)`;
- **1,034 constraints**.

Cross-implementation vectors in `j3_cross_layer/` bind the reproduced FE key to the Groth16 witness representation.

## Groth16 host benchmark

For steady-state host runs after initialization:

- witness generation: approximately **24.14 ms** mean;
- proof generation: approximately **64.37 ms** mean;
- proof verification: approximately **10.11 ms** mean.

These are host-side measurements and are not presented as ESP32 proving times.

## EVM verification, freshness, and replay protection

The final fuzzy-extractor-derived proof path was evaluated with the Solidity verifier and stateful freshness wrapper.

Representative measurements include:

- verifier-only proof verification: **215,569 gas**;
- first stateful attestation: **241,121 gas**;
- subsequent stateful attestation: **212,179 gas**;
- stale replay rejection: **3,241 gas**.

Replay protection is provided by protocol state and monotonic freshness checking rather than by Groth16 alone.

The Foundry regression suite includes valid FE-derived proofs, sequential attestations, and replay/stale-proof rejection tests.

## Behavioral post-attestation evaluation

The Cog-GAT/autoencoder component is evaluated as a **separate gateway-side post-attestation risk extension**.

The behavioral experiments use controlled BoT-IoT train/validation/test partitions and report classification and risk-gating metrics. Cryptographic proof failure, public-input mismatch, or stale freshness state remains a hard rejection condition before behavioral evidence is considered.

For cryptographically valid sessions, behavioral risk can influence post-attestation actions such as monitoring, challenge, restriction, quarantine, or adaptive DPI intensity.

Behavioral measurements are not used to claim correctness of the physical-to-EVM attestation path.

## Scoped compositional security argument

The revised manuscript provides a scoped compositional security argument for the physical-to-EVM path under explicit assumptions covering:

- FE reproduction/security;
- commitment binding;
- Groth16 knowledge soundness;
- freshness/state enforcement;
- public-context binding;
- separation of the behavioral post-attestation branch from the hard cryptographic gate.

The argument is intentionally scoped to the stated adversarial model and does not reinterpret physical side-channel compromise, invasive extraction, blockchain consensus failure, or compromised witness transport as cryptographic guarantees of the attestation construction.

## Repository organization

Key directories include:

```text
main/                                   ESP32 SRAM-PUF and fuzzy-extractor firmware
experiments/esp32_multidevice_D0_D5/   Six-device cold-power campaign and replay analysis
puf_analysis*/                          Earlier physical SRAM-PUF analysis artifacts
puf_results*/                           Earlier physical capture artifacts
j2_adversarial/                         BCH-C and adversarial validation
j3_cross_layer/                         FE-to-BN254/Groth16 binding artifacts
j3_zk/                                  Circom, Groth16, Foundry, and EVM experiments
j5_ai/                                  Behavioral AI and adaptive-DPI experiments
```

## Reproducing the D0-D5 analysis

From the repository root:

```bash
python3 experiments/esp32_multidevice_D0_D5/analysis/analyze_multidevice.py
```

Expected summary:

```text
PASS: 180 captures analyzed
Primary D1-D5 uniqueness: 49.2188% (10 pairs)
Extended D0-D5 uniqueness: 49.0885% (15 pairs)
FE held-out: 60/60; max corrected errors=4/16
Common-mask stress test: 60/60; perfect common cells=547
```

Integrity manifests are included in the experiment directory.

## Evidence boundaries

The repository supports the claims reported in the revised manuscript within the measured environments. In particular:

- the D0-D5 experiment is a six-device ESP32 pilot, not a large-scale manufacturing-population study;
- host Groth16 timings are not ESP32 proving timings;
- EVM gas measurements are not device-energy measurements;
- behavioral results are controlled gateway-side evaluations, not a substitute for cryptographic attestation;
- synthetic perturbation tests are stress/conformance tests, not physical BER measurements.

These boundaries are part of the measurement definition and prevent cross-environment results from being over-interpreted.

## Citation

If you use this repository, please cite the accompanying manuscript:

**L-PoPI: Cross-Layer Physical-to-EVM Attestation for DePIN IoT**

Citation metadata can be updated after publication.
