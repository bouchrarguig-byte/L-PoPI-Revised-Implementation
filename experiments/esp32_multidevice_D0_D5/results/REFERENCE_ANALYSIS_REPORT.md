# L-PoPI D0–D5 Multi-Device SRAM-PUF Final Analysis

## Audit and dataset integrity

- Archive analyzed: `LPOPI_D0_D5_FINAL_180CAPTURES.tar.gz`
- Final acquisition commit: `8670f38`
- Devices: D0–D5 (6 physical ESP32 boards)
- Valid captures: **180/180** (30 per device)
- SRAM region: Region 1, `0x3FFF2000`, 256 bytes = 2048 bits
- Split fixed in metadata: captures **001–020 enrollment**, **021–030 held-out**
- SHA-256 verification: **30/30 capture files passed for every device**
- Acquisition-layer failed attempts were never counted: D0=0, D1=0, D2=1, D3=2, D4=3, D5=0 (6 retries total). These are host/UART acquisition retries, not PUF bit-error events.

## Analysis protocol

1. Build one 2048-bit enrollment template per device from captures 001–020 by majority vote. Exact 10/10 ties are broken deterministically with capture 001.
2. Compute template uniformity as the fraction of ones.
3. Compute raw held-out BER for captures 021–030 against that device's enrollment template.
4. Compute inter-device uniqueness from Hamming distance between enrollment templates.
5. Stable-cell selection uses enrollment data only: rank all 2048 bit positions by enrollment stability, break equal-stability ties by ascending bit index, and freeze the first 272 positions. Held-out data are never used for selection.
6. BCH-C replay uses the exact firmware parameters: m=9, t=16, n=511, primitive polynomial 0x211, shortened packet 272 bits = 128 data + 144 ECC bits. The Python replay reproduces the firmware encoder/decoder algorithm and passes its published reference vectors and deterministic 0/1/8/16/17-error decoder tests.
7. A public deterministic 128-bit benchmark secret is used only to make the offline code-offset FE replay reproducible; it is not a production secret-generation procedure. HKDF-SHA256 key reconstruction and commitment verification are included in the replay.

## Reviewer-ready per-device table

| Device | Rev. | Reliability (%) | Uniformity (%) | Held-out raw BER (%) | Perfect-stable cells (20/20) | BCH errors mean | BCH errors max | FE held-out |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| D0 | v3.0 | 95.8447 | 48.9258 | 4.3555 | 1659 | 0.5000 | 2 | 10/10 |
| D1 | v3.1 | 95.7926 | 50.2930 | 4.3799 | 1634 | 0.7000 | 4 | 10/10 |
| D2 | v3.1 | 96.0547 | 49.5117 | 4.2773 | 1659 | 1.0000 | 3 | 10/10 |
| D3 | v3.1 | 95.6868 | 50.7324 | 4.7998 | 1647 | 1.5000 | 3 | 10/10 |
| D4 | v3.1 | 95.9945 | 48.4375 | 4.2188 | 1655 | 0.8000 | 3 | 10/10 |
| D5 | v3.1 | 95.4492 | 51.2207 | 4.9512 | 1607 | 0.8000 | 3 | 10/10 |

**Six-device means:** all-capture reliability = **95.8038% ± 0.2193%**; enrollment-template uniformity = **49.8535% ± 1.0786%**; held-out raw BER = **4.4971% ± 0.3025%** across device means.

## Inter-device uniqueness

### Primary homogeneous cohort: D1–D5 (all rev v3.1)

- N = 5 devices; 10 inter-device pairs
- Mean normalized inter-device HD: **49.2188%**
- SD across 10 pair values: **1.0193%**
- Range: **48.0957%–50.9277%**

### Extended cohort: D0–D5

- N = 6 devices; 15 inter-device pairs
- Mean normalized inter-device HD: **49.0885%**
- SD across 15 pair values: **1.0721%**
- Range: **47.7539%–50.9766%**
- Adding historical rev-v3.0 D0 changes the mean uniqueness by only **-0.1302 percentage points**.

| Device A | Device B | HD (bits) | Normalized HD (%) |
| --- | --- | --- | --- |
| D0 | D1 | 1044 | 50.9766 |
| D0 | D2 | 978 | 47.7539 |
| D0 | D3 | 995 | 48.5840 |
| D0 | D4 | 988 | 48.2422 |
| D0 | D5 | 995 | 48.5840 |
| D1 | D2 | 1024 | 50.0000 |
| D1 | D3 | 997 | 48.6816 |
| D1 | D4 | 1034 | 50.4883 |
| D1 | D5 | 1019 | 49.7559 |
| D2 | D3 | 985 | 48.0957 |
| D2 | D4 | 998 | 48.7305 |
| D2 | D5 | 1043 | 50.9277 |
| D3 | D4 | 985 | 48.0957 |
| D3 | D5 | 1006 | 49.1211 |
| D4 | D5 | 989 | 48.2910 |

## Genuine vs inter-device separation

Across all 60 held-out captures, raw BER to the correct enrollment template is:

- Mean: **4.4971%**
- SD: **0.4348%**
- Range: **3.3691%–5.3223%**

The smallest inter-device template distance is **47.7539%**. Therefore, in this six-device pilot cohort, the observed genuine and inter-device distance ranges do **not overlap**.

## Bit aliasing

For the six enrollment templates, mean bit-aliasing is **49.8535%**. Because N=6, per-bit aliasing can take only 0, 16.67, 33.33, 50, 66.67, 83.33, or 100%.

- Exactly 50% aliasing (3 ones / 3 zeros): **606 / 2048 = 29.59%**
- Between 33.33% and 66.67% inclusive: **1528 / 2048 = 74.61%**
- All-zero positions: 37
- All-one positions: 33

## BCH-C / fuzzy-extractor held-out replay

Per-device stable-cell pools contain **1607–1659 positions that were perfectly stable in all 20 enrollment captures**, so the 272 selected BCH positions are 20/20 stable on every device.

Exact firmware-equivalent offline BCH-C + code-offset + HKDF/commitment replay on captures 021–030:

- **60/60 held-out reconstructions PASS**
- Corrected errors per 272-bit BCH packet: overall range **0–4**
- BCH correction capability: **t = 16**
- Largest observed held-out error count uses only **4/16 = 25.0%** of the decoder's guaranteed correction radius.

A conservative pooled-mask check gives the same conclusion. There are **547** bit positions that were perfect (20/20) in the enrollment data of **all six devices simultaneously**; freezing the first 272 common positions still yields **60/60** held-out BCH reconstructions, with a worst case of **4** corrected bits.

## Scope language for the manuscript

These results support a **six-device pilot characterization**, not a population-level manufacturing claim. The primary cohort should remain the homogeneous D1–D5 rev-v3.1 set, while D0 should be reported as an extended rev-v3.0 validation device. The held-out split and stable-cell selection should be stated explicitly to avoid any appearance of test-set leakage.

## Suggested Reviewer 1 (R1-3) response wording

> We agree that the original single-board characterization was insufficient. We therefore added a controlled multi-device SRAM-PUF campaign using six physically distinct ESP32 boards and 30 complete cold-power acquisitions per board (180 valid responses total). To preserve hardware homogeneity, the principal cohort comprises five ESP32 rev-v3.1 devices (D1–D5), while the historical rev-v3.0 board (D0) is reported separately as an extended validation device. Captures 1–20 were frozen for enrollment and captures 21–30 were held out from all stable-cell selection. The homogeneous five-device cohort achieved a mean inter-device normalized Hamming distance of 49.22% across all 10 device pairs; the six-device extended cohort achieved 49.09% across 15 pairs. Across the six devices, mean all-capture bit reliability was 95.80%, while mean held-out raw BER against enrollment templates was 4.50%. For the BCH-C fuzzy extractor (272-bit shortened packet, t=16), enrollment-only stable-cell selection followed by firmware-equivalent offline decoding reconstructed the enrolled key on all 60 held-out responses (60/60), with only 0–4 corrected bit errors per packet. These results materially extend the previous single-board evidence, although we conservatively describe the experiment as a pilot multi-device characterization rather than population-scale silicon validation.
