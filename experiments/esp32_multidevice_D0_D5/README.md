# L-PoPI six-device ESP32 SRAM-PUF reproducibility package

This directory accompanies the multi-device validation of the L-PoPI SRAM-PUF / BCH-C physical-to-attestation pipeline. It contains the raw cold-power measurements, acquisition logs, metadata, per-device integrity manifests, a standard-library-only reproduction script, and manuscript-ready result tables.

## Dataset at a glance

- 6 physically distinct ESP32 boards: D0-D5.
- 180 valid cold-power SRAM responses: 30 per device.
- Region 1: `0x3FFF2000`, 256 bytes / 2048 bits.
- Enrollment: captures 001-020.
- Held-out: captures 021-030.
- Frozen acquisition commit recorded in all metadata: `8670f38`.
- D1-D5 are the homogeneous rev-v3.1 primary cohort; D0 is a rev-v3.0 extended validation device.

## Reported headline results

| Evaluation | Result |
|---|---:|
| D1-D5 uniqueness, 10 device pairs | 49.2188% |
| D0-D5 uniqueness, 15 device pairs | 49.0885% |
| Six-device mean all-capture reliability | 95.8038% |
| Six-device mean enrollment-template uniformity | 49.8535% |
| Mean held-out raw BER | 4.4971% |
| Held-out BCH-C / FE reconstruction | 60/60 PASS |
| Observed corrected BCH errors | 0-4, with t=16 |
| Common perfect enrollment positions across all six | 547 |
| Common-mask held-out reconstruction | 60/60 PASS |

These values are a pilot multi-device characterization and are not presented as a population-scale manufacturing proof.

## Directory structure

```text
esp32_multidevice_D0_D5/
├── README.md
├── PROTOCOL.md
├── FIRMWARE_PROVENANCE.md
├── PUBLICATION_NOTICE.md
├── device_metadata.csv
├── SOURCE_ARCHIVE_SHA256.txt
├── raw/
│   ├── D0/ ... D5/
│   │   ├── metadata.txt
│   │   ├── collection.log
│   │   ├── SHA256SUMS.txt
│   │   └── puf_results/
│   │       ├── capture_001.txt ... capture_030.txt
│   │       └── puf_measurements.csv
├── analysis/
│   ├── analyze_multidevice.py
│   └── requirements.txt
└── results/
    ├── REFERENCE_ANALYSIS_REPORT.md
    ├── REFERENCE_FE_REPLAY.json
    ├── REFERENCE_TABLES.tex
    └── reproduced/
        ├── analysis_summary.json
        ├── device_summary.csv
        ├── inter_device_HD.csv
        ├── heldout_BER.csv
        ├── bch_fe_results.csv
        ├── common_mask_bch_results.csv
        └── selected_indexes.json
```

## Reproduce the analysis

No third-party Python library is required.

```bash
cd experiments/esp32_multidevice_D0_D5
python3 analysis/analyze_multidevice.py
```

Expected terminal summary:

```text
PASS: 180 captures analyzed
Primary D1-D5 uniqueness: 49.2188% (10 pairs)
Extended D0-D5 uniqueness: 49.0885% (15 pairs)
FE held-out: 60/60; max corrected errors=4/16
Common-mask stress test: 60/60; perfect common cells=547
```

The script includes BCH encoder/decoder conformance tests before analyzing the dataset and writes fresh machine-readable outputs to `results/reproduced/`.

## Verify raw capture integrity

Each device contains its original capture manifest:

```bash
for d in D0 D1 D2 D3 D4 D5; do
  (cd raw/$d && sha256sum -c SHA256SUMS.txt)
done
```

All 30 capture hashes must report `OK` for every device.

## Reproducibility and firmware provenance

The raw acquisition metadata identifies firmware commit `8670f38`. See `FIRMWARE_PROVENANCE.md`. Before citing this directory publicly, ensure the acquisition commit and the final experiment directory are available through an immutable GitHub tag/release.

## Security note

The raw SRAM responses are research data. Do not reuse these six physical boards as devices whose published PUF responses are expected to remain secret. See `PUBLICATION_NOTICE.md`.
