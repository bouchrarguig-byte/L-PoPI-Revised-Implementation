# Frozen D0-D5 acquisition and analysis protocol

## Hardware cohort

- D1-D5: five physically distinct ESP32-D0WD-V3 revision v3.1 boards; this is the primary homogeneous cohort.
- D0: historical ESP32-D0WDQ6-V3 revision v3.0 board; reported as an extended validation device rather than merged into the homogeneous-hardware claim.
- ESP8266 hardware is not included in this cohort.

## Acquisition

- Frozen firmware commit recorded by the collector: `8670f38`.
- SRAM Region 1: address `0x3FFF2000`, 256 bytes = 2048 bits.
- 30 valid cold-power acquisitions per device.
- Each acquisition required a complete USB power disconnection followed by exactly 10 s off-power before reconnection.
- The RESET button was not used for measurement cycles.
- Transport-level UART failures were discarded before a valid PUF frame was recorded; the same capture index was retried only after another full cold-power cycle. Such retries are not PUF bit-error observations.
- Recorded non-counted acquisition retries: D0=0, D1=0, D2=1, D3=2, D4=3, D5=0.

## Fixed split

- Enrollment: captures `001-020`.
- Held-out evaluation: captures `021-030`.
- Held-out captures are never used for cell selection or template construction.

## Enrollment template

For each of 2048 positions, the enrollment template is the majority value across the 20 enrollment captures. An exact 10/10 tie is broken deterministically by the value in capture 001. Tie counts are reported by the analysis script.

## Metrics

- Reliability: mean per-bit majority stability over all 30 acquisitions for each device.
- Uniformity: fraction of ones in the enrollment template.
- Held-out intra-device BER: normalized Hamming distance between each held-out response and that device's enrollment template.
- Uniqueness: normalized Hamming distance between enrollment templates from different physical devices. The primary D1-D5 cohort has exactly 10 independent device pairs; the extended D0-D5 cohort has exactly 15.
- Bit aliasing: at each bit position, fraction of the six device templates equal to one. With N=6 this metric is necessarily coarse.

## BCH-C fuzzy-extractor replay

The firmware-equivalent offline replay uses the frozen BCH-C parameters:

- `m=9`
- `t=16`
- `n=511`
- primitive polynomial `0x211`
- shortened packet: 272 bits = 128 data bits + 144 ECC bits
- generator: `0x12b6bd0545db34c1e01d5296e58c8ed2701ad`

Per device, all 2048 positions are ranked by enrollment-only stability (descending), with bit index as the deterministic tie-break. The first 272 positions are frozen before held-out evaluation. A public deterministic 128-bit benchmark secret is used only for reproducible replay; it is not a production key-generation procedure.

A conservative stress test also uses one common 272-position mask selected from positions that were perfect 20/20 in the enrollment sets of all six boards.

## Scope

This experiment is reported as a **six-device pilot characterization**, not a manufacturing-population proof. The D1-D5 results are the principal homogeneous-hardware result; D0 is an extended revision-v3.0 validation point.
