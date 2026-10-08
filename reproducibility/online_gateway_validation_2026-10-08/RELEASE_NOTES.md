# L-PoPI Prospective Physical Online Gateway Validation

This versioned snapshot contains the prospective physical online gateway
experiment added in response to Reviewer 1 Comment R1-6 for manuscript
IoT-4480298:

**L-PoPI: Cross-Layer Physical-to-EVM Attestation for DePIN IoT**

## Frozen deployment configuration

- Stateful 1-s windowed gateway inference
- Cog-GAT mode: src
- alpha: 0.1
- lambda: 0.8
- threshold: 0.512
- deployment features: pkts, bytes, dur
- live training: disabled
- live retuning: disabled
- model/policy changes during runs: none

The threshold 0.512 is the validation-derived prospective deployment
operating point.

## Physical experiment

Three prospective ESP32-to-gateway runs were performed using the same
frozen model and policy.

Application-level receiver messages:

- Run01: 860
- Run02: 861
- Run03: 860
- Total: 2,581

Across the three experimental sequences:

- missing sequence numbers: 0
- duplicate sequence numbers: 0

## PCAP/gateway completeness

- Run01: 294 PCAPs generated, 293 processed
- Run02: 321 PCAPs generated, 320 processed
- Run03: 291 PCAPs generated, 291 processed

Overall:

- 906 PCAPs generated
- 904 processed
- 99.78% processing completeness

The single terminal PCAP in Runs 01 and 02 was finalized after gateway
termination. Run03 used an explicit gateway-drain condition and achieved
complete processing.

## Behavioral results

After excluding warm-up, mixed transition, and unlabeled windows:

| Condition | Flows | NORMAL | RISK | Mean Cog-GAT |
|---|---:|---:|---:|---:|
| Baseline | 359 | 359 | 0 | 0.511641 |
| Benign variation | 259 | 259 | 0 | 0.511603 |
| Controlled high-rate burst | 180 | 180 | 0 | 0.509139 |

All 798 phase-specific flows remained below the frozen threshold of 0.512.

The burst condition is a controlled benign high-rate perturbation and
must not be interpreted as a cyberattack or used to estimate online
attack recall.

## Online latency

Across the 798 phase-specific windows:

- Argus/Ra mean: 424.214 ms
- ML inference mean: 10.140 ms
- processing-start-to-decision mean: 441.591 ms
- processing-start-to-decision p95: 480.952 ms
- PCAP-finalized-to-decision mean: 527.748 ms
- beginning-of-1-s-window-to-decision mean: 1.528 s

Mean resources:

- pipeline CPU: 35.664%
- host CPU: 7.025%
- Python RSS: 1265.280 MB

## Evidence boundary

This experiment provides prospective evidence for physical
ESP32-to-gateway execution, causal stateful processing, frozen-policy
operation, bounded online latency, and stable resource use.

It does not establish online cyberattack recall or universal threshold
calibration.

The behavioral branch remains complementary post-attestation risk
evidence and is not part of the hard physical-to-EVM attestation
predicate.

## Firmware provenance

The exact firmware executed during Runs 01-03 is identified by SHA-256:

30895801db44d6cca8121ec75626a32ffeb8ca7ba5ec583b5c13523681e08102

The exact experimental file contained local Wi-Fi credentials and is
therefore not redistributed. The public firmware copy differs only by
replacement of the SSID and Wi-Fi password with placeholders.

The previous second-revision snapshot dated 2026-10-07 remains preserved
unchanged.
