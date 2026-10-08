# L-PoPI Prospective Physical Online Gateway Validation

## Scope

This directory contains the reproducibility artifacts for the prospective
physical online gateway experiment added in response to Reviewer 1,
Comment R1-6 for manuscript IoT-4480298:

**L-PoPI: Cross-Layer Physical-to-EVM Attestation for DePIN IoT**

The experiment evaluates the complementary behavioral branch in a real
ESP32-to-gateway deployment.

The behavioral score remains outside the hard physical-to-EVM attestation
acceptance predicate.

## Online architecture

The evaluated pipeline performs:

ESP32 UDP telemetry
-> 1-s packet-capture window
-> Argus 5 bidirectional flow extraction
-> frozen deployment scaler
-> frozen GATv2 model
-> causal Cog-GAT state
-> NORMAL/RISK decision

The deployment is therefore described as:

**1-s stateful windowed online gateway inference**

and not as packet-by-packet inference.

## Frozen deployment policy

The same deployment policy was used for all prospective physical runs:

- mode: `src`
- alpha: `0.1`
- lambda: `0.8`
- threshold: `0.512`
- live training: disabled
- online retuning: disabled
- model modification during runs: none

The threshold 0.512 is the validation-derived prospective deployment
operating point.

No ESP32 live observations were used for training or tuning.

## Online deployment features

The deployment-compatible behavioral model uses:

- `pkts`
- `bytes`
- `dur`

The original Argus `seq` field was excluded from the online deployment
model because repeated fresh Argus processes reset this field.

The online deployment model does not replace the original offline results
reported in the manuscript.

## Physical experiment

Three independent prospective physical runs were performed using an ESP32
and an HP ZBook gateway.

Each run used the following controlled schedule:

- WARMUP: 20 s, approximately 1 message/s, target payload 128 B
- BASELINE: 120 s, approximately 1 message/s, target payload 128 B
- VARIATION: 120 s, repeated transmission intervals of
  500/1500/750/1250 ms and target payload sizes of
  96/256/160/320 B
- BURST: 60 s, approximately 100-ms interval, target payload 512 B

The BURST phase is a controlled benign high-rate traffic perturbation.

It is not an attack condition and must not be used to estimate
cyberattack-detection recall.

## ESP32 receiver integrity

Application-level experiment messages:

- Run01: 860
- Run02: 861
- Run03: 860
- Total: 2,581

Across all final experiment sequences:

- missing sequence numbers: 0
- duplicate sequence numbers: 0

## PCAP-to-gateway completeness

- Run01: 294 PCAPs generated / 293 processed
- Run02: 321 PCAPs generated / 320 processed
- Run03: 291 PCAPs generated / 291 processed

Overall:

- PCAPs generated: 906
- gateway windows processed: 904
- overall processing completeness: 99.78%

The single terminal PCAP in Run01 and Run02 was finalized after the
gateway had already been stopped.

Before Run03, the shutdown procedure was changed only operationally:
the gateway was explicitly allowed to drain all finalized PCAPs before
termination.

Run03 therefore achieved complete PCAP-to-gateway processing.

No model, scaler, policy, threshold, or traffic-generation parameter was
changed between prospective runs.

## Phase-specific behavioral results

Warm-up, mixed-transition, and unlabeled windows were excluded from the
phase-specific manuscript statistics.

| Condition | Flows | NORMAL | RISK | Mean Cog-GAT | Cog-GAT p95 |
|---|---:|---:|---:|---:|---:|
| Baseline | 359 | 359 | 0 | 0.511641 | 0.511643 |
| Benign variation | 259 | 259 | 0 | 0.511603 | 0.511638 |
| Controlled burst | 180 | 180 | 0 | 0.509139 | 0.510522 |

All 798 phase-specific flows remained below the frozen threshold of
0.512.

The controlled burst reduced rather than increased the mean behavioral
score under the evaluated workload. This result is reported as observed
and is not interpreted as attack detection.

## Online latency and resources

Across the 798 phase-specific experimental windows:

| Metric | Mean | Median | p95 | Max |
|---|---:|---:|---:|---:|
| Argus + Ra | 424.214 ms | 444.404 ms | 461.068 ms | 518.850 ms |
| ML inference | 10.140 ms | 10.161 ms | 12.115 ms | 15.652 ms |
| Processing start to decision | 441.591 ms | 461.485 ms | 480.952 ms | 543.842 ms |
| PCAP finalized to decision | 527.748 ms | 530.895 ms | 583.425 ms | 754.280 ms |
| Beginning of 1-s window to decision | 1527.748 ms | 1530.895 ms | 1583.425 ms | 1754.280 ms |

Mean resource usage:

- pipeline CPU: 35.664%
- host CPU: 7.025%
- Python RSS: 1265.280 MB
- processing throughput: approximately 2.28 flow-windows/s

The acquisition cadence was one completed window per second, so the
measured gateway processing capacity remained above the incoming window
rate.

## Argus extraction

The live gateway uses Argus 5.

Before prospective deployment, Argus 3 and Argus 5 were compared on the
same smoke-test PCAPs.

After filtering Argus management records (`proto=man`), all real network
flows matched exactly in the deployment features `pkts`, `bytes`, and
`dur`.

The dedicated equivalence audit is included under:

`extractor_audit/`

## Firmware provenance

The SHA-256 of the exact ESP32 firmware executed during Runs 01-03 is:

`30895801db44d6cca8121ec75626a32ffeb8ca7ba5ec583b5c13523681e08102`

The original source contained local Wi-Fi credentials and is therefore
not redistributed publicly.

The public file:

`firmware/esp32_online_validation_redacted.ino`

differs from the experimentally executed source only in replacement of
the Wi-Fi SSID and password with placeholders.

All scientific and operational experiment parameters remain unchanged.

## PCAP provenance

The raw PCAPs are not included directly in this repository snapshot.

SHA-256 manifests for all generated PCAPs are provided under:

`provenance/`

Expected counts:

- Run01: 294 PCAP hashes
- Run02: 321 PCAP hashes
- Run03: 291 PCAP hashes

## Directory structure

### `code/`

Contains:

- `online_coggat_gateway.py`
- `esp32_udp_receiver.py`
- `analyze_final_3runs.py`

### `firmware/`

Contains the credential-redacted ESP32 experimental firmware.

### `frozen_policy/`

Contains the frozen prospective deployment policy.

### `extractor_audit/`

Contains the frozen Argus 5 extractor configuration and Argus 3/5
equivalence audit.

### `receiver_logs/`

Contains the ESP32 application-level receiver logs from the three runs.

### `gateway_runs/`

Contains per-run:

- session metadata
- session summary
- window metrics
- flow decisions

### `final_analysis/`

Contains:

- receiver audit
- PCAP/gateway completeness audit
- per-run behavioral results
- pooled behavioral results
- pooled latency/resource statistics
- annotated window and flow records
- final JSON summary
- SHA-256 analysis provenance

### `provenance/`

Contains:

- exact experimental firmware provenance
- PCAP SHA-256 manifests
- complete package SHA-256 manifest

## Evidence boundary

This prospective experiment supports claims of:

- physical ESP32-to-gateway operation
- stateful causal gateway inference
- fixed-policy deployment
- continuous 1-s window processing
- bounded post-window latency
- stable host resource use
- absence of decision backlog under the evaluated workload

It does not establish:

- online attack recall
- online attack precision
- universal threshold calibration
- generalization to all IoT networks
- packet-by-packet detection
- behavioral inclusion in the hard attestation predicate

The behavioral branch remains complementary post-attestation risk
evidence.

## Versioning

The previous final second-revision reproducibility snapshot:

`second-revision-final-2026-10-07`

remains preserved unchanged.

This directory represents the subsequent prospective physical online
validation added specifically to strengthen Reviewer 1 Comment R1-6.
