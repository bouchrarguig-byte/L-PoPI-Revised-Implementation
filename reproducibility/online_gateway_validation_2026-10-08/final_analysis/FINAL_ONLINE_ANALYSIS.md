# Final Three-Run Online Gateway Analysis

Frozen deployment policy: Cog-GAT mode=src, alpha=0.1, lambda=0.8, threshold=0.512. No live training or live retuning.

## Run completeness

| run   |   pcap_files |   processed_windows |   unprocessed_pcaps | unprocessed_names           |   processed_missing_file |   remaining_part_files |   flow_rows | complete   |
|:------|-------------:|--------------------:|--------------------:|:----------------------------|-------------------------:|-----------------------:|------------:|:-----------|
| run01 |          294 |                 293 |                   1 | window_20261008T161752.pcap |                        0 |                      0 |         292 | False      |
| run02 |          321 |                 320 |                   1 | window_20261008T170054.pcap |                        0 |                      0 |         319 | False      |
| run03 |          291 |                 291 |                   0 |                             |                        0 |                      0 |         290 | True       |

## Receiver audit

| run   |   raw_receiver_rows |   pre_experiment_rows |   experiment_messages |   seq_min |   seq_max | sequence_continuous   |   missing_seq_count |   duplicate_seq_count |   warmup_messages |   baseline_messages |   variation_messages |   burst_messages |
|:------|--------------------:|----------------------:|----------------------:|----------:|----------:|:----------------------|--------------------:|----------------------:|------------------:|--------------------:|---------------------:|-----------------:|
| run01 |                 869 |                     9 |                   860 |         0 |       859 | True                  |                   0 |                     0 |                20 |                 121 |                  120 |              599 |
| run02 |                 861 |                     0 |                   861 |         0 |       860 | True                  |                   0 |                     0 |                21 |                 119 |                  120 |              601 |
| run03 |                 860 |                     0 |                   860 |         0 |       859 | True                  |                   0 |                     0 |                20 |                 120 |                  120 |              600 |

## Pooled behavioral results

| phase     |   flows |   normal |   risk |   risk_fraction |   gat_probability_mean |   coggat_score_mean |   coggat_score_median |   coggat_score_p95 |   coggat_score_max |   pkts_mean |   bytes_mean |    dur_mean |
|:----------|--------:|---------:|-------:|----------------:|-----------------------:|--------------------:|----------------------:|-------------------:|-------------------:|------------:|-------------:|------------:|
| BASELINE  |     359 |      359 |      0 |               0 |               0.511643 |            0.511641 |              0.511643 |           0.511643 |           0.511643 |     2       |      252.329 | 0.000322373 |
| VARIATION |     259 |      259 |      0 |               0 |               0.51161  |            0.511603 |              0.511611 |           0.511638 |           0.511644 |     2.21622 |      370.421 | 0.0539386   |
| BURST     |     180 |      180 |      0 |               0 |               0.508765 |            0.509139 |              0.508858 |           0.510522 |           0.511632 |    19.8333  |     6314.78  | 0.875719    |

## Pooled latency and resource statistics

| metric                          |   n |       mean |        sd |     median |        p95 |        min |        max |
|:--------------------------------|----:|-----------:|----------:|-----------:|-----------:|-----------:|-----------:|
| argus_ra_ms                     | 798 |  424.214   | 33.763    |  444.404   |  461.068   |  346.647   |  518.85    |
| ml_inference_ms                 | 798 |   10.1404  |  1.84794  |   10.1607  |   12.115   |    2.53468 |   15.6516  |
| processing_start_to_decision_ms | 798 |  441.591   | 35.4132   |  461.485   |  480.952   |  352.72    |  543.842   |
| pcap_finalized_to_decision_ms   | 798 |  527.748   | 39.6175   |  530.895   |  583.425   |  433.301   |  754.28    |
| window_start_to_decision_est_ms | 798 | 1527.75    | 39.6175   | 1530.89    | 1583.43    | 1433.3     | 1754.28    |
| pipeline_cpu_percent            | 798 |   35.6642  |  5.41111  |   38.6583  |   41.6617  |   16.5851  |   49.551   |
| host_cpu_percent                | 798 |    7.02455 |  2.30756  |    6.29185 |   11.54    |    4.44811 |   25.3814  |
| python_rss_after_mb             | 798 | 1265.28    |  0.531089 | 1265.31    | 1266.06    | 1264.11    | 1266.16    |
| observed_flows_per_s            | 798 |    1       |  0        |    1       |    1       |    1       |    1       |
| processing_throughput_flows_s   | 798 |    2.27941 |  0.185942 |    2.16692 |    2.54916 |    1.83877 |    2.83511 |

## Conservative interpretation

- Baseline Cog-GAT mean: 0.511641.
- Benign variation Cog-GAT mean: 0.511603.
- Controlled burst Cog-GAT mean: 0.509139.
- Threshold remained fixed at 0.512.
- Published-phase flows classified RISK: 0 / 798.
- The controlled burst is a high-rate benign perturbation and must not be described as a cyberattack or as an attack-detection recall test.
- The online experiment evaluates prospective physical gateway feasibility, latency, resource stability, and behavior under controlled traffic conditions.

## Key operational result

- argus_ra_ms: mean=424.214 ms, median=444.404 ms, p95=461.068 ms, max=518.850 ms.
- ml_inference_ms: mean=10.140 ms, median=10.161 ms, p95=12.115 ms, max=15.652 ms.
- processing_start_to_decision_ms: mean=441.591 ms, median=461.485 ms, p95=480.952 ms, max=543.842 ms.
- pcap_finalized_to_decision_ms: mean=527.748 ms, median=530.895 ms, p95=583.425 ms, max=754.280 ms.
- window_start_to_decision_est_ms: mean=1527.748 ms, median=1530.895 ms, p95=1583.425 ms, max=1754.280 ms.