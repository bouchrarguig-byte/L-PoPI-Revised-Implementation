#!/usr/bin/env bash
set -euo pipefail

RUNS=30
OUT="results/groth16_benchmark.csv"

echo "run,witness_ms,prove_ms,verify_ms" > "$OUT"

for i in $(seq 1 "$RUNS"); do
    WITNESS="build/bench_${i}.wtns"
    PROOF="build/bench_proof_${i}.json"
    PUBLIC="build/bench_public_${i}.json"

    t0=$(date +%s%N)
    node \
      build/lpopi_attestation_js/generate_witness.js \
      build/lpopi_attestation_js/lpopi_attestation.wasm \
      inputs/input_n1.json \
      "$WITNESS"
    t1=$(date +%s%N)

    snarkjs groth16 prove \
      build/lpopi_attestation_final.zkey \
      "$WITNESS" \
      "$PROOF" \
      "$PUBLIC"
    t2=$(date +%s%N)

    snarkjs groth16 verify \
      build/verification_key.json \
      "$PUBLIC" \
      "$PROOF" >/dev/null
    t3=$(date +%s%N)

    witness_ms=$(( (t1-t0)/1000000 ))
    prove_ms=$(( (t2-t1)/1000000 ))
    verify_ms=$(( (t3-t2)/1000000 ))

    echo "$i,$witness_ms,$prove_ms,$verify_ms" | tee -a "$OUT"

    rm -f "$WITNESS" "$PROOF" "$PUBLIC"
done

echo
echo "Saved to $OUT"
