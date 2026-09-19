import fs from "fs";
import { performance } from "perf_hooks";
import { groth16, wtns } from "snarkjs";

const RUNS = 30;

const wasm =
  "build_opt/lpopi_attestation_opt_js/lpopi_attestation_opt.wasm";

const zkey =
  "build_opt/lpopi_attestation_opt_final.zkey";

const vk = JSON.parse(
  fs.readFileSync(
    "build_opt/verification_key_opt.json",
    "utf8"
  )
);

const input = JSON.parse(
  fs.readFileSync(
    "inputs/input_fe_opt_n1.json",
    "utf8"
  )
);

const witnessTimes = [];
const proveTimes = [];
const verifyTimes = [];

function stats(values) {
  const sorted = [...values].sort((a,b) => a-b);
  const mean =
    values.reduce((a,b) => a+b, 0) / values.length;

  const variance =
    values.reduce(
      (a,b) => a + (b-mean)**2, 0
    ) / (values.length - 1);

  const median =
    sorted.length % 2
      ? sorted[(sorted.length-1)/2]
      : (
          sorted[sorted.length/2 - 1] +
          sorted[sorted.length/2]
        ) / 2;

  return {
    n: values.length,
    mean,
    median,
    stdev: Math.sqrt(variance),
    min: sorted[0],
    max: sorted[sorted.length-1]
  };
}

console.log(
  "=== L-PoPI FE-DERIVED OPTIMIZED J3 IN-PROCESS BENCHMARK ==="
);
console.log("runs =", RUNS);

for (let i = 1; i <= RUNS; i++) {

  const witnessFile =
    `build_opt/inprocess_fe_opt_${i}.wtns`;

  let t0 = performance.now();

  await wtns.calculate(
    input,
    wasm,
    witnessFile
  );

  let t1 = performance.now();

  const {
    proof,
    publicSignals
  } = await groth16.prove(
    zkey,
    witnessFile
  );

  let t2 = performance.now();

  const valid = await groth16.verify(
    vk,
    publicSignals,
    proof
  );

  let t3 = performance.now();

  if (!valid) {
    throw new Error(
      `Verification failed at run ${i}`
    );
  }

  const witnessMs = t1 - t0;
  const proveMs = t2 - t1;
  const verifyMs = t3 - t2;

  witnessTimes.push(witnessMs);
  proveTimes.push(proveMs);
  verifyTimes.push(verifyMs);

  console.log(
    `${i},` +
    `${witnessMs.toFixed(3)},` +
    `${proveMs.toFixed(3)},` +
    `${verifyMs.toFixed(3)}`
  );

  fs.unlinkSync(witnessFile);
}

const result = {
  witness_ms: stats(witnessTimes),
  prove_ms: stats(proveTimes),
  verify_ms: stats(verifyTimes)
};

console.log("\n=== SUMMARY ===");

for (const [name, s] of Object.entries(result)) {
  console.log(name);
  console.log(`  n      = ${s.n}`);
  console.log(`  mean   = ${s.mean.toFixed(3)} ms`);
  console.log(`  median = ${s.median.toFixed(3)} ms`);
  console.log(`  stdev  = ${s.stdev.toFixed(3)} ms`);
  console.log(`  min    = ${s.min.toFixed(3)} ms`);
  console.log(`  max    = ${s.max.toFixed(3)} ms`);
}

fs.writeFileSync(
  "results/groth16_inprocess_fe_opt_summary.json",
  JSON.stringify(result, null, 2)
);

console.log("J3_FE_BENCHMARK_ALL_PASS");
process.exit(0);
