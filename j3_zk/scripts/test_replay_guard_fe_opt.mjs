import fs from "fs";
import { groth16 } from "snarkjs";

const vk = JSON.parse(
  fs.readFileSync(
    "build_opt/verification_key_opt.json",
    "utf8"
  )
);

const proof = JSON.parse(
  fs.readFileSync(
    "build_opt/proof_fe_opt_n1.json",
    "utf8"
  )
);

const publicN1 = JSON.parse(
  fs.readFileSync(
    "build_opt/public_fe_opt_n1.json",
    "utf8"
  )
);

const usedNonces = new Set();

async function protocolVerify(publicSignals, proof) {

  const cryptoValid = await groth16.verify(
    vk,
    publicSignals,
    proof
  );

  if (!cryptoValid) {
    return {
      accepted: false,
      reason: "INVALID_PROOF"
    };
  }

  const deviceID = publicSignals[0];
  const nonce = publicSignals[1];

  const nonceKey = `${deviceID}:${nonce}`;

  if (usedNonces.has(nonceKey)) {
    return {
      accepted: false,
      reason: "NONCE_ALREADY_USED"
    };
  }

  usedNonces.add(nonceKey);

  return {
    accepted: true,
    reason: "VALID_FRESH_ATTESTATION"
  };
}

console.log(
  "=== L-PoPI FE-DERIVED OPTIMIZED REPLAY-GUARD TEST ==="
);

/* T1 — original proof */
const cryptoN1 =
  await groth16.verify(vk, publicN1, proof);

console.log(
  "T1 cryptographic verification N1:",
  cryptoN1 ? "PASS" : "FAIL"
);

/* T2 — first protocol submission */
const first =
  await protocolVerify(publicN1, proof);

console.log(
  "T2 first protocol submission:",
  first
);

/* T3 — exact replay */
const replay =
  await protocolVerify(publicN1, proof);

console.log(
  "T3 exact replay:",
  replay
);

/* T4 — transplant proof to another nonce */
const publicModified = [...publicN1];

publicModified[1] =
  (BigInt(publicModified[1]) + 1n).toString();

const modifiedValid =
  await groth16.verify(
    vk,
    publicModified,
    proof
  );

console.log(
  "T4 old proof with modified nonce:",
  modifiedValid ? "UNEXPECTED_PASS" : "EXPECTED_FAIL"
);

/* J3 cross-layer regression assertions */
if (!cryptoN1) {
  throw new Error("T1_FAIL");
}

if (
  !first.accepted ||
  first.reason !== "VALID_FRESH_ATTESTATION"
) {
  throw new Error("T2_FAIL");
}

if (
  replay.accepted ||
  replay.reason !== "NONCE_ALREADY_USED"
) {
  throw new Error("T3_FAIL");
}

if (modifiedValid) {
  throw new Error("T4_FAIL");
}

console.log("J3_FE_REPLAY_GUARD_ALL_PASS");

/*
 * snarkjs may leave worker resources alive after verification.
 * All awaited cryptographic/protocol assertions above have completed.
 */
process.exit(0);
