import fs from "fs";
import { groth16 } from "snarkjs";

const vk = JSON.parse(
  fs.readFileSync("build/verification_key.json", "utf8")
);

const proof = JSON.parse(
  fs.readFileSync("build/proof_n1.json", "utf8")
);

const publicSignals = JSON.parse(
  fs.readFileSync("build/public_n1.json", "utf8")
);

/*
 * Public signal ordering:
 * [deviceID, nonce, enrollmentCommitment, sessionCommitment]
 */
const usedNonces = new Set();

async function protocolVerify(publicSignals, proof) {
    const deviceID = publicSignals[0];
    const nonce = publicSignals[1];

    const replayKey = `${deviceID}:${nonce}`;

    /*
     * First verify cryptographic correctness.
     */
    const cryptoValid = await groth16.verify(
        vk,
        publicSignals,
        proof
    );

    if (!cryptoValid) {
        return {
            accepted: false,
            reason: "INVALID_GROTH16_PROOF"
        };
    }

    /*
     * Then enforce protocol freshness.
     */
    if (usedNonces.has(replayKey)) {
        return {
            accepted: false,
            reason: "NONCE_ALREADY_USED"
        };
    }

    usedNonces.add(replayKey);

    return {
        accepted: true,
        reason: "VALID_FRESH_ATTESTATION"
    };
}

console.log("=== L-PoPI J3 REPLAY-GUARD TEST ===");

const cryptoOnly = await groth16.verify(
    vk,
    publicSignals,
    proof
);

console.log(
    "T1 cryptographic verification N1:",
    cryptoOnly ? "PASS" : "FAIL"
);

const first = await protocolVerify(publicSignals, proof);

console.log(
    "T2 first protocol submission:",
    first
);

const replay = await protocolVerify(publicSignals, proof);

console.log(
    "T3 exact replay:",
    replay
);

/*
 * Modify the public nonce while keeping the old proof.
 */
const wrongNonceSignals = [...publicSignals];
wrongNonceSignals[1] = "1002";

const wrongNonceCrypto = await groth16.verify(
    vk,
    wrongNonceSignals,
    proof
);

console.log(
    "T4 old proof with nonce=1002:",
    wrongNonceCrypto ? "UNEXPECTED_PASS" : "EXPECTED_FAIL"
);
