import fs from "fs";
import { buildPoseidon } from "circomlibjs";

const FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/*
 * Reproducible J3 test vector.
 *
 * This is NOT yet the real ESP32 PUF-derived HKDF key.
 * It is used only to validate the ZK pipeline.
 */
const kHex =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const deviceID = 1n;
const nonce = 1001n;

const kRaw = BigInt("0x" + kHex);
const k = kRaw % FIELD;

const poseidon = await buildPoseidon();
const F = poseidon.F;

const enrollmentCommitment =
  F.toObject(poseidon([k, deviceID]));

const sessionCommitment =
  F.toObject(poseidon([k, deviceID, nonce]));

const input = {
  k: k.toString(),
  deviceID: deviceID.toString(),
  nonce: nonce.toString(),
  enrollmentCommitment: enrollmentCommitment.toString(),
  sessionCommitment: sessionCommitment.toString()
};

fs.writeFileSync(
  "inputs/input_n1.json",
  JSON.stringify(input, null, 2)
);

console.log("=== L-PoPI J3 INPUT VECTOR ===");
console.log("k_raw                =", kRaw.toString());
console.log("k_field              =", k.toString());
console.log("deviceID             =", deviceID.toString());
console.log("nonce                =", nonce.toString());
console.log("enrollmentCommitment =", enrollmentCommitment.toString());
console.log("sessionCommitment    =", sessionCommitment.toString());
console.log("PASS: inputs/input_n1.json written");
