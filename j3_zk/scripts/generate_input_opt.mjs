import fs from "fs";
import { buildPoseidon } from "circomlibjs";

const FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

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
  F.toObject(poseidon([enrollmentCommitment, nonce]));

const input = {
  k: k.toString(),
  deviceID: deviceID.toString(),
  nonce: nonce.toString(),
  enrollmentCommitment: enrollmentCommitment.toString(),
  sessionCommitment: sessionCommitment.toString()
};

fs.writeFileSync(
  "inputs/input_opt_n1.json",
  JSON.stringify(input, null, 2)
);

console.log(input);
