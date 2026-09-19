import fs from "fs";
import { buildPoseidon } from "circomlibjs";

/*
 * L-PoPI J3 cross-layer integration.
 *
 * k is NOT a synthetic benchmark key.
 * It is the BN254 Fr scalar produced by the frozen
 * lpofi-fe-key-to-bn254-fr-v1 derivation from the
 * experimentally reproduced BCH-C/HKDF FE key.
 */

const FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const k =
  20381541263182433181125994181280330857900782190627183313278923050233798187682n;

const deviceID = 1n;
const nonce = 1001n;

if (k <= 0n || k >= FIELD) {
  throw new Error("FE-derived scalar is outside BN254 Fr");
}

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

fs.mkdirSync("inputs", { recursive: true });

fs.writeFileSync(
  "inputs/input_fe_opt_n1.json",
  JSON.stringify(input, null, 2) + "\n"
);

console.log("scheme=lpofi-fe-key-to-bn254-fr-v1");
console.log("scalar_in_field=PASS");
console.log("deviceID=" + deviceID);
console.log("nonce=" + nonce);
console.log(
  "enrollmentCommitment=" + enrollmentCommitment
);
console.log(
  "sessionCommitment=" + sessionCommitment
);
console.log("J3_FE_INPUT_GENERATION_PASS");
