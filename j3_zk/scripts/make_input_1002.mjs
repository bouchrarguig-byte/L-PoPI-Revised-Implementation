import { buildPoseidon } from "circomlibjs";
import fs from "fs";

const poseidon = await buildPoseidon();
const F = poseidon.F;

const k =
  514631507721405306298073637848375664226723355710112857507800679889911926255n;

const deviceID = 1n;
const nonce = 1002n;

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
  "inputs/input_opt_1002.json",
  JSON.stringify(input, null, 2)
);

console.log(input);
