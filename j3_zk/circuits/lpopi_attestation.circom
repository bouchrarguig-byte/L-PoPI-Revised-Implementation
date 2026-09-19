pragma circom 2.2.3;

include "../node_modules/circomlib/circuits/poseidon.circom";

/*
 * L-PoPI J3 - Privacy-Preserving Attestation
 *
 * Private witness:
 *   k = PUF-derived reconstructed secret represented as a BN254 field element.
 *
 * Public inputs:
 *   deviceID
 *   nonce
 *   enrollmentCommitment = Poseidon(k, deviceID)
 *   sessionCommitment    = Poseidon(k, deviceID, nonce)
 *
 * Security meaning:
 *   - enrollmentCommitment binds the private witness to the enrolled device.
 *   - sessionCommitment binds the same witness to the current session context.
 *
 * IMPORTANT:
 *   The circuit binds the proof to a nonce, but nonce reuse must be rejected
 *   by the protocol/verifier state. Groth16 alone does not detect replay of
 *   the same proof with the same public inputs.
 */

template LPoPIAttestation() {
    signal input k;

    signal input deviceID;
    signal input nonce;
    signal input enrollmentCommitment;
    signal input sessionCommitment;

    component enrollHash = Poseidon(2);
    enrollHash.inputs[0] <== k;
    enrollHash.inputs[1] <== deviceID;

    enrollHash.out === enrollmentCommitment;

    component sessionHash = Poseidon(3);
    sessionHash.inputs[0] <== k;
    sessionHash.inputs[1] <== deviceID;
    sessionHash.inputs[2] <== nonce;

    sessionHash.out === sessionCommitment;
}

/*
 * k is PRIVATE.
 * The four signals listed below are PUBLIC.
 */
component main {
    public [
        deviceID,
        nonce,
        enrollmentCommitment,
        sessionCommitment
    ]
} = LPoPIAttestation();
