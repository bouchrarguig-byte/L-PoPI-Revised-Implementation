pragma circom 2.2.3;

include "../node_modules/circomlib/circuits/poseidon.circom";

template LPoPIAttestation3Public() {
    // Private witness
    signal input k;

    // Public inputs
    signal input deviceID;
    signal input nonce;
    signal input enrollmentCommitment;

    // Internal derived session binding
    signal sessionCommitment;

    component enrollHash = Poseidon(2);
    enrollHash.inputs[0] <== k;
    enrollHash.inputs[1] <== deviceID;

    enrollHash.out === enrollmentCommitment;

    component sessionHash = Poseidon(2);
    sessionHash.inputs[0] <== enrollmentCommitment;
    sessionHash.inputs[1] <== nonce;

    sessionCommitment <== sessionHash.out;
}

component main {
    public [
        deviceID,
        nonce,
        enrollmentCommitment
    ]
} = LPoPIAttestation3Public();
