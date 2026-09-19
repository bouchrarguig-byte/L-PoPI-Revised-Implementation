pragma circom 2.2.3;

include "../node_modules/circomlib/circuits/poseidon.circom";

template LPoPIAttestationOptimized() {
    signal input k;

    signal input deviceID;
    signal input nonce;
    signal input enrollmentCommitment;
    signal input sessionCommitment;

    component enrollHash = Poseidon(2);
    enrollHash.inputs[0] <== k;
    enrollHash.inputs[1] <== deviceID;

    enrollHash.out === enrollmentCommitment;

    component sessionHash = Poseidon(2);
    sessionHash.inputs[0] <== enrollmentCommitment;
    sessionHash.inputs[1] <== nonce;

    sessionHash.out === sessionCommitment;
}

component main {
    public [
        deviceID,
        nonce,
        enrollmentCommitment,
        sessionCommitment
    ]
} = LPoPIAttestationOptimized();
