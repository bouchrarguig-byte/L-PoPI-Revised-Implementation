pragma circom 2.2.3;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template TestPoseidon2() {
    signal input a;
    signal input b;
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== a;
    h.inputs[1] <== b;

    out <== h.out;
}

component main = TestPoseidon2();
