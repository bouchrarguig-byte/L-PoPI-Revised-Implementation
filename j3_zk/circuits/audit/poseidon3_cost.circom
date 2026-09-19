pragma circom 2.2.3;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template TestPoseidon3() {
    signal input a;
    signal input b;
    signal input c;
    signal output out;

    component h = Poseidon(3);
    h.inputs[0] <== a;
    h.inputs[1] <== b;
    h.inputs[2] <== c;

    out <== h.out;
}

component main = TestPoseidon3();
