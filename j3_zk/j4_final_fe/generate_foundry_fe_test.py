import json
from pathlib import Path

ROOT = Path(".")
p1 = json.loads((ROOT / "build_opt/proof_fe_opt_n1.json").read_text())
u1 = json.loads((ROOT / "build_opt/public_fe_opt_n1.json").read_text())

p2 = json.loads((ROOT / "j4_final_fe/proof_fe_n1002.json").read_text())
u2 = json.loads((ROOT / "j4_final_fe/public_fe_n1002.json").read_text())

def sol_proof(name, p, u):
    # snarkjs -> Solidity verifier ordering for Fq2 B coordinates.
    # Existing snarkjs-generated Foundry tests use:
    # [pi_b[0][1], pi_b[0][0]]
    # [pi_b[1][1], pi_b[1][0]]
    return f'''
    function {name}()
        internal
        pure
        returns (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        )
    {{
        a = [
            uint256({p["pi_a"][0]}),
            uint256({p["pi_a"][1]})
        ];

        b = [
            [
                uint256({p["pi_b"][0][1]}),
                uint256({p["pi_b"][0][0]})
            ],
            [
                uint256({p["pi_b"][1][1]}),
                uint256({p["pi_b"][1][0]})
            ]
        ];

        c = [
            uint256({p["pi_c"][0]}),
            uint256({p["pi_c"][1]})
        ];

        input = [
            uint256({u[0]}),
            uint256({u[1]}),
            uint256({u[2]}),
            uint256({u[3]})
        ];
    }}
'''

src = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../src/Groth16Verifier.sol";
import "../src/LPoPIAttestationVerifierMonotonicYul.sol";

contract LPoPIAttestationVerifierFEFinalTest {
    Groth16Verifier verifier;
    LPoPIAttestationVerifierMonotonicYul protocol;

    function setUp() public {
        verifier = new Groth16Verifier();
        protocol =
            new LPoPIAttestationVerifierMonotonicYul(address(verifier));
    }
'''

src += sol_proof("proof1001FE", p1, u1)
src += sol_proof("proof1002FE", p2, u2)

src += r'''
    function testFEProof1001CryptographicallyValid() public view {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proof1001FE();

        require(
            verifier.verifyProof(a, b, c, input),
            "FE_1001_CRYPTO_REJECTED"
        );
    }

    function testFEProof1002CryptographicallyValid() public view {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proof1002FE();

        require(
            verifier.verifyProof(a, b, c, input),
            "FE_1002_CRYPTO_REJECTED"
        );
    }

    function testTwoSequentialFEAttestations() public {
        (
            uint[2] memory a1,
            uint[2][2] memory b1,
            uint[2] memory c1,
            uint[4] memory input1
        ) = proof1001FE();

        (
            uint[2] memory a2,
            uint[2][2] memory b2,
            uint[2] memory c2,
            uint[4] memory input2
        ) = proof1002FE();

        protocol.attest(a1, b1, c1, input1);

        require(
            protocol.lastNonce(1) == 1001,
            "FE_NONCE_1001_NOT_STORED"
        );

        protocol.attest(a2, b2, c2, input2);

        require(
            protocol.lastNonce(1) == 1002,
            "FE_NONCE_1002_NOT_STORED"
        );
    }

    function testFEReplay1001RejectedAfter1002() public {
        (
            uint[2] memory a1,
            uint[2][2] memory b1,
            uint[2] memory c1,
            uint[4] memory input1
        ) = proof1001FE();

        (
            uint[2] memory a2,
            uint[2][2] memory b2,
            uint[2] memory c2,
            uint[4] memory input2
        ) = proof1002FE();

        protocol.attest(a1, b1, c1, input1);
        protocol.attest(a2, b2, c2, input2);

        (bool ok,) = address(protocol).call(
            abi.encodeCall(
                protocol.attest,
                (a1, b1, c1, input1)
            )
        );

        require(!ok, "FE_STALE_REPLAY_ACCEPTED");
        require(
            protocol.lastNonce(1) == 1002,
            "FE_STATE_CHANGED_AFTER_REPLAY"
        );
    }

    function testOldFEProofWithHigherNonceRejected() public {
        (
            uint[2] memory a1,
            uint[2][2] memory b1,
            uint[2] memory c1,
            uint[4] memory input1
        ) = proof1001FE();

        // Change public nonce without generating a corresponding proof.
        input1[1] = 1002;

        (bool ok,) = address(protocol).call(
            abi.encodeCall(
                protocol.attest,
                (a1, b1, c1, input1)
            )
        );

        require(!ok, "OLD_FE_PROOF_ACCEPTED_WITH_NONCE_1002");
        require(
            protocol.lastNonce(1) == 0,
            "STATE_CHANGED_AFTER_INVALID_FE_PROOF"
        );
    }
}
'''

out = ROOT / "evm/test/LPoPIAttestationVerifierFEFinal.t.sol"
out.write_text(src)

print("WROTE", out)
print("N1001 public =", u1)
print("N1002 public =", u2)

assert u1[0] == u2[0] == "1"
assert u1[1] == "1001"
assert u2[1] == "1002"
assert u1[2] == u2[2]
assert u1[3] != u2[3]

print("J4_FE_FOUNDRY_GENERATOR_PASS")
