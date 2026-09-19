// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./LPoPIAttestationVerifierFEFinal.t.sol";

contract LPoPIAttestationVerifierFEFinalGasTest
    is LPoPIAttestationVerifierFEFinalTest
{
    event GasResult(string label, uint256 gasUsed);

    function testGasFESequentialAndReplay() public {
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

        uint256 g0 = gasleft();
        protocol.attest(a1, b1, c1, input1);
        uint256 firstGas = g0 - gasleft();
        emit GasResult("FIRST_FE_ATTEST", firstGas);

        g0 = gasleft();
        protocol.attest(a2, b2, c2, input2);
        uint256 secondGas = g0 - gasleft();
        emit GasResult("SECOND_FE_ATTEST", secondGas);

        g0 = gasleft();
        (bool ok,) = address(protocol).call(
            abi.encodeCall(
                protocol.attest,
                (a1, b1, c1, input1)
            )
        );
        uint256 replayGas = g0 - gasleft();

        require(!ok, "FE_REPLAY_ACCEPTED");
        emit GasResult("STALE_FE_REPLAY", replayGas);

        require(protocol.lastNonce(1) == 1002, "BAD_FINAL_NONCE");
    }

    function testGasVerifierOnlyFE1001() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proof1001FE();

        uint256 g0 = gasleft();
        bool ok = verifier.verifyProof(a, b, c, input);
        uint256 used = g0 - gasleft();

        require(ok, "FE_VERIFIER_FAILED");
        emit GasResult("VERIFIER_ONLY_FE_1001", used);
    }
}
