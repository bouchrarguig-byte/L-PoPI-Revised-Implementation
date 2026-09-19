// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../src/Groth16Verifier.sol";
import "../src/LPoPIAttestationVerifierMonotonic.sol";

contract LPoPIAttestationVerifierMonotonicTest {
    Groth16Verifier verifier;
    LPoPIAttestationVerifierMonotonic protocol;

    function setUp() public {
        verifier = new Groth16Verifier();
        protocol =
            new LPoPIAttestationVerifierMonotonic(address(verifier));
    }

    function proof()
        internal
        pure
        returns (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        )
    {
        a = [
            uint256(0x03621f54f41403665eced19f482cf5679a2f0f4e15bcf8e98c1667bf1ae621ba),
            uint256(0x0bc34b019189b79965971dbe75f22b550783d2f113a23b982476f96fa8c9baeb)
        ];

        b = [
            [
                uint256(0x0ad6b1a9c6ba99d15608d29c4419fe1ec15e3fefed073673895ee9ed3d4df182),
                uint256(0x1a7facdc566a2d5bc7db795f2e34f3f85d9bc5e5f83b0ea4f37d81466c11b420)
            ],
            [
                uint256(0x03804ef9fb381bbe8ab83b61956476212407e1708b0c593cb1ca71c35c1b4f8c),
                uint256(0x2f1f9ae55ce3d7be6ee7ef4fbf5c516b767a93314a670ff307c2f6adae6c6798)
            ]
        ];

        c = [
            uint256(0x2d649e3c735c2b43a794ed50f56d4a23dca1f1c3a8e32538a873518a05af56dd),
            uint256(0x120a08a261df29b13aa4ffaa8e1f0e3a5ec4e0b23b677d51c2e513c9d8872350)
        ];

        input = [
            uint256(1),
            uint256(1001),
            uint256(0x0d7fa25507ee1aa1e54f45dbb710aecef4019446efcabc3a59a194ea312503cb),
            uint256(0x1cad6d959a4704867e60a2b405e65f435c1238915b76ab920b4b2ee1bd966532)
        ];
    }

    function testValidFirstAttestation() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proof();

        protocol.attest(a, b, c, input);

        require(
            protocol.lastNonce(input[0]) == input[1],
            "last nonce not updated"
        );
    }

    function testExactReplayRejected() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proof();

        protocol.attest(a, b, c, input);

        (bool ok,) = address(protocol).call(
            abi.encodeCall(protocol.attest, (a, b, c, input))
        );

        require(!ok, "exact replay accepted");
    }

    function testLowerNonceRejectedBeforeVerification() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proof();

        protocol.attest(a, b, c, input);

        // This also makes the old proof cryptographically inconsistent,
        // but monotonic freshness should reject it first.
        input[1] = 1000;

        (bool ok,) = address(protocol).call(
            abi.encodeCall(protocol.attest, (a, b, c, input))
        );

        require(!ok, "lower nonce accepted");
    }

    function testHigherNonceWithOldProofRejected() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proof();

        protocol.attest(a, b, c, input);

        // Fresh according to monotonic state, but cryptographically invalid
        // because this proof was generated for nonce 1001.
        input[1] = 1002;

        (bool ok,) = address(protocol).call(
            abi.encodeCall(protocol.attest, (a, b, c, input))
        );

        require(!ok, "old proof accepted for fresh nonce");

        require(
            protocol.lastNonce(1) == 1001,
            "state changed after invalid proof"
        );
    }
}
