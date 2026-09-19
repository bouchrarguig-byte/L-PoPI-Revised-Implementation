// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../src/Groth16Verifier.sol";
import "../src/LPoPIAttestationVerifier.sol";

contract LPoPIAttestationVerifierTest {
    Groth16Verifier verifier;
    LPoPIAttestationVerifier protocol;

    function setUp() public {
        verifier = new Groth16Verifier();
        protocol = new LPoPIAttestationVerifier(address(verifier));
    }

    function proofData()
        internal
        pure
        returns (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        )
    {
        a[0] =
            0x03621f54f41403665eced19f482cf5679a2f0f4e15bcf8e98c1667bf1ae621ba;
        a[1] =
            0x0bc34b019189b79965971dbe75f22b550783d2f113a23b982476f96fa8c9baeb;

        b[0][0] =
            0x0ad6b1a9c6ba99d15608d29c4419fe1ec15e3fefed073673895ee9ed3d4df182;
        b[0][1] =
            0x1a7facdc566a2d5bc7db795f2e34f3f85d9bc5e5f83b0ea4f37d81466c11b420;

        b[1][0] =
            0x03804ef9fb381bbe8ab83b61956476212407e1708b0c593cb1ca71c35c1b4f8c;
        b[1][1] =
            0x2f1f9ae55ce3d7be6ee7ef4fbf5c516b767a93314a670ff307c2f6adae6c6798;

        c[0] =
            0x2d649e3c735c2b43a794ed50f56d4a23dca1f1c3a8e32538a873518a05af56dd;
        c[1] =
            0x120a08a261df29b13aa4ffaa8e1f0e3a5ec4e0b23b677d51c2e513c9d8872350;

        input[0] = 1;
        input[1] = 1001;

        input[2] =
            0x0d7fa25507ee1aa1e54f45dbb710aecef4019446efcabc3a59a194ea312503cb;

        input[3] =
            0x1cad6d959a4704867e60a2b405e65f435c1238915b76ab920b4b2ee1bd966532;
    }

    function testValidFirstAttestation() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proofData();

        protocol.attest(a, b, c, input);

        require(
            protocol.usedNonce(input[0], input[1]),
            "nonce not marked used"
        );
    }

    function testExactReplayRejected() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proofData();

        protocol.attest(a, b, c, input);

        (bool ok, bytes memory data) =
            address(protocol).call(
                abi.encodeWithSelector(
                    protocol.attest.selector,
                    a,
                    b,
                    c,
                    input
                )
            );

        require(!ok, "replay unexpectedly accepted");
        require(data.length >= 4, "missing revert selector");
    }

    function testModifiedNonceRejected() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proofData();

        input[1] = 1002;

        (bool ok,) =
            address(protocol).call(
                abi.encodeWithSelector(
                    protocol.attest.selector,
                    a,
                    b,
                    c,
                    input
                )
            );

        require(!ok, "modified nonce unexpectedly accepted");
    }

    function testModifiedDeviceIDRejected() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proofData();

        input[0] = 2;

        (bool ok,) =
            address(protocol).call(
                abi.encodeWithSelector(
                    protocol.attest.selector,
                    a,
                    b,
                    c,
                    input
                )
            );

        require(!ok, "modified deviceID unexpectedly accepted");
    }

    function testModifiedSessionCommitmentRejected() public {
        (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[4] memory input
        ) = proofData();

        input[3] ^= 1;

        (bool ok,) =
            address(protocol).call(
                abi.encodeWithSelector(
                    protocol.attest.selector,
                    a,
                    b,
                    c,
                    input
                )
            );

        require(!ok, "modified session commitment unexpectedly accepted");
    }
}
