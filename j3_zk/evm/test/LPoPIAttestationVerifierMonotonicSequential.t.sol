// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../src/Groth16Verifier.sol";
import "../src/LPoPIAttestationVerifierMonotonic.sol";

contract LPoPIAttestationVerifierMonotonicSequentialTest {
    Groth16Verifier verifier;
    LPoPIAttestationVerifierMonotonic protocol;

    function setUp() public {
        verifier = new Groth16Verifier();
        protocol =
            new LPoPIAttestationVerifierMonotonic(address(verifier));
    }

    function proof1001()
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

    function proof1002()
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
            uint256(0x1f0f4f73e2e6611bfd8ac9ec3700321d88938b1ae0b92ef155468ce81075146e),
            uint256(0x2aa85a9277435fcd7da9e3f509caee83a7e46c26fb0996bd24a0fd3813d541d9)
        ];

        b = [
            [
                uint256(0x2bc29a4739a60f56b2d924d894de22ea703e89c2d1b8d78031cdf03771f0fcd2),
                uint256(0x2c55a1b8f1aaa4cb6895299c280897656a11878b53fa7ec8dda44138a9369034)
            ],
            [
                uint256(0x1b25abf9ec8c2df322d9402e6cc506910b602505477146e60d726ad302a7d3d2),
                uint256(0x1ca5da2597dd0e8eaeca97a1466b3560e0b898f638800d1431ba3d8050c9b69b)
            ]
        ];

        c = [
            uint256(0x089a20a2158d2814d3dcc1f651ca6819634de68408a3a77ecb9e1183bba962b7),
            uint256(0x0e38c6b4f7838082ac49b005c55218595ecd956b325a4d49d8353494ba312148)
        ];

        input = [
            uint256(1),
            uint256(1002),
            uint256(0x0d7fa25507ee1aa1e54f45dbb710aecef4019446efcabc3a59a194ea312503cb),
            uint256(0x0967cd635c278d1dd1838eb13c3a4822ed861bb05ab4bc2885cbab412edd4116)
        ];
    }

    function testTwoSequentialFreshAttestations() public {
        (
            uint[2] memory a1,
            uint[2][2] memory b1,
            uint[2] memory c1,
            uint[4] memory input1
        ) = proof1001();

        (
            uint[2] memory a2,
            uint[2][2] memory b2,
            uint[2] memory c2,
            uint[4] memory input2
        ) = proof1002();

        // First valid fresh attestation: 0 -> 1001.
        protocol.attest(a1, b1, c1, input1);

        require(
            protocol.lastNonce(1) == 1001,
            "first nonce not stored"
        );

        // Second valid fresh attestation: 1001 -> 1002.
        protocol.attest(a2, b2, c2, input2);

        require(
            protocol.lastNonce(1) == 1002,
            "second nonce not stored"
        );
    }

    function testReplay1001RejectedAfter1002() public {
        (
            uint[2] memory a1,
            uint[2][2] memory b1,
            uint[2] memory c1,
            uint[4] memory input1
        ) = proof1001();

        (
            uint[2] memory a2,
            uint[2][2] memory b2,
            uint[2] memory c2,
            uint[4] memory input2
        ) = proof1002();

        protocol.attest(a1, b1, c1, input1);
        protocol.attest(a2, b2, c2, input2);

        // nonce 1001 is now stale because lastNonce == 1002.
        (bool ok,) = address(protocol).call(
            abi.encodeCall(
                protocol.attest,
                (a1, b1, c1, input1)
            )
        );

        require(!ok, "stale nonce 1001 accepted");
        require(
            protocol.lastNonce(1) == 1002,
            "state changed after stale replay"
        );
    }
}
