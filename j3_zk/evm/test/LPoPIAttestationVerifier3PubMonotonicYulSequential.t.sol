// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../src/Groth16Verifier3Pub.sol";
import "../src/LPoPIAttestationVerifier3PubMonotonicYul.sol";

contract LPoPIAttestationVerifier3PubMonotonicYulSequentialTest {
    Groth16Verifier verifier;
    LPoPIAttestationVerifier3PubMonotonicYul protocol;

    function setUp() public {
        verifier = new Groth16Verifier();

        protocol =
            new LPoPIAttestationVerifier3PubMonotonicYul(
                address(verifier)
            );
    }


    function proof1001()
        internal
        pure
        returns (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[3] memory input
        )
    {
        a = [
            uint256(21818994902918840040963823416905603745797329491695012977935930540041580550902),
            uint256(18927415639980170926718573947100394043811048758774793281395460123143464527615)
        ];

        b = [
            [uint256(20928159378084806261875209899963212455379943282376127734955946985755232763175), uint256(19942520851825867500539322601311521421280701419441225595072414697601708275657)],
            [uint256(13213051646267809276563216690005028404228678224395738535163535881960518874488), uint256(12110808437624877581290369867788178632053141377408305651894220025411597377453)]
        ];

        c = [
            uint256(15379911108626314897409126501541390969913457249429332007887139378703791499926),
            uint256(17060555207082530741342097799614514358204138860360074303594584673282912118837)
        ];

        input = [
            uint256(1),
            uint256(1001),
            uint256(6105576984148100997313938535153708518444427338464231626758362898858877715403)
        ];
    }



    function proof1002()
        internal
        pure
        returns (
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[3] memory input
        )
    {
        a = [
            uint256(2735186307625265296461543186297482431829342267319724071369849212994126629453),
            uint256(3185929775011549209880372228187973478117164738673369155081802235081240976770)
        ];

        b = [
            [uint256(12710912723300078383771574912468801662650094254015636267462103672732995705855), uint256(19212485908870559385471990457983248597470392405837359834674927447146782296133)],
            [uint256(7929470349687625596083937878350421674896316467188616683609496340131345776457), uint256(17999553319531752590557399548195731619409395211396689178321099904920491526164)]
        ];

        c = [
            uint256(21827898529292303923293121604303255879350163586253497464219309959956060982396),
            uint256(1544083227783875268806187049255460294666292830819884959764100556032562978455)
        ];

        input = [
            uint256(1),
            uint256(1002),
            uint256(6105576984148100997313938535153708518444427338464231626758362898858877715403)
        ];
    }


    function testTwoSequentialFreshAttestations() public {
        (
            uint[2] memory a1,
            uint[2][2] memory b1,
            uint[2] memory c1,
            uint[3] memory input1
        ) = proof1001();

        protocol.attest(a1, b1, c1, input1);

        require(
            protocol.lastNonce(1) == 1001,
            "NONCE_1001_NOT_STORED"
        );

        (
            uint[2] memory a2,
            uint[2][2] memory b2,
            uint[2] memory c2,
            uint[3] memory input2
        ) = proof1002();

        protocol.attest(a2, b2, c2, input2);

        require(
            protocol.lastNonce(1) == 1002,
            "NONCE_1002_NOT_STORED"
        );
    }

    function testReplay1001RejectedAfter1002() public {
        (
            uint[2] memory a1,
            uint[2][2] memory b1,
            uint[2] memory c1,
            uint[3] memory input1
        ) = proof1001();

        protocol.attest(a1, b1, c1, input1);

        (
            uint[2] memory a2,
            uint[2][2] memory b2,
            uint[2] memory c2,
            uint[3] memory input2
        ) = proof1002();

        protocol.attest(a2, b2, c2, input2);

        (
            bool ok,
        ) = address(protocol).call(
            abi.encodeWithSelector(
                protocol.attest.selector,
                a1,
                b1,
                c1,
                input1
            )
        );

        require(!ok, "STALE_REPLAY_ACCEPTED");

        require(
            protocol.lastNonce(1) == 1002,
            "STATE_CHANGED_AFTER_REPLAY"
        );
    }

    function testHigherNonceWithOldProofRejected() public {
        (
            uint[2] memory a1,
            uint[2][2] memory b1,
            uint[2] memory c1,
            uint[3] memory input1
        ) = proof1001();

        // Forge a higher nonce while keeping the old proof.
        input1[1] = 1002;

        (
            bool ok,
        ) = address(protocol).call(
            abi.encodeWithSelector(
                protocol.attest.selector,
                a1,
                b1,
                c1,
                input1
            )
        );

        require(!ok, "OLD_PROOF_ACCEPTED_WITH_NEW_NONCE");
        require(
            protocol.lastNonce(1) == 0,
            "STATE_CHANGED_AFTER_INVALID_PROOF"
        );
    }
}
