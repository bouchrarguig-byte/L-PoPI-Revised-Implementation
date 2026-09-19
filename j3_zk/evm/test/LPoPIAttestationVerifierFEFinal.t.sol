// SPDX-License-Identifier: MIT
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

    function proof1001FE()
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
            uint256(18174056268911402717468774956364212395026643871265902426868756149865735247757),
            uint256(16101021747271504840917591043072952082029525387501931447351236081465387668347)
        ];

        b = [
            [
                uint256(17825651573775802208129243434906486763659890360092542023284645500410659849756),
                uint256(6933453357964759151370635366644568219488492003496710396013326599084651780789)
            ],
            [
                uint256(2103591034593084228318630856197507643822573233531173218004688474902035568291),
                uint256(510879326429079712225310967930672932157437444709767495605344612254786624202)
            ]
        ];

        c = [
            uint256(988782567817137168213355004130266873909932285304610927921225374698862394823),
            uint256(7720090299069782608423607009175148477695688488258519507691460304198971359157)
        ];

        input = [
            uint256(1),
            uint256(1001),
            uint256(3556187519990975477694098663944908210784843514906402506971834286230000518876),
            uint256(19637292634983147031919114895912131671132176766619494907119855905623744388979)
        ];
    }

    function proof1002FE()
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
            uint256(16091861682177106463209407611836615729810720094459282537384960353977440792610),
            uint256(17111918269382132499881566176547604502955248283334807695889600460723538738999)
        ];

        b = [
            [
                uint256(11481071571421519834092448837264586273715720086956205194615933794917484897617),
                uint256(304616996671728477028472311404917396529669694046818377330148136174652819770)
            ],
            [
                uint256(6128036262976887115114651301637124500473207138633949191205653090526740951706),
                uint256(1803906413535955676257826979285246598993181232408462696732924139871654207631)
            ]
        ];

        c = [
            uint256(4353940454959439608527366729825223876952360724126004154360756606394531445166),
            uint256(9168323671705249294585039093903923334321572295764633350662941545801481946651)
        ];

        input = [
            uint256(1),
            uint256(1002),
            uint256(3556187519990975477694098663944908210784843514906402506971834286230000518876),
            uint256(11785379966518379873694348689416864817905303457153850139339726046898273881121)
        ];
    }

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
