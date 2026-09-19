// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Groth16Verifier.sol";

contract LPoPIAttestationVerifierFlat {
    Groth16Verifier public immutable verifier;

    mapping(bytes32 => bool) public usedAttestation;

    error InvalidProof();
    error NonceAlreadyUsed();

    constructor(address verifierAddress) {
        verifier = Groth16Verifier(verifierAddress);
    }

    function replayKey(
        uint256 deviceID,
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(deviceID, nonce));
    }

    function attest(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[4] calldata input
    ) external {
        bytes32 key =
            keccak256(abi.encodePacked(input[0], input[1]));

        if (usedAttestation[key]) {
            revert NonceAlreadyUsed();
        }

        if (!verifier.verifyProof(a, b, c, input)) {
            revert InvalidProof();
        }

        usedAttestation[key] = true;
    }
}
