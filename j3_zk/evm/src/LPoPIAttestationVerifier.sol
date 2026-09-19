// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Groth16Verifier.sol";

contract LPoPIAttestationVerifier {
    Groth16Verifier public immutable verifier;

    mapping(uint256 => mapping(uint256 => bool)) public usedNonce;

    error InvalidProof();
    error NonceAlreadyUsed();

    constructor(address verifierAddress) {
        verifier = Groth16Verifier(verifierAddress);
    }

    function attest(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[4] calldata input
    ) external {
        uint256 deviceID = input[0];
        uint256 nonce = input[1];

        if (usedNonce[deviceID][nonce]) {
            revert NonceAlreadyUsed();
        }

        if (!verifier.verifyProof(a, b, c, input)) {
            revert InvalidProof();
        }

        usedNonce[deviceID][nonce] = true;
    }
}
