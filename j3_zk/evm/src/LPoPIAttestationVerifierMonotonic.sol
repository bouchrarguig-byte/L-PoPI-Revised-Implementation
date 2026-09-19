// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Groth16Verifier.sol";

contract LPoPIAttestationVerifierMonotonic {
    Groth16Verifier public immutable verifier;

    // Highest successfully consumed nonce for each device.
    mapping(uint256 => uint256) public lastNonce;

    error InvalidProof();
    error StaleNonce();

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

        // Reject replay and out-of-order/stale attestations before Groth16.
        if (nonce <= lastNonce[deviceID]) {
            revert StaleNonce();
        }

        if (!verifier.verifyProof(a, b, c, input)) {
            revert InvalidProof();
        }

        // State is changed only after successful proof verification.
        lastNonce[deviceID] = nonce;
    }
}
