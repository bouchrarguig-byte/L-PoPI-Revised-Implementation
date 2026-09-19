// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Groth16Verifier.sol";

contract LPoPIAttestationVerifierYul {
    Groth16Verifier public immutable verifier;

    mapping(uint256 => mapping(uint256 => bool)) public usedNonce;

    error InvalidProof();
    error NonceAlreadyUsed();

    constructor(address verifierAddress) {
        verifier = Groth16Verifier(verifierAddress);
    }

    function attest(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[4] calldata
    ) external {
        address verifierAddress = address(verifier);

        assembly {
            // ---------------------------------------------------------
            // ABI calldata layout
            //
            // 0x000 : attest selector (4 bytes)
            // 0x004 : a[0]
            // 0x024 : a[1]
            //         b[0][0]
            //         b[0][1]
            //         b[1][0]
            //         b[1][1]
            //         c[0]
            //         c[1]
            // 0x104 : input[0] = deviceID
            // 0x124 : input[1] = nonce
            // 0x144 : input[2] = enrollmentCommitment
            // 0x164 : input[3] = sessionCommitment
            // ---------------------------------------------------------

            let deviceID := calldataload(0x104)
            let nonce := calldataload(0x124)

            // ---------------------------------------------------------
            // Storage layout for:
            //
            // mapping(uint256 => mapping(uint256 => bool)) usedNonce;
            //
            // verifier is immutable, so usedNonce occupies slot 0.
            // ---------------------------------------------------------

            mstore(0x00, deviceID)
            mstore(0x20, 0)
            let outerSlot := keccak256(0x00, 0x40)

            mstore(0x00, nonce)
            mstore(0x20, outerSlot)
            let replaySlot := keccak256(0x00, 0x40)

            // ---------------------------------------------------------
            // Reject replay BEFORE Groth16 verification.
            // NonceAlreadyUsed() selector = 0x1fb09b80
            // ---------------------------------------------------------

            if sload(replaySlot) {
                mstore(0x00, shl(224, 0x1fb09b80))
                revert(0x00, 0x04)
            }

            // ---------------------------------------------------------
            // Reconstruct verifyProof calldata.
            //
            // attest() and verifyProof() have the same argument types.
            // Therefore only the selector must be changed.
            //
            // verifyProof selector = 0x5fe8c13b
            // ---------------------------------------------------------

            let ptr := mload(0x40)
            let payloadSize := sub(calldatasize(), 4)

            mstore(ptr, shl(224, 0x5fe8c13b))

            calldatacopy(
                add(ptr, 4),
                4,
                payloadSize
            )

            // ---------------------------------------------------------
            // Call generated Groth16 verifier.
            // ---------------------------------------------------------

            let ok := staticcall(
                gas(),
                verifierAddress,
                ptr,
                add(payloadSize, 4),
                ptr,
                0x20
            )

            // InvalidProof() selector = 0x09bde339

            // The verifier call itself failed.
            if iszero(ok) {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }

            // Require a canonical 32-byte ABI bool return.
            if iszero(eq(returndatasize(), 0x20)) {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }

            // verifyProof returned false.
            if iszero(eq(mload(ptr), 1)) {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }

            // ---------------------------------------------------------
            // Consume (deviceID, nonce) only after successful proof.
            // ---------------------------------------------------------

            sstore(replaySlot, 1)
        }
    }
}
