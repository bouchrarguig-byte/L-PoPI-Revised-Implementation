// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    Groth16Verifier as Groth16Verifier3Pub
} from "./Groth16Verifier3Pub.sol";

contract LPoPIAttestationVerifier3PubMonotonicYul {
    Groth16Verifier3Pub public immutable verifier;

    mapping(uint256 => uint256) public lastNonce;

    error InvalidProof();
    error StaleNonce();

    constructor(address verifierAddress) {
        verifier = Groth16Verifier3Pub(verifierAddress);
    }

    function attest(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[3] calldata
    ) external {
        address verifierAddress = address(verifier);

        assembly {
            /*
             * ABI calldata layout
             *
             * 0x000 : 4-byte attest selector
             *
             * A:
             * 0x004
             * 0x024
             *
             * B:
             * 0x044
             * 0x064
             * 0x084
             * 0x0a4
             *
             * C:
             * 0x0c4
             * 0x0e4
             *
             * publicSignals[0] deviceID:
             * 0x104
             *
             * publicSignals[1] nonce:
             * 0x124
             *
             * publicSignals[2] enrollmentCommitment:
             * 0x144
             */

            let deviceID := calldataload(0x104)
            let nonce := calldataload(0x124)

            /*
             * mapping(uint256 => uint256) lastNonce
             * is storage slot 0 because verifier is immutable.
             */
            mstore(0x00, deviceID)
            mstore(0x20, 0)
            let nonceSlot := keccak256(0x00, 0x40)

            let previous := sload(nonceSlot)

            /*
             * Freshness rule:
             * nonce must be strictly greater than the last accepted nonce.
             *
             * StaleNonce() selector = 0xd8d01cf0
             */
            if iszero(gt(nonce, previous)) {
                mstore(0x00, shl(224, 0xd8d01cf0))
                revert(0x00, 0x04)
            }

            /*
             * attest(...) and verifyProof(...) have exactly the
             * same static ABI payload layout apart from the selector.
             *
             * 3-public-input verifier selector:
             * 0x11479fea
             */
            let ptr := mload(0x40)
            let payloadSize := sub(calldatasize(), 4)

            mstore(ptr, shl(224, 0x11479fea))

            calldatacopy(
                add(ptr, 4),
                4,
                payloadSize
            )

            let ok := staticcall(
                gas(),
                verifierAddress,
                ptr,
                add(payloadSize, 4),
                ptr,
                0x20
            )

            /*
             * InvalidProof() selector = 0x09bde339
             */
            if iszero(ok) {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }

            if iszero(eq(returndatasize(), 0x20)) {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }

            if iszero(eq(mload(ptr), 1)) {
                mstore(0x00, shl(224, 0x09bde339))
                revert(0x00, 0x04)
            }

            /*
             * Commit state only after successful Groth16 verification.
             */
            sstore(nonceSlot, nonce)
        }
    }
}
