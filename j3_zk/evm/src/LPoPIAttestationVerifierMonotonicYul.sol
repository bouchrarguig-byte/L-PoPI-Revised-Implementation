// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Groth16Verifier.sol";

contract LPoPIAttestationVerifierMonotonicYul {
    Groth16Verifier public immutable verifier;

    mapping(uint256 => uint256) public lastNonce;

    error InvalidProof();
    error StaleNonce();

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
            // input[0] and input[1]
            let deviceID := calldataload(0x104)
            let nonce := calldataload(0x124)

            // lastNonce mapping occupies storage slot 0
            // because verifier is immutable.
            mstore(0x00, deviceID)
            mstore(0x20, 0)
            let nonceSlot := keccak256(0x00, 0x40)

            let previous := sload(nonceSlot)

            // Require nonce > lastNonce[deviceID].
            if iszero(gt(nonce, previous)) {
                mstore(0x00, shl(224, 0xd8d01cf0))
                revert(0x00, 0x04)
            }

            // attest() and verifyProof() share the same argument layout.
            let ptr := mload(0x40)
            let payloadSize := sub(calldatasize(), 4)

            // verifyProof selector = 0x5fe8c13b
            mstore(ptr, shl(224, 0x5fe8c13b))

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

            // InvalidProof() = 0x09bde339
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

            // Update only after successful Groth16 verification.
            sstore(nonceSlot, nonce)
        }
    }
}
