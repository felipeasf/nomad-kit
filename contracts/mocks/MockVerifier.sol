// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IVerifier} from "../interfaces/IVerifier.sol";

/**
 * @title MockVerifier
 * @notice A mock verifier that unconditionally returns true for any proof.
 * @dev Useful for wiring flows and early tests without requiring actual ZK circuits.
 *      DO NOT use in production - this provides no security guarantees.
 */
contract MockVerifier is IVerifier {
    /**
     * @notice Mock verification that always returns true
     * @dev Ignores all parameters and unconditionally returns true
     * @return valid Always returns true
     */
    function verifyProof(
        bytes calldata, /* proof */
        bytes32, /* root */
        bytes32, /* nullifierHash */
        bytes32, /* externalNullifier */
        bytes calldata /* signal */
    ) external pure returns (bool valid) {
        return true;
    }
}
