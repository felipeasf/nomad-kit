// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IVerifier
 * @notice Interface for zero-knowledge proof verification in inheritance vaults.
 * @dev Designed for Semaphore-style membership proofs where heirs prove membership
 *      in a committed set without revealing their identity.
 */
interface IVerifier {
    /**
     * @notice Verifies a zero-knowledge membership proof (Semaphore-style).
     * @dev The proof demonstrates that the caller knows a secret corresponding to
     *      a member of the heir set committed in the Merkle root, without revealing
     *      which member they are.
     * @param proof Encoded proof bytes containing the zk-SNARK proof data.
     * @param root Merkle root of the heir set committed on-chain.
     * @param nullifierHash One-time nullifier to prevent double claims by the same heir.
     * @param externalNullifier Domain separator tying this proof to a specific vault/round.
     * @param signal Optional ABI-encoded signal (e.g., payout parameters hash, recipient address).
     * @return valid True if the proof is valid and the claimer is authorized.
     */
    function verifyProof(
        bytes calldata proof,
        bytes32 root,
        bytes32 nullifierHash,
        bytes32 externalNullifier,
        bytes calldata signal
    ) external view returns (bool valid);
}
