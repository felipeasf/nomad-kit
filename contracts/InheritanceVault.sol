// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IVerifier} from "./interfaces/IVerifier.sol";
import {Ownable} from "../lib/solady/src/auth/Ownable.sol";

/**
 * @title InheritanceVault
 * @notice A vault that enables heirs to claim assets after owner's inactivity using ZK proofs.
 * @dev Implements a heartbeat mechanism with expiry periods and challenge windows.
 *      Uses zero-knowledge proofs to verify heir membership without revealing identity.
 *
 * State Machine:
 * 1. Alive: Owner can send heartbeats, update settings
 * 2. Expiry Started: After missed heartbeat, challenge window opens
 * 3. Challenge Window: Owner can revoke expiry, or heirs wait for window to close
 * 4. Claimable: After challenge window, heirs can claim with valid ZK proofs
 *
 * TODO: Asset registry & payout router (ERC20/721/1155)
 * TODO: Optional bonds/slashing for startExpiry() / claim()
 * TODO: Integrate Paymaster / 4337 hooks (gasless)
 * TODO: Consider reentrancy guard once transfers are added
 * TODO: Support multiple rounds/epochs for rotating heir sets
 */
contract InheritanceVault is Ownable {
    // ═══════════════════════════════════════════════════════════════════
    //                             STORAGE
    // ═══════════════════════════════════════════════════════════════════

    /// @notice The ZK verifier contract used to validate heir proofs
    IVerifier public verifier;

    /// @notice Merkle root of the heir set (commitment to authorized heirs)
    bytes32 public heirRoot;

    /// @notice How often the owner must send heartbeats (in seconds)
    uint256 public heartbeatInterval;

    /// @notice Timestamp when the next heartbeat is due
    uint256 public nextDeadline;

    /// @notice Duration of the challenge window after expiry starts (in seconds)
    uint256 public challengeWindow;

    /// @notice End timestamp of the current challenge window (0 when not in expiry)
    uint256 public challengeWindowEnd;

    /// @notice Tracks used nullifiers to prevent double claiming
    mapping(bytes32 => bool) public usedNullifier;

    // ═══════════════════════════════════════════════════════════════════
    //                             ERRORS
    // ═══════════════════════════════════════════════════════════════════

    /// @dev Action requires vault to be alive (not in expiry)
    error NotAlive();

    /// @dev Cannot start expiry while still alive
    error StillAlive();

    /// @dev Action requires being in challenge window
    error NotInChallengeWindow();

    /// @dev Challenge window has already ended
    error ChallengeWindowOver();

    /// @dev Expiry has not been started yet
    error ExpiryNotStarted();

    /// @dev Action requires vault to still be alive
    error Expired();

    /// @dev ZK proof verification failed
    error InvalidProof();

    /// @dev This nullifier has already been used
    error NullifierAlreadyUsed();

    /// @dev Claiming is not open yet (challenge window still active)
    error ClaimNotOpen();

    /// @dev Address cannot be zero
    error ZeroAddress();

    /// @dev Root cannot be zero
    error ZeroRoot();

    /// @dev Invalid constructor parameters
    error InvalidParams();

    // ═══════════════════════════════════════════════════════════════════
    //                             EVENTS
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Emitted when expiry period starts
    event ExpiryStarted(uint256 at, uint256 challengeWindowEnd);

    /// @notice Emitted when owner revokes an active expiry
    event ExpiryRevoked(uint256 at);

    /// @notice Emitted when an heir successfully claims assets
    event Claimed(bytes32 nullifierHash, address to, uint256 amount, bytes signal);

    /// @notice Emitted when the heir root is updated
    event RootUpdated(bytes32 newRoot);

    /// @notice Emitted when owner sends a heartbeat
    event Heartbeat(uint256 nextDeadline);

    /// @notice Emitted when verifier is updated
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    // ═══════════════════════════════════════════════════════════════════
    //                            MODIFIERS
    // ═══════════════════════════════════════════════════════════════════

    /// @dev Ensures vault is currently alive (not in expiry state)
    modifier onlyAlive() {
        if (challengeWindowEnd != 0 || block.timestamp > nextDeadline) {
            revert NotAlive();
        }
        _;
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Initializes a new inheritance vault
     * @param _verifier Address of the ZK verifier contract
     * @param _heirRoot Initial Merkle root of the heir set
     * @param _heartbeatInterval How often owner must send heartbeats (seconds)
     * @param _challengeWindow Duration of challenge window after expiry (seconds)
     */
    constructor(
        address _verifier,
        bytes32 _heirRoot,
        uint256 _heartbeatInterval,
        uint256 _challengeWindow
    ) {
        if (_verifier == address(0)) revert ZeroAddress();
        if (_heirRoot == bytes32(0)) revert ZeroRoot();
        if (_heartbeatInterval == 0 || _challengeWindow == 0) revert InvalidParams();

        // Initialize Solady ownership
        _initializeOwner(msg.sender);
        
        verifier = IVerifier(_verifier);
        heirRoot = _heirRoot;
        heartbeatInterval = _heartbeatInterval;
        challengeWindow = _challengeWindow;
        nextDeadline = block.timestamp + _heartbeatInterval;

        emit RootUpdated(_heirRoot);
        emit Heartbeat(nextDeadline);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                          OWNER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Owner sends a heartbeat to prove they are still alive
     * @dev Resets the deadline and keeps the vault in alive state
     */
    function keepAlive() external onlyOwner onlyAlive {
        nextDeadline = block.timestamp + heartbeatInterval;
        emit Heartbeat(nextDeadline);
    }

    /**
     * @notice Owner revokes an active expiry during the challenge window
     * @dev Can only be called during an active challenge window
     */
    function revokeExpiry() external onlyOwner {
        if (challengeWindowEnd == 0) revert ExpiryNotStarted();
        if (block.timestamp > challengeWindowEnd) revert ChallengeWindowOver();

        challengeWindowEnd = 0;
        // Refresh heartbeat on revoke
        nextDeadline = block.timestamp + heartbeatInterval;

        emit ExpiryRevoked(block.timestamp);
        emit Heartbeat(nextDeadline);
    }

    /**
     * @notice Owner updates the heir root (commitment to authorized heirs)
     * @param newRoot New Merkle root of the heir set
     */
    function setRoot(bytes32 newRoot) external onlyOwner onlyAlive {
        if (newRoot == bytes32(0)) revert ZeroRoot();
        heirRoot = newRoot;
        emit RootUpdated(newRoot);
    }

    /**
     * @notice Update the ZK verifier contract
     * @param newVerifier Address of the new verifier contract
     */
    function setVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        address oldVerifier = address(verifier);
        verifier = IVerifier(newVerifier);
        emit VerifierUpdated(oldVerifier, newVerifier);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                          PUBLIC FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Anyone can start the expiry process after a missed heartbeat
     * @dev Can only be called after the deadline has passed and expiry hasn't started
     */
    function startExpiry() external {
        if (block.timestamp <= nextDeadline) revert StillAlive();
        if (challengeWindowEnd != 0) revert ExpiryNotStarted(); // Already started

        challengeWindowEnd = block.timestamp + challengeWindow;
        emit ExpiryStarted(block.timestamp, challengeWindowEnd);
    }

    /**
     * @notice Heirs can claim assets after the challenge window ends
     * @dev Requires a valid ZK proof demonstrating heir membership
     * @param proof ZK proof bytes
     * @param nullifierHash One-time nullifier to prevent double claiming
     * @param signal Optional signal data (e.g., payout parameters)
     * @param to Address to receive the claimed assets
     * @param amount Amount to claim (for event logging, actual logic TBD)
     */
    function claim(
        bytes calldata proof,
        bytes32 nullifierHash,
        bytes calldata signal,
        address to,
        uint256 amount
    ) external {
        // State checks
        if (challengeWindowEnd == 0) revert ExpiryNotStarted();
        if (block.timestamp <= challengeWindowEnd) revert ClaimNotOpen();
        if (usedNullifier[nullifierHash]) revert NullifierAlreadyUsed();
        if (to == address(0)) revert ZeroAddress();

        // External nullifier derivation (vault domain)
        // TODO: Make round configurable for multi-epoch support
        bytes32 externalNullifier = keccak256(abi.encodePacked(address(this), uint256(1)));

        // Verify ZK proof
        bool isValid = verifier.verifyProof(
            proof,
            heirRoot,
            nullifierHash,
            externalNullifier,
            signal
        );
        if (!isValid) revert InvalidProof();

        // Effects: mark nullifier as used
        usedNullifier[nullifierHash] = true;

        // TODO: Interactions - transfer ERC20/721/1155 based on signal or internal policy
        // This is where asset transfer logic will be implemented

        emit Claimed(nullifierHash, to, amount, signal);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Check if the vault is currently alive
     * @return True if vault is alive (not in expiry and deadline not passed)
     */
    function isAlive() public view returns (bool) {
        return challengeWindowEnd == 0 && block.timestamp <= nextDeadline;
    }

    /**
     * @notice Check if claiming is currently open for heirs
     * @return True if challenge window has ended and claiming is open
     */
    function claimOpen() public view returns (bool) {
        return challengeWindowEnd != 0 && block.timestamp > challengeWindowEnd;
    }

    /**
     * @notice Check if expiry has been started
     * @return True if expiry process has begun
     */
    function inExpiry() public view returns (bool) {
        return challengeWindowEnd != 0;
    }

    /**
     * @notice Check if currently in challenge window
     * @return True if in challenge window (owner can still revoke)
     */
    function inChallengeWindow() public view returns (bool) {
        return challengeWindowEnd != 0 && block.timestamp <= challengeWindowEnd;
    }
}
