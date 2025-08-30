// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {InheritanceVault} from "../contracts/InheritanceVault.sol";
import {MockVerifier} from "../contracts/mocks/MockVerifier.sol";
import {IVerifier} from "../contracts/interfaces/IVerifier.sol";
import {Ownable} from "../lib/solady/src/auth/Ownable.sol";

/**
 * @title InheritanceVaultTest
 * @notice Comprehensive test suite for the InheritanceVault contract
 * @dev Tests the complete lifecycle from deployment to claiming
 */
contract InheritanceVaultTest is Test {
    // Test contracts
    InheritanceVault public vault;
    MockVerifier public mockVerifier;
    
    // Test accounts
    address public owner = address(0x1);
    address public heir = address(0x2);
    address public anyone = address(0x3);
    
    // Test parameters
    bytes32 public constant HEIR_ROOT = keccak256("test_heir_root");
    uint256 public constant HEARTBEAT_INTERVAL = 1 days;
    uint256 public constant CHALLENGE_WINDOW = 7 days;
    
    // Test data for claims
    bytes public constant MOCK_PROOF = "mock_proof_data";
    bytes32 public constant NULLIFIER_HASH = keccak256("test_nullifier");
    bytes public constant SIGNAL = abi.encode("test_signal");
    uint256 public constant CLAIM_AMOUNT = 1000;

    function setUp() public {
        // Deploy mock verifier
        mockVerifier = new MockVerifier();
        
        // Deploy vault as owner
        vm.prank(owner);
        vault = new InheritanceVault(
            address(mockVerifier),
            HEIR_ROOT,
            HEARTBEAT_INTERVAL,
            CHALLENGE_WINDOW
        );
        
        // Label addresses for better trace readability
        vm.label(owner, "Owner");
        vm.label(heir, "Heir");
        vm.label(anyone, "Anyone");
        vm.label(address(vault), "InheritanceVault");
        vm.label(address(mockVerifier), "MockVerifier");
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           DEPLOYMENT TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_DeploymentState() public {
        assertEq(address(vault.verifier()), address(mockVerifier));
        assertEq(vault.heirRoot(), HEIR_ROOT);
        assertEq(vault.heartbeatInterval(), HEARTBEAT_INTERVAL);
        assertEq(vault.challengeWindow(), CHALLENGE_WINDOW);
        assertEq(vault.owner(), owner);
        assertEq(vault.challengeWindowEnd(), 0);
        
        // Check initial deadline
        uint256 expectedDeadline = block.timestamp + HEARTBEAT_INTERVAL;
        assertEq(vault.nextDeadline(), expectedDeadline);
        
        // Check initial state
        assertTrue(vault.isAlive());
        assertFalse(vault.inExpiry());
        assertFalse(vault.inChallengeWindow());
        assertFalse(vault.claimOpen());
    }

    function test_DeploymentRevertsOnZeroVerifier() public {
        vm.expectRevert(InheritanceVault.ZeroAddress.selector);
        new InheritanceVault(address(0), HEIR_ROOT, HEARTBEAT_INTERVAL, CHALLENGE_WINDOW);
    }

    function test_DeploymentRevertsOnZeroRoot() public {
        vm.expectRevert(InheritanceVault.ZeroRoot.selector);
        new InheritanceVault(address(mockVerifier), bytes32(0), HEARTBEAT_INTERVAL, CHALLENGE_WINDOW);
    }

    function test_DeploymentRevertsOnZeroInterval() public {
        vm.expectRevert(InheritanceVault.InvalidParams.selector);
        new InheritanceVault(address(mockVerifier), HEIR_ROOT, 0, CHALLENGE_WINDOW);
    }

    function test_DeploymentRevertsOnZeroChallengeWindow() public {
        vm.expectRevert(InheritanceVault.InvalidParams.selector);
        new InheritanceVault(address(mockVerifier), HEIR_ROOT, HEARTBEAT_INTERVAL, 0);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           HEARTBEAT TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_OwnerCanKeepAlive() public {
        uint256 initialDeadline = vault.nextDeadline();
        
        // Fast forward some time but stay alive
        vm.warp(block.timestamp + 12 hours);
        
        vm.prank(owner);
        vault.keepAlive();
        
        uint256 newDeadline = vault.nextDeadline();
        assertEq(newDeadline, block.timestamp + HEARTBEAT_INTERVAL);
        assertTrue(newDeadline > initialDeadline);
        assertTrue(vault.isAlive());
    }

    function test_NonOwnerCannotKeepAlive() public {
        vm.prank(anyone);
        vm.expectRevert(Ownable.Unauthorized.selector);
        vault.keepAlive();
    }

    function test_CannotKeepAliveWhenExpired() public {
        // Fast forward past deadline
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        
        vm.prank(owner);
        vm.expectRevert(InheritanceVault.NotAlive.selector);
        vault.keepAlive();
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           EXPIRY TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_AnyoneCanStartExpiryAfterDeadline() public {
        // Fast forward past deadline
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        
        vm.prank(anyone);
        vault.startExpiry();
        
        assertFalse(vault.isAlive());
        assertTrue(vault.inExpiry());
        assertTrue(vault.inChallengeWindow());
        assertFalse(vault.claimOpen());
        
        uint256 expectedWindowEnd = block.timestamp + CHALLENGE_WINDOW;
        assertEq(vault.challengeWindowEnd(), expectedWindowEnd);
    }

    function test_CannotStartExpiryWhileAlive() public {
        vm.prank(anyone);
        vm.expectRevert(InheritanceVault.StillAlive.selector);
        vault.startExpiry();
    }

    function test_CannotStartExpiryTwice() public {
        // Start expiry first time
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        
        // Try to start again
        vm.prank(anyone);
        vm.expectRevert(InheritanceVault.ExpiryNotStarted.selector);
        vault.startExpiry();
    }

    function test_OwnerCanRevokeExpiryDuringChallengeWindow() public {
        // Start expiry
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        
        // Owner revokes during challenge window
        vm.warp(block.timestamp + 1 days); // Still within 7-day window
        vm.prank(owner);
        vault.revokeExpiry();
        
        assertTrue(vault.isAlive());
        assertFalse(vault.inExpiry());
        assertFalse(vault.inChallengeWindow());
        assertFalse(vault.claimOpen());
        assertEq(vault.challengeWindowEnd(), 0);
        
        // Check that deadline was refreshed
        uint256 expectedDeadline = block.timestamp + HEARTBEAT_INTERVAL;
        assertEq(vault.nextDeadline(), expectedDeadline);
    }

    function test_CannotRevokeExpiryAfterChallengeWindow() public {
        // Start expiry
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        
        // Fast forward past challenge window
        vm.warp(block.timestamp + CHALLENGE_WINDOW + 1);
        
        vm.prank(owner);
        vm.expectRevert(InheritanceVault.ChallengeWindowOver.selector);
        vault.revokeExpiry();
    }

    function test_NonOwnerCannotRevokeExpiry() public {
        // Start expiry
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        
        vm.prank(anyone);
        vm.expectRevert(Ownable.Unauthorized.selector);
        vault.revokeExpiry();
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           CLAIMING TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_HeirCanClaimAfterChallengeWindow() public {
        // Start expiry
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        
        // Fast forward past challenge window
        vm.warp(block.timestamp + CHALLENGE_WINDOW + 1);
        
        // Heir claims
        vm.prank(heir);
        vault.claim(MOCK_PROOF, NULLIFIER_HASH, SIGNAL, heir, CLAIM_AMOUNT);
        
        // Check nullifier is now used
        assertTrue(vault.usedNullifier(NULLIFIER_HASH));
    }

    function test_CannotClaimDuringChallengeWindow() public {
        // Start expiry
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        
        // Try to claim during challenge window
        vm.warp(block.timestamp + 1 days); // Still within window
        
        vm.prank(heir);
        vm.expectRevert(InheritanceVault.ClaimNotOpen.selector);
        vault.claim(MOCK_PROOF, NULLIFIER_HASH, SIGNAL, heir, CLAIM_AMOUNT);
    }

    function test_CannotClaimBeforeExpiry() public {
        vm.prank(heir);
        vm.expectRevert(InheritanceVault.ExpiryNotStarted.selector);
        vault.claim(MOCK_PROOF, NULLIFIER_HASH, SIGNAL, heir, CLAIM_AMOUNT);
    }

    function test_CannotReuseNullifier() public {
        // Complete flow to first claim
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        vm.warp(block.timestamp + CHALLENGE_WINDOW + 1);
        
        // First claim succeeds
        vm.prank(heir);
        vault.claim(MOCK_PROOF, NULLIFIER_HASH, SIGNAL, heir, CLAIM_AMOUNT);
        
        // Second claim with same nullifier fails
        vm.prank(heir);
        vm.expectRevert(InheritanceVault.NullifierAlreadyUsed.selector);
        vault.claim(MOCK_PROOF, NULLIFIER_HASH, SIGNAL, heir, CLAIM_AMOUNT);
    }

    function test_CannotClaimToZeroAddress() public {
        // Setup for claiming
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        vm.warp(block.timestamp + CHALLENGE_WINDOW + 1);
        
        vm.prank(heir);
        vm.expectRevert(InheritanceVault.ZeroAddress.selector);
        vault.claim(MOCK_PROOF, NULLIFIER_HASH, SIGNAL, address(0), CLAIM_AMOUNT);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           OWNER FUNCTION TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_OwnerCanUpdateRoot() public {
        bytes32 newRoot = keccak256("new_heir_root");
        
        vm.prank(owner);
        vault.setRoot(newRoot);
        
        assertEq(vault.heirRoot(), newRoot);
    }

    function test_CannotUpdateRootToZero() public {
        vm.prank(owner);
        vm.expectRevert(InheritanceVault.ZeroRoot.selector);
        vault.setRoot(bytes32(0));
    }

    function test_CannotUpdateRootWhenNotAlive() public {
        // Make vault not alive
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        
        bytes32 newRoot = keccak256("new_heir_root");
        vm.prank(owner);
        vm.expectRevert(InheritanceVault.NotAlive.selector);
        vault.setRoot(newRoot);
    }

    function test_OwnerCanTransferOwnership() public {
        address newOwner = address(0x999);
        
        vm.prank(owner);
        vault.transferOwnership(newOwner);
        
        assertEq(vault.owner(), newOwner);
    }

    function test_CannotTransferOwnershipToZero() public {
        vm.prank(owner);
        vm.expectRevert(Ownable.NewOwnerIsZeroAddress.selector);
        vault.transferOwnership(address(0));
    }

    function test_OwnerCanUpdateVerifier() public {
        MockVerifier newVerifier = new MockVerifier();
        
        vm.prank(owner);
        vault.setVerifier(address(newVerifier));
        
        assertEq(address(vault.verifier()), address(newVerifier));
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           INTEGRATION TEST
    // ═══════════════════════════════════════════════════════════════════

    function test_CompleteLifecycleFlow() public {
        // Phase 1: Vault is alive, owner sends heartbeats
        assertTrue(vault.isAlive());
        
        vm.prank(owner);
        vault.keepAlive();
        assertTrue(vault.isAlive());
        
        // Phase 2: Owner misses heartbeat, expiry starts
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        assertFalse(vault.isAlive());
        
        vm.prank(anyone);
        vault.startExpiry();
        assertTrue(vault.inExpiry());
        assertTrue(vault.inChallengeWindow());
        
        // Phase 3: Challenge window passes, claiming opens
        vm.warp(block.timestamp + CHALLENGE_WINDOW + 1);
        assertFalse(vault.inChallengeWindow());
        assertTrue(vault.claimOpen());
        
        // Phase 4: Heir claims successfully
        vm.prank(heir);
        vault.claim(MOCK_PROOF, NULLIFIER_HASH, SIGNAL, heir, CLAIM_AMOUNT);
        
        assertTrue(vault.usedNullifier(NULLIFIER_HASH));
    }

    function test_OwnerCanRecoverDuringChallengeWindow() public {
        // Start expiry
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        
        // Owner recovers during challenge window
        vm.warp(block.timestamp + 1 days);
        vm.prank(owner);
        vault.revokeExpiry();
        
        // Vault is back to alive state
        assertTrue(vault.isAlive());
        assertFalse(vault.inExpiry());
        
        // Owner can continue sending heartbeats
        vm.prank(owner);
        vault.keepAlive();
        
        // Even if we fast forward past original challenge window,
        // claiming should not be available
        vm.warp(block.timestamp + CHALLENGE_WINDOW + 1);
        assertFalse(vault.claimOpen());
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           EVENT TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_HeartbeatEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit InheritanceVault.Heartbeat(block.timestamp + HEARTBEAT_INTERVAL);
        vault.keepAlive();
    }

    function test_ExpiryStartedEvent() public {
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        
        vm.prank(anyone);
        vm.expectEmit(true, true, true, true);
        emit InheritanceVault.ExpiryStarted(block.timestamp, block.timestamp + CHALLENGE_WINDOW);
        vault.startExpiry();
    }

    function test_ClaimedEvent() public {
        // Setup for claiming
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        vm.prank(anyone);
        vault.startExpiry();
        vm.warp(block.timestamp + CHALLENGE_WINDOW + 1);
        
        vm.prank(heir);
        vm.expectEmit(true, true, true, true);
        emit InheritanceVault.Claimed(NULLIFIER_HASH, heir, CLAIM_AMOUNT, SIGNAL);
        vault.claim(MOCK_PROOF, NULLIFIER_HASH, SIGNAL, heir, CLAIM_AMOUNT);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                        VIEW FUNCTION TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_ViewFunctionsInDifferentStates() public {
        // Initial state: Alive
        assertTrue(vault.isAlive());
        assertFalse(vault.inExpiry());
        assertFalse(vault.inChallengeWindow());
        assertFalse(vault.claimOpen());
        
        // After deadline passed: Dead but no expiry started
        vm.warp(block.timestamp + HEARTBEAT_INTERVAL + 1);
        assertFalse(vault.isAlive());
        assertFalse(vault.inExpiry());
        assertFalse(vault.inChallengeWindow());
        assertFalse(vault.claimOpen());
        
        // After expiry started: In challenge window
        vm.prank(anyone);
        vault.startExpiry();
        assertFalse(vault.isAlive());
        assertTrue(vault.inExpiry());
        assertTrue(vault.inChallengeWindow());
        assertFalse(vault.claimOpen());
        
        // After challenge window: Claims open
        vm.warp(block.timestamp + CHALLENGE_WINDOW + 1);
        assertFalse(vault.isAlive());
        assertTrue(vault.inExpiry());
        assertFalse(vault.inChallengeWindow());
        assertTrue(vault.claimOpen());
    }
}
