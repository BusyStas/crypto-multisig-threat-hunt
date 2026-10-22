// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MiniSafe} from "../src/MiniSafe.sol";
import {GuardedSafe} from "../src/GuardedSafe.sol";
import {StorageWriter} from "../src/StorageWriter.sol";

/// @notice Reproduces, end to end, the class of takeover behind the Feb 2025
///         Bybit/Safe{Wallet} loss: a legitimate owner quorum signs a valid
///         transaction, but the operation is a DELEGATECALL into logic that
///         rewrites the wallet's own owner set.
///
/// Test 1 shows the unguarded wallet being seized. Test 2 shows the guarded
/// wallet refusing the exact same signed transaction. The contrast is the
/// deliverable.
contract BlindSigningTakeoverTest is Test {
    // three honest owners of a 2-of-3 wallet
    uint256 pk1 = 0xA11CE;
    uint256 pk2 = 0xB0B;
    uint256 pk3 = 0xC0FFEE;
    address own1 = vm.addr(0xA11CE);
    address own2 = vm.addr(0xB0B);
    address own3 = vm.addr(0xC0FFEE);

    address attacker = address(0xBAD);
    StorageWriter writer;

    function setUp() public {
        writer = new StorageWriter();
    }

    function _sortedOwners() internal view returns (address[] memory a) {
        // MiniSafe needs ascending signer order; build the owner array so the
        // two lowest-address keys we sign with line up.
        a = new address[](3);
        a[0] = own1;
        a[1] = own2;
        a[2] = own3;
    }

    /// Build a 2-of-3 signature blob over `txHash`, in ascending signer order.
    function _twoSigs(bytes32 txHash) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash));
        // sort the two signers we use (own1/own2 vs their addresses)
        (uint256 loPk, uint256 hiPk) = own1 < own2 ? (pk1, pk2) : (pk2, pk1);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(loPk, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(hiPk, digest);
        return abi.encodePacked(r1, s1, v1, r2, s2, v2);
    }

    // ---------------------------------------------------------------
    // 1. Unguarded wallet: the signed delegatecall seizes control.
    // ---------------------------------------------------------------
    function test_UnguardedWallet_IsSeizedBySignedDelegateCall() public {
        MiniSafe safe = new MiniSafe(_sortedOwners(), 2);

        // Sanity: before the attack, the wallet is a healthy 2-of-3.
        assertEq(safe.getOwners().length, 3);
        assertEq(safe.threshold(), 2);

        // The payload the owners are asked to approve. To a signer glancing at
        // a hash in a wallet UI this is just "another transaction".
        bytes memory data = abi.encodeCall(StorageWriter.seizeControl, (attacker));
        MiniSafe.Operation op = MiniSafe.Operation.DelegateCall;

        bytes32 txHash = safe.getTransactionHash(address(writer), 0, data, op, safe.nonce());
        bytes memory sigs = _twoSigs(txHash);

        safe.execTransaction(address(writer), 0, data, op, sigs);

        // Wallet has been rewritten in its own storage context.
        address[] memory ownersAfter = safe.getOwners();
        assertEq(ownersAfter.length, 1, "owner set collapsed");
        assertEq(ownersAfter[0], attacker, "attacker is sole owner");
        assertEq(safe.threshold(), 1, "threshold dropped to 1");
        assertTrue(safe.isOwner(attacker));
        assertFalse(safe.isOwner(own1));
    }

    // ---------------------------------------------------------------
    // 2. Guarded wallet: the identical signed transaction is refused.
    // ---------------------------------------------------------------
    function test_GuardedWallet_RejectsUnallowlistedDelegateCall() public {
        GuardedSafe safe = new GuardedSafe(_sortedOwners(), 2);

        bytes memory data = abi.encodeCall(StorageWriter.seizeControl, (attacker));
        GuardedSafe.Operation op = GuardedSafe.Operation.DelegateCall;

        bytes32 txHash = safe.getTransactionHash(address(writer), 0, data, op, safe.nonce());
        bytes memory sigs = _twoSigs(txHash);

        // Same valid quorum, same payload — but the target was never allowlisted.
        vm.expectRevert(bytes("delegatecall target not allowlisted"));
        safe.execTransaction(address(writer), 0, data, op, sigs);

        // Wallet is untouched.
        assertEq(safe.getOwners().length, 3);
        assertEq(safe.threshold(), 2);
        assertFalse(safe.isOwner(attacker));
    }
}
