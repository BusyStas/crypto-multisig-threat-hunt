// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GuardedSafe} from "../src/GuardedSafe.sol";
import {StorageWriter} from "../src/StorageWriter.sol";

/// Signature-neutralized harness (same rationale as the symbolic/Echidna ones).
contract HarnessGuardedSafe is GuardedSafe {
    constructor(address[] memory o, uint256 t) GuardedSafe(o, t) {}

    function _checkSignatures(bytes32, bytes calldata) internal view override {}
}

/// Handler the invariant fuzzer pokes at: it only ever tries delegatecalls into
/// unapproved targets, i.e. it plays the attacker.
contract AttackerHandler is Test {
    HarnessGuardedSafe public safe;
    StorageWriter public writer;

    constructor(HarnessGuardedSafe _safe, StorageWriter _writer) {
        safe = _safe;
        writer = _writer;
    }

    function hijackViaWriter(address newOwner) public {
        bytes memory data = abi.encodeCall(StorageWriter.seizeControl, (newOwner));
        try safe.execTransaction(address(writer), 0, data, GuardedSafe.Operation.DelegateCall, "") {}
        catch {}
    }

    function arbitraryDelegate(address to, bytes memory data) public {
        try safe.execTransaction(to, 0, data, GuardedSafe.Operation.DelegateCall, "") {} catch {}
    }
}

/// @notice The Foundry-native equivalent of the Echidna run, so the property is
///         checked in this repo's default `forge test` without extra tooling.
contract GuardInvariantTest is Test {
    HarnessGuardedSafe internal safe;
    StorageWriter internal writer;
    AttackerHandler internal handler;

    address internal ownerA = address(0xA);
    address internal ownerB = address(0xB);

    function setUp() public {
        address[] memory owners = new address[](2);
        owners[0] = ownerA;
        owners[1] = ownerB;
        safe = new HarnessGuardedSafe(owners, 2);
        writer = new StorageWriter();
        handler = new AttackerHandler(safe, writer);
        targetContract(address(handler));
    }

    function invariant_ownerSetNeverHijacked() public view {
        assertEq(safe.getOwners().length, 2);
        assertEq(safe.threshold(), 2);
        assertTrue(safe.isOwner(ownerA));
        assertTrue(safe.isOwner(ownerB));
    }
}
