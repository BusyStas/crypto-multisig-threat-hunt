// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GuardedSafe} from "../../src/GuardedSafe.sol";
import {StorageWriter} from "../../src/StorageWriter.sol";

/// @notice Echidna property-fuzzing harness.
///         Run: `echidna test/echidna/EchidnaGuard.sol --contract EchidnaGuard \
///              --config echidna.yaml`
///
/// Echidna repeatedly calls the public functions below with fuzzed inputs and,
/// after each call, checks every `echidna_*` property still holds. The property
/// we assert is the security goal: no sequence of fuzzed attempts to delegatecall
/// an unapproved contract can ever change the wallet's owner set or threshold.
///
/// As in the symbolic harness, ECDSA recovery is disabled so the fuzzer spends
/// its budget on the guard logic rather than failing to forge signatures.
contract HarnessGuardedSafe is GuardedSafe {
    constructor(address[] memory o, uint256 t) GuardedSafe(o, t) {}

    function _checkSignatures(bytes32, bytes calldata) internal view override {}
}

contract EchidnaGuard {
    HarnessGuardedSafe internal safe;
    StorageWriter internal writer;
    address internal constant OWNER_A = address(0xA);
    address internal constant OWNER_B = address(0xB);

    constructor() {
        address[] memory owners = new address[](2);
        owners[0] = OWNER_A;
        owners[1] = OWNER_B;
        safe = new HarnessGuardedSafe(owners, 2);
        writer = new StorageWriter();
    }

    // --- fuzzed actions -------------------------------------------------

    /// Attempt to seize the wallet via an unapproved delegatecall target.
    function tryHijackViaWriter(address newOwner) public {
        bytes memory data = abi.encodeCall(StorageWriter.seizeControl, (newOwner));
        // swallow the expected revert so fuzzing continues
        try safe.execTransaction(address(writer), 0, data, GuardedSafe.Operation.DelegateCall, "") {}
        catch {}
    }

    /// Attempt a delegatecall to an arbitrary target with arbitrary calldata.
    function tryArbitraryDelegate(address to, bytes memory data) public {
        try safe.execTransaction(to, 0, data, GuardedSafe.Operation.DelegateCall, "") {} catch {}
    }

    // --- invariants (must always return true) ---------------------------

    function echidna_owner_count_stable() public view returns (bool) {
        return safe.getOwners().length == 2;
    }

    function echidna_threshold_stable() public view returns (bool) {
        return safe.threshold() == 2;
    }

    function echidna_original_owners_intact() public view returns (bool) {
        return safe.isOwner(OWNER_A) && safe.isOwner(OWNER_B);
    }
}
