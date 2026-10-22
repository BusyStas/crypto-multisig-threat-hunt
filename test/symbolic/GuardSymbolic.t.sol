// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GuardedSafe} from "../../src/GuardedSafe.sol";

/// @dev Harness that neutralizes signature recovery so the SMT solver can focus
///      on the one property we want a *proof* of, not a fuzzing sample: that the
///      delegatecall allowlist gate holds for every possible target and payload.
///      ECDSA recovery is assumed valid here on purpose — it is verified by the
///      concrete Foundry tests, not by symbolic execution (solvers can't invert
///      keccak/ecrecover).
contract HarnessGuardedSafe is GuardedSafe {
    constructor(address[] memory o, uint256 t) GuardedSafe(o, t) {}

    function _checkSignatures(bytes32, bytes calldata) internal view override {
        // signatures assumed valid for this proof
    }
}

/// @notice Symbolic proof, discharged by Halmos:
///         `halmos --function check_ --match-contract GuardSymbolicTest`
contract GuardSymbolicTest is Test {
    HarnessGuardedSafe internal safe;
    address internal ownerA = address(0xA);
    address internal ownerB = address(0xB);

    function setUp() public {
        address[] memory owners = new address[](2);
        owners[0] = ownerA;
        owners[1] = ownerB;
        safe = new HarnessGuardedSafe(owners, 2);
    }

    /// For ALL targets `to` and ALL calldata `data`: if `to` is not on the
    /// delegatecall allowlist, an attempted delegatecall execution must fail.
    /// There is no payload, however crafted, that slips a delegatecall past the
    /// guard into an unapproved contract.
    function check_noUnallowlistedDelegatecallEverSucceeds(address to, bytes memory data) public {
        // the property's premise: target was never approved
        vm.assume(!safe.allowedDelegateTarget(to));

        (bool ok,) = address(safe).call(
            abi.encodeCall(
                GuardedSafe.execTransaction,
                (to, 0, data, GuardedSafe.Operation.DelegateCall, "")
            )
        );

        // must always revert -> ok == false on every symbolic path
        assert(!ok);
    }

    /// Dual property: a plain CALL is never subjected to the allowlist, so the
    /// guard does not break ordinary wallet operation. (A call to `to` may still
    /// revert for unrelated reasons, so we only assert the guard itself does not
    /// add a revert: a call to an EOA-like target with empty data succeeds.)
    function check_plainCallNotBlockedByAllowlist(address to) public {
        vm.assume(to != address(safe));
        vm.assume(to.code.length == 0); // behaves like an EOA: empty call returns ok
        vm.assume(!safe.allowedDelegateTarget(to));

        (bool ok,) = address(safe).call(
            abi.encodeCall(
                GuardedSafe.execTransaction,
                (to, 0, "", GuardedSafe.Operation.Call, "")
            )
        );
        assert(ok);
    }
}
