// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MiniSafe
/// @notice A deliberately minimal Safe-style multisig, written only to study a
///         well-documented risk class: an owner set that approves a payload
///         without seeing that the payload re-delegates execution.
///
/// This is a teaching harness, not production code. It keeps just enough of the
/// real Safe design to make the lesson honest:
///   - an owner set and a signature threshold,
///   - EIP-712-style transaction hashing with a per-wallet nonce,
///   - an `execTransaction` that supports both CALL and DELEGATECALL, exactly
///     like the real contract's `Enum.Operation`.
///
/// The whole point of the exercise is that nothing here is "broken" in the
/// usual sense. Every check passes. The gap is human: a quorum of owners signs
/// an operation whose *type* (delegatecall) they never meaningfully reviewed.
contract MiniSafe {
    // --- events ---------------------------------------------------------
    event ExecutionSuccess(bytes32 indexed txHash);
    event ExecutionFailure(bytes32 indexed txHash);

    // --- storage (layout mirrors the shape of a real Safe) --------------
    // slot 0 is intentionally the owner-count / threshold area in real Safe;
    // we keep an explicit mapping + array so the study code is readable.
    address[] private _owners;
    mapping(address => bool) public isOwner;
    uint256 public threshold;
    uint256 public nonce;

    enum Operation {
        Call,
        DelegateCall
    }

    constructor(address[] memory owners_, uint256 threshold_) {
        require(threshold_ > 0 && threshold_ <= owners_.length, "bad threshold");
        for (uint256 i = 0; i < owners_.length; i++) {
            address o = owners_[i];
            require(o != address(0) && !isOwner[o], "bad owner");
            isOwner[o] = true;
            _owners.push(o);
        }
        threshold = threshold_;
    }

    function getOwners() external view returns (address[] memory) {
        return _owners;
    }

    /// @notice Hash a transaction the owners are asked to sign.
    /// @dev Note that `operation` is part of the hash, so the signature *does*
    ///      commit to call-vs-delegatecall. The flaw this repo studies is not
    ///      that the type is unsigned — it's that signers approve the digest
    ///      without decoding it, so a delegatecall looks like any other hash.
    function getTransactionHash(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                to,
                value,
                keccak256(data),
                operation,
                _nonce
            )
        );
    }

    /// @notice Execute a transaction once `threshold` owners have signed it.
    /// @dev Signatures must be supplied in ascending signer-address order so
    ///      the contract can reject duplicates cheaply — same rule the real
    ///      Safe uses.
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes calldata signatures
    ) external returns (bool success) {
        bytes32 txHash = getTransactionHash(to, value, data, operation, nonce);
        _checkSignatures(txHash, signatures);

        nonce++;

        if (operation == Operation.DelegateCall) {
            // The studied code path. Execution runs in THIS wallet's storage
            // context: `to` can rewrite owners, threshold, nonce — anything.
            (success,) = to.delegatecall(data);
        } else {
            (success,) = to.call{value: value}(data);
        }

        if (success) {
            emit ExecutionSuccess(txHash);
        } else {
            emit ExecutionFailure(txHash);
        }
    }

    function _checkSignatures(bytes32 txHash, bytes calldata signatures) internal view {
        uint256 required = threshold;
        require(signatures.length >= required * 65, "too few sigs");

        address last = address(0);
        for (uint256 i = 0; i < required; i++) {
            (uint8 v, bytes32 r, bytes32 s) = _splitSignature(signatures, i);
            address signer = ecrecover(_ethSigned(txHash), v, r, s);
            require(signer > last, "unordered/dup");
            require(isOwner[signer], "not owner");
            last = signer;
        }
    }

    function _ethSigned(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function _splitSignature(bytes calldata sigs, uint256 i)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        uint256 o = i * 65;
        r = bytes32(sigs[o:o + 32]);
        s = bytes32(sigs[o + 32:o + 64]);
        v = uint8(sigs[o + 64]);
    }

    receive() external payable {}
}
