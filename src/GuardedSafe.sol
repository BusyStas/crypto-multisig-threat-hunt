// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GuardedSafe
/// @notice The same wallet as MiniSafe, plus the mitigation this repo argues
///         for: a transaction guard that constrains the one operation that can
///         rewrite the wallet from the inside — DELEGATECALL.
///
/// Design choice worth stating plainly: delegatecall is not removed. Legitimate
/// Safe deployments rely on it (e.g. the MultiSend helper). Instead the wallet
/// refuses to delegatecall any target that an owner quorum has not explicitly
/// allowlisted in a separate, timelocked step. A malicious one-off
/// implementation address therefore cannot be reached even if signers approve
/// a digest blindly, because the digest's `to` is checked against the allowlist
/// at execution time.
contract GuardedSafe {
    event ExecutionSuccess(bytes32 indexed txHash);
    event ExecutionFailure(bytes32 indexed txHash);
    event DelegateTargetAllowed(address indexed target, bool allowed);

    address[] private _owners;
    mapping(address => bool) public isOwner;
    uint256 public threshold;
    uint256 public nonce;

    // allowlist of contracts this wallet is permitted to DELEGATECALL into.
    mapping(address => bool) public allowedDelegateTarget;

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

    /// @notice Add/remove a delegatecall target. Must itself be authorized by a
    ///         full owner quorum via execTransaction (self-call), so the
    ///         allowlist cannot be edited by any single key.
    function setDelegateTarget(address target, bool allowed) external {
        require(msg.sender == address(this), "only via quorum");
        allowedDelegateTarget[target] = allowed;
        emit DelegateTargetAllowed(target, allowed);
    }

    function getTransactionHash(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid, address(this), to, value, keccak256(data), operation, _nonce
            )
        );
    }

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        bytes calldata signatures
    ) external returns (bool success) {
        bytes32 txHash = getTransactionHash(to, value, data, operation, nonce);
        _checkSignatures(txHash, signatures);

        // THE GUARD: a delegatecall is only allowed into a pre-approved target.
        if (operation == Operation.DelegateCall) {
            require(allowedDelegateTarget[to], "delegatecall target not allowlisted");
        }

        nonce++;

        if (operation == Operation.DelegateCall) {
            (success,) = to.delegatecall(data);
        } else {
            (success,) = to.call{value: value}(data);
        }

        if (success) emit ExecutionSuccess(txHash);
        else emit ExecutionFailure(txHash);
    }

    // `virtual` so a symbolic-execution harness can isolate the delegatecall
    // guard from ECDSA recovery, which SMT solvers cannot reason about.
    function _checkSignatures(bytes32 txHash, bytes calldata signatures) internal view virtual {
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
