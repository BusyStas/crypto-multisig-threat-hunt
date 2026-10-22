// SPDX-License-Identifier: MIT
//! A faithful, toolchain-free model of what Anchor's account constraints
//! actually enforce for the vault authority rotation. The Anchor program
//! (`../programs/vault-multisig`) expresses this with `has_one` + `Signer`;
//! here the same decision is a plain function so it can be unit-tested with
//! `cargo test`, no Solana toolchain required.
//!
//! The model is deliberately literal:
//!   - `insecure_rotate` ignores who signed — it mirrors the vulnerable handler.
//!   - `secure_rotate` enforces current-authority-signed — it mirrors the fix.

pub type Pubkey = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultConfig {
    pub authority: Pubkey,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthzError {
    /// Current authority did not sign.
    MissingSigner,
    /// Signer is not the account's recorded authority (`has_one` violation).
    AuthorityMismatch,
}

/// VULNERABLE: rotate with no check on the submitter. Always "succeeds".
/// Present only to characterize the bug under test.
pub fn insecure_rotate(cfg: &mut VaultConfig, new_authority: Pubkey) {
    cfg.authority = new_authority;
}

/// SECURE: rotate only if the current authority is among the transaction
/// signers AND matches the config's recorded authority.
///
/// `signers` models Solana's set of accounts that signed the transaction;
/// `claimed_authority` models the `authority` account passed to the
/// instruction. Both constraints must hold, matching `has_one = authority`
/// plus `authority: Signer`.
pub fn secure_rotate(
    cfg: &mut VaultConfig,
    claimed_authority: Pubkey,
    signers: &[Pubkey],
    new_authority: Pubkey,
) -> Result<(), AuthzError> {
    // Signer<'info>: the claimed authority must have signed.
    if !signers.contains(&claimed_authority) {
        return Err(AuthzError::MissingSigner);
    }
    // has_one = authority: the signer must be the recorded authority.
    if cfg.authority != claimed_authority {
        return Err(AuthzError::AuthorityMismatch);
    }
    cfg.authority = new_authority;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: Pubkey = [1u8; 32];
    const ATTACKER: Pubkey = [9u8; 32];
    const NEW: Pubkey = [2u8; 32];

    #[test]
    fn insecure_lets_anyone_seize_the_vault() {
        let mut cfg = VaultConfig { authority: OWNER };
        // Attacker rotates authority to themselves; nothing stops it.
        insecure_rotate(&mut cfg, ATTACKER);
        assert_eq!(cfg.authority, ATTACKER, "insecure path hands over the vault");
    }

    #[test]
    fn secure_rejects_attacker_who_signed_but_is_not_authority() {
        let mut cfg = VaultConfig { authority: OWNER };
        // Attacker signs their own tx, but is not the recorded authority.
        let err = secure_rotate(&mut cfg, ATTACKER, &[ATTACKER], NEW).unwrap_err();
        assert_eq!(err, AuthzError::AuthorityMismatch);
        assert_eq!(cfg.authority, OWNER, "vault untouched");
    }

    #[test]
    fn secure_rejects_authority_that_did_not_sign() {
        let mut cfg = VaultConfig { authority: OWNER };
        // Claims to be OWNER but OWNER is not in the signer set.
        let err = secure_rotate(&mut cfg, OWNER, &[ATTACKER], NEW).unwrap_err();
        assert_eq!(err, AuthzError::MissingSigner);
        assert_eq!(cfg.authority, OWNER, "vault untouched");
    }

    #[test]
    fn secure_allows_the_real_authority() {
        let mut cfg = VaultConfig { authority: OWNER };
        secure_rotate(&mut cfg, OWNER, &[OWNER], NEW).unwrap();
        assert_eq!(cfg.authority, NEW, "legitimate rotation succeeds");
    }
}
