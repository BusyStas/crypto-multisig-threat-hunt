// SPDX-License-Identifier: MIT
//! vault_multisig — Anchor reference program for the Solana half of this study.
//!
//! The Ethereum half shows a *signed-but-unreviewed* operation seizing a wallet.
//! Solana has no delegatecall, but it has the same underlying failure in a
//! different dress: an instruction that mutates privileged state without
//! checking **who is allowed to submit it**. On Solana that is the canonical
//! "missing signer / missing has_one" account-validation bug, and it is the
//! single most common class in Anchor audits.
//!
//! `set_authority_insecure` and `set_authority_secure` are the same operation.
//! The only difference is account validation. That difference is the audit.
//!
//! NOTE: building this to BPF requires the Solana platform tools
//! (`anchor build`). The authorization decision both handlers hinge on is
//! extracted and unit-tested, toolchain-free, in `solana/authz-model`.

use anchor_lang::prelude::*;

declare_id!("Vau1tM5igThreatHunt1111111111111111111111111");

#[program]
pub mod vault_multisig {
    use super::*;

    /// Create the vault config, recording its controlling authority.
    pub fn initialize(ctx: Context<Initialize>, threshold: u8) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.authority = ctx.accounts.authority.key();
        cfg.threshold = threshold;
        cfg.bump = ctx.bumps.config;
        Ok(())
    }

    // ---------------------------------------------------------------
    // VULNERABLE: rotates the vault authority with no check on who signed.
    // ---------------------------------------------------------------
    //
    // `new_authority` is just an address argument. `config` is writable. There
    // is no `Signer` on the current authority and no `has_one` tying the config
    // to whoever is calling. Any account can invoke this and hand the vault to
    // itself — the on-chain equivalent of "the transaction executed exactly as
    // submitted; nobody checked the submitter."
    pub fn set_authority_insecure(ctx: Context<SetAuthorityInsecure>, new_authority: Pubkey) -> Result<()> {
        ctx.accounts.config.authority = new_authority;
        Ok(())
    }

    // ---------------------------------------------------------------
    // SECURE: the same rotation, gated by account validation.
    // ---------------------------------------------------------------
    //
    // `has_one = authority` forces `config.authority == authority.key()`, and
    // `authority: Signer` forces that key to have signed. Together they are the
    // Anchor expression of "only the current authority may rotate the authority."
    pub fn set_authority_secure(ctx: Context<SetAuthoritySecure>, new_authority: Pubkey) -> Result<()> {
        ctx.accounts.config.authority = new_authority;
        Ok(())
    }
}

#[account]
pub struct VaultConfig {
    pub authority: Pubkey,
    pub threshold: u8,
    pub bump: u8,
}

impl VaultConfig {
    pub const SIZE: usize = 8 + 32 + 1 + 1;
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = VaultConfig::SIZE,
        seeds = [b"config", authority.key().as_ref()],
        bump
    )]
    pub config: Account<'info, VaultConfig>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// The bug is entirely in this accounts struct: no Signer, no has_one.
#[derive(Accounts)]
pub struct SetAuthorityInsecure<'info> {
    #[account(mut)]
    pub config: Account<'info, VaultConfig>,
    /// CHECK: deliberately unconstrained to demonstrate the missing check.
    pub authority: UncheckedAccount<'info>,
}

// The fix is entirely in this accounts struct.
#[derive(Accounts)]
pub struct SetAuthoritySecure<'info> {
    #[account(mut, has_one = authority)]
    pub config: Account<'info, VaultConfig>,
    pub authority: Signer<'info>,
}
