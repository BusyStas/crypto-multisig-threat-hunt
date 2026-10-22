# Mitigations: closing the blind-signing seam

The exploit in this repo needs two things to line up: a signer quorum that
approves a digest without decoding it, and an operation type (`DELEGATECALL`)
that can rewrite the wallet from the inside. Defense works at both ends.

## 1. Don't let signers approve what they can't see

This is where the real incidents are won or lost. The contract did exactly what
it was told; the humans didn't know what they were telling it.

- **Clear signing / calldata decoding at the device.** The signing surface must
  decode and display the actual operation — target, value, *and operation type*
  — not a hash. A hardware wallet showing a raw `0x…` digest is not review.
- **Independent transaction simulation.** Simulate the proposed transaction
  (e.g. Tenderly, a local fork) and show the resulting state diff to each signer
  before they sign. A simulation of this exploit shows `owners` and `threshold`
  changing — impossible to miss, where a hash hides it.
- **Out-of-band verification of the target.** For any delegatecall, the target
  address should be checked against a known-good list through a second channel,
  not trusted because it is "in the transaction."

## 2. Constrain the dangerous operation on-chain

Signer diligence is necessary but not sufficient; the contract should refuse the
dangerous shape by default. `GuardedSafe` in this repo does the minimal version:

- **Allowlist delegatecall targets.** Delegatecall only into contracts an owner
  quorum has explicitly approved, ideally behind a timelock so a sudden new
  target is visible before it is usable. This repo proves (Halmos) that an
  unallowlisted target can never be reached.
- **Guard / module checks.** The real Safe supports a transaction `Guard`;
  use it to enforce the allowlist and to reject unexpected `operation` values.
- **Prefer purpose-built libraries over arbitrary delegatecall.** If the only
  legitimate delegatecall is a known helper (e.g. MultiSend), pin it.

## 3. Harden the supply chain that builds the signing UI

The Feb 2025 Bybit/Safe{Wallet} loss began off-chain: attacker-modified
JavaScript served to signers. On-chain guards do not help if the thing computing
"what you're signing" is compromised.

- Reproducible, pinned front-end builds; Subresource Integrity on served assets.
- Isolated, least-privilege CI/CD; signed commits and artifacts; no long-lived
  cloud credentials on build runners.
- Monitor and alert on any owner/threshold change and any new delegatecall
  target, so a successful attack is caught in minutes, not on withdrawal.

## 4. The Solana parallel

Solana has no delegatecall, but the same root cause — *a privileged state change
that doesn't verify who authorized it* — appears as the missing-`Signer` /
missing-`has_one` account-validation bug modeled in `solana/`. The mitigation is
symmetric: constrain the instruction's accounts so only the recorded authority,
having signed, can mutate privileged state.
