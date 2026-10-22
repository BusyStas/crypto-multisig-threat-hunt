# The chain was fine. Everything around it wasn't.

**Threat-hunting the off-chain attack surface of a multisig wallet — from a
blind-signed delegatecall takeover to the detection tools that do and don't
catch it, with a Solana/Anchor parallel.**

Most catastrophic losses in digital assets don't come from broken cryptography
or broken consensus. They come from the *seams*: the signing UI, the operation
type nobody reviewed, the build pipeline that served the UI. The largest crypto
theft on record — the February 2025 Bybit/Safe{Wallet} incident, ~$1.5B — did
not exploit a smart-contract bug. The contract executed exactly as signed. The
signers just couldn't see what they were signing.

This repo reproduces that class of failure end to end, in a self-contained local
harness, and then turns the security tooling on it to show which tools catch it.

> ⚠️ **Scope and intent.** Everything here runs against local test contracts.
> There are no live targets, no deployment, no keys, no exfiltration — the
> "attacker" is a Foundry test asserting that a known weakness reproduces, so a
> fix and a detector can be demonstrated against it. This is defensive security
> research of a publicly documented vulnerability class.

## The vulnerability in one paragraph

A healthy 2-of-3 multisig (`src/MiniSafe.sol`, a minimal Safe-style wallet)
executes a transaction once a quorum signs its hash. The transaction's
*operation type* can be `DELEGATECALL`. When it is, the target contract runs in
the **wallet's own storage context** and can rewrite the owner set and
threshold. A quorum that approves the digest without decoding it therefore hands
the entire wallet to whoever authored the payload — every signature valid, every
check passed. `src/StorageWriter.sol` is that payload; it collapses the wallet to
a single attacker-chosen owner.

## The fix

`src/GuardedSafe.sol` keeps delegatecall (legitimate deployments need it) but
refuses to delegatecall any target an owner quorum hasn't explicitly
allowlisted, in a separate quorum-gated step. The same signed takeover
transaction now reverts. See `MITIGATIONS.md` for the full defense-in-depth
argument, including the off-chain (signing UI + CI/CD supply chain) half that
the Bybit incident actually turned on.

## What the tools caught — and what they missed

| Tool | Technique | Caught the takeover? |
|------|-----------|----------------------|
| Slither | static analysis | **No** — saw only a generic `low-level-call` |
| Echidna | property fuzzing | Yes (breaks the owner-stability invariant) |
| Halmos | symbolic execution | Yes — *proves* no unallowlisted delegatecall can succeed |
| Foundry invariant | bounded invariant fuzzing | Yes — 8,192 attacker calls, owners never hijacked |

The uncomfortable headline: the cheap, fast linter is the one that misses it.
Static analysis answers "is this line dangerous in general?", not "can a
signed-but-unreviewed delegatecall seize *this* wallet?" That needs a property
and a tool that searches or proves over states. Details and raw output:
[`detection/`](detection/README.md).

## Layout

```
src/
  MiniSafe.sol          vulnerable Safe-style multisig
  StorageWriter.sol     the delegatecall payload that seizes it
  GuardedSafe.sol       the hardened wallet (delegatecall allowlist)
test/
  BlindSigningTakeover.t.sol   reproduces the takeover; proves the guard blocks it
  GuardInvariant.t.sol         Foundry invariant: owners never hijacked
  symbolic/GuardSymbolic.t.sol Halmos symbolic proofs of the guard
  echidna/EchidnaGuard.sol     Echidna property harness
solana/
  programs/vault-multisig/     Anchor program: missing-signer authority bug + fix
  authz-model/                 toolchain-free Rust model of the check, unit-tested
detection/                     tool configs + captured output + writeup
MITIGATIONS.md                 defense-in-depth, on-chain and off-chain
```

## Running it

```bash
# EVM: build + unit tests + invariant (Foundry)
forge test -vvv

# Symbolic proofs (Halmos)
pip install halmos
halmos --function check_ --match-contract GuardSymbolicTest

# Static analysis (Slither)
pip install slither-analyzer
slither .

# Property fuzzing (Echidna) — needs the echidna binary
echidna test/echidna/EchidnaGuard.sol --contract EchidnaGuard --config echidna.yaml

# Solana authorization model (no Solana toolchain needed)
cargo test --manifest-path solana/authz-model/Cargo.toml

# Anchor program build (needs the Solana platform tools)
# anchor build
```

CI runs Foundry, Halmos, Slither, Echidna, and the Rust model on every push
(`.github/workflows/ci.yml`).

## Background reading

The incident this models is extensively, publicly documented. Good starting
points: the Safe{Wallet} / Bybit post-incident writeups (Feb–Mar 2025) and the
general literature on Safe transaction guards and delegatecall risk. This repo
adds nothing an attacker doesn't already have; it exists to make the *defense*
concrete and testable.

---

*Author: Stas ([BusyStas](https://github.com/BusyStas)). Built as a security
research study of the off-chain attack surface of digital-asset custody.*
