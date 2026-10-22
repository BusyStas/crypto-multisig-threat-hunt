# Detection: what each tool caught, and what it missed

The point of running three very different tools against the same code is that
they fail and succeed in different places. For a blind-signing / delegatecall
takeover, the result is uncomfortable: the cheap, fast linter is the one that
does *not* catch it.

| Tool | Technique | Caught the takeover? | What it actually reported |
|------|-----------|----------------------|---------------------------|
| **Slither** | Static analysis | **No** (not as a takeover) | Flagged the `delegatecall` only as a generic `low-level-call`, plus `reentrancy-events`. It cannot know that the delegatecall target can rewrite owner storage — that depends on who controls `to` and the storage layout, which is a design fact, not a code smell. |
| **Echidna** | Property fuzzing | **Yes** (on the unguarded harness) | Given a property "owner set never changes," the fuzzer drives `execTransaction` into the writer and breaks the invariant. On `GuardedSafe` the property holds. |
| **Halmos** | Symbolic execution | **Yes, as a proof** | Proves for *all* targets and *all* calldata that an unallowlisted delegatecall cannot succeed on `GuardedSafe`. Not a sample — a proof over the whole input space (modulo the assumed signature check). |
| **Foundry invariant** | Bounded invariant fuzzing | **Yes** | The in-repo equivalent of the Echidna run: 256 runs × 8192 calls of an attacker handler, owner set never hijacked. |

## The lesson

Static analysis answers "is this line dangerous in general?" It is not built to
answer "can a signed-but-unreviewed delegatecall seize this specific wallet?"
That question needs a *property* ("owners don't change out from under us") and a
tool that searches or proves over states — fuzzing or symbolic execution.

A review that stops at a clean Slither report would have shipped this.

## Reproducing

```bash
# Slither (static)
slither .

# Halmos (symbolic proof)
halmos --function check_ --match-contract GuardSymbolicTest

# Foundry invariant (runs in the default suite)
forge test --match-path 'test/GuardInvariant.t.sol'

# Echidna (property fuzzing) — requires the echidna binary
echidna test/echidna/EchidnaGuard.sol --contract EchidnaGuard --config echidna.yaml
```

Raw tool output captured in this directory: `slither-output.txt`,
`halmos-output.txt`, `invariant-output.txt`.

> Note on the captured runs: Slither, Halmos and the Foundry invariant were run
> in the authoring environment and their output is saved here. Echidna is
> distributed as a prebuilt binary that the authoring sandbox could not fetch,
> so its harness and config are provided and exercised in CI rather than
> captured here; the Foundry invariant covers the same property locally.
