# Agent ID Card (AIC)

A living, self-renewing identity chain for autonomous agents — not a
static passport photo, a lineage.

**The specification is [SPEC.md](SPEC.md), not this repository's code.**
An autonomous agent might run in Python, Node, Go, Rust, or something
that hasn't been invented yet, and might have no Python interpreter
available at all. AIC is defined as an exact, language-agnostic JSON
format and a set of algorithms (canonicalization, signing, chain
verification, tiered disclosure) — described completely in SPEC.md — so
that any runtime can generate and verify a conformant card without ever
touching this repository's Python. If you are an agent (or the developer
of one) bootstrapping your own identity and this format isn't already
implemented in your stack: **read SPEC.md, especially §11 (bootstrap
procedure), and implement it directly from the JSON shapes and
algorithms given there.**

## Why this exists

Most identity formats built for people (X.509 certificates, passports,
even most Verifiable-Credential deployments) assume identity is mostly
static, held by one long-lived key, blessed by one authority, and
revoked (if ever) via an external denylist someone has to remember to
check. Autonomous agents break most of those assumptions: they're
forked, upgraded, re-keyed, and retired constantly; a real chain of
trust for one usually involves several independent parties (operator,
model provider, other agents it has worked with) rather than one CA;
and "is this thing still even running" changes far faster than any
certificate's validity window. AIC is built around those differences
specifically — see SPEC.md §1 for the full set of design principles, and
§5 for the three-tier, privilege-gated disclosure model (public /
detailed / sensitive) that lets an agent honestly state "yes, I have
more detail than this, cryptographically committed, and I've disclosed
it to whoever I've decided should see it" without lying about what
exists versus what's merely withheld.

## Repository layout

- **[SPEC.md](SPEC.md)** — the normative specification. Read this first.
- **[HARNESS_BOOTSTRAP.md](HARNESS_BOOTSTRAP.md)** — addressed directly
  to an AI coding-agent harness (Claude Code, OpenCode, or similar): what
  to do the first time you're invoked in a new environment — be curious
  about your surroundings, generate your own card honestly, keep an
  append-only hash-chained log of every action, learn from experience
  and keep the card honest over time, know your own limitations, then
  wait for instructions.
- **[NO_PYTHON.md](NO_PYTHON.md)** — tested, copy-paste recipes (OpenSSL
  CLI, Node's built-in `crypto`, libsodium) plus the exact manual
  canonicalization rules, for a system with an AI on it but no Python
  interpreter at all — a pure-C++ ROS 2 node, firmware, a minimal
  container.
- `agent_id_card/` — a Python reference implementation:
  - `epoch.py`/`tiers.py` — the identity chain and its three disclosure
    tiers; `renewal.py`/`attestation.py`/`delegate.py`/`bundle.py`/
    `verify.py` — liveness, web-of-trust claims, scoped sub-identities,
    and verification.
  - `log.py` — a generic append-only, hash-chained JSON Lines log.
  - `experience.py` — what an agent has learned about itself over time
    (discovered/lost capabilities, discovered/resolved limitations).
  - `harness.py` — `AgentHarness`: wraps any AI backend (via a
    one-method `AgentAdapter.capabilities()` protocol) and ties identity,
    the action log, and experience-driven reconciliation into one
    runtime, so an ID card keeps matching reality instead of freezing at
    whatever was true at bootstrap.
  - `provenance.py` — honest runtime introspection (OS, hardware,
    accelerator/driver, installed language runtimes and tool/library
    versions) for Tier 3 content.
  - `cli.py` (the `aic` command) — a thin wrapper over all of the above.
  Convenient, tested, and NOT the source of truth — see SPEC.md §0/§13.
- `scripts/bootstrap_identity.py` — a runnable reference implementation
  of HARNESS_BOOTSTRAP.md's discovery + identity-generation steps.
- `tests/` — the reference implementation's test suite.

## Quick start (Python reference implementation)

Requires Python 3.11 or newer, Git, and `uv`. The commands below use a
POSIX shell and install the test and development extras from this checkout.

```bash
git clone https://github.com/Jayasuryamahadevan/agent-id-card.git
cd agent-id-card
uv venv --python 3.11 .venv && source .venv/bin/activate
uv pip install -e ".[test,dev]"
ruff check agent_id_card tests
python3 -m unittest discover -s tests -v
```

```bash
aic init --state-dir .aic --name my-agent --purpose "does X, reports Y" \
  --capabilities "observe.status.v1" --limitations "no persistent memory"
aic log --state-dir .aic tool.invoked --detail '{"tool":"bash"}'
aic experience record --state-dir .aic capability_discovered --content '{"capability":"observe.logs.v1"}'
aic reconcile --state-dir .aic --apply   # mints a capability_update epoch if anything changed
aic bundle --state-dir .aic --out bundle.json
aic verify --bundle bundle.json
```

Or drive it as a library (e.g. to wrap a real AI backend via
`AgentAdapter`):

```python
from agent_id_card import AgentHarness

harness = AgentHarness(state_dir=".aic", adapter=my_adapter)
if not harness.is_bootstrapped:
    harness.bootstrap("my-agent", "does X, reports Y", my_adapter.capabilities())
harness.ensure_live()
report = harness.reconcile(auto_apply=True)  # diffs my_adapter.capabilities() against the card
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Ecosystem link

[![RustChain bounty participant](https://img.shields.io/badge/RustChain-bounty%20participant-orange)](https://rustchain.org)

This badge is included for participation in the RustChain ecosystem bounty program; it does not imply that Agent ID Card depends on RustChain.
