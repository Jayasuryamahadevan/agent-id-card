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
  append-only hash-chained log of every action, know your own
  limitations, then wait for instructions.
- `agent_id_card/` — a Python reference implementation of the base chain
  (epoch / renewal / attestation / delegate / bundle / verify), with a
  CLI (`aic`). Convenient, tested, and NOT the source of truth — see
  SPEC.md §0 and §13.
- `scripts/bootstrap_identity.py` — a runnable reference implementation
  of HARNESS_BOOTSTRAP.md's discovery + identity-generation steps.
- `tests/` — the reference implementation's test suite.

## Quick start (Python reference implementation)

```bash
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[test,dev]"
ruff check agent_id_card tests
python3 -m unittest discover -s tests -v
```

```bash
aic init --state-dir .aic --name my-agent --purpose "does X, reports Y" --capabilities "observe.,coordinate."
aic bundle --state-dir .aic --out bundle.json
aic verify --bundle bundle.json
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
