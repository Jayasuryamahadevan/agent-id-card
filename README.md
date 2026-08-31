# Agent ID Card (AIC)

A living, self-renewing identity chain for autonomous agents -- not a
static passport photo, a lineage.

Full design writeup: see [SPEC.md](SPEC.md) (added alongside the tiered
disclosure model). This README will be filled in fully once that lands.

## Quick start

```bash
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[test,dev]"
python3 -m unittest discover -s tests -v
```
