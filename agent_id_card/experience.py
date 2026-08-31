"""The experience store: where an agent's accumulated learning lives,
separate from the raw action log (`log.py`/HARNESS_BOOTSTRAP.md ss4).

The action log answers "what did I do." The experience store answers
"what did I learn" -- and specifically, what it learned about ITSELF:
a capability it discovered it actually has (or lost), a limitation it
ran into that its current ID card doesn't yet disclose. `harness.py`'s
`reconcile()` reads this store and, when it finds something the current
epoch's Tier 2 content doesn't yet reflect, mints a `capability_update`
epoch to catch the card up to reality -- so an agent's self-declared
capabilities and limitations drift towards the truth over its operating
life instead of freezing at whatever was known at bootstrap.

Same append-only, hash-chained file format as the action log (built on
the same `AppendOnlyLog`), for the same reasons: a plain, appendable,
`grep`-able text file, not a database, and every entry (including a
"lesson" someone got wrong) stays in history -- corrected by a later
entry, never edited or deleted, same rule as an `incident` attestation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .log import AppendOnlyLog

CAPABILITY_DISCOVERED = "capability_discovered"
CAPABILITY_LOST = "capability_lost"
LIMITATION_DISCOVERED = "limitation_discovered"
LIMITATION_RESOLVED = "limitation_resolved"
OBSERVATION = "observation"
LESSON = "lesson"
OUTCOME = "outcome"

WELL_KNOWN_KINDS = frozenset({
    CAPABILITY_DISCOVERED, CAPABILITY_LOST, LIMITATION_DISCOVERED, LIMITATION_RESOLVED,
    OBSERVATION, LESSON, OUTCOME,
})


class ExperienceStore:
    def __init__(self, path: Path) -> None:
        self.log = AppendOnlyLog(path)

    def record(self, kind: str, content: dict[str, Any]) -> dict[str, Any]:
        return self.log.append(kind, content)

    def entries(self, kind: str | None = None) -> list[dict[str, Any]]:
        return self.log.entries(kind)

    def verify(self) -> None:
        self.log.verify()

    def derive_capability_set(self, baseline: list[str]) -> list[str]:
        """Replay every capability_discovered/capability_lost entry, in
        order, on top of `baseline` (the genesis epoch's original
        declared_capabilities) -- always recomputed from full history,
        never from a stored cursor, so it's naturally idempotent no
        matter how many times reconcile() has already run."""
        capabilities = set(baseline)
        for entry in self.entries():
            capability = entry.get("detail", {}).get("capability")
            if not capability:
                continue
            if entry["kind"] == CAPABILITY_DISCOVERED:
                capabilities.add(capability)
            elif entry["kind"] == CAPABILITY_LOST:
                capabilities.discard(capability)
        return sorted(capabilities)

    def derive_limitation_set(self, baseline: list[str]) -> list[str]:
        limitations = set(baseline)
        for entry in self.entries():
            limitation = entry.get("detail", {}).get("limitation")
            if not limitation:
                continue
            if entry["kind"] == LIMITATION_DISCOVERED:
                limitations.add(limitation)
            elif entry["kind"] == LIMITATION_RESOLVED:
                limitations.discard(limitation)
        return sorted(limitations)
