"""A generic append-only, hash-chained JSON Lines log.

Used for both the action log ("what did this agent do") and the
experience store ("what did this agent learn") -- see
HARNESS_BOOTSTRAP.md ss4 for the format this implements, and
harness.py/experience.py for how each is used. One file, one chain: each
entry commits to the previous one's digest via the same RFC 8785 +
SHA-256 convention used everywhere else in AIC, so the same mental model
(and the same tooling) applies to "am I looking at an unedited history"
regardless of which kind of log it is.

This is deliberately NOT a database: a plain, appendable text file is
something every language can write and every operator can `tail -f`,
`grep`, or diff without special tooling -- consistent with AIC's
language-agnostic, no-hidden-machinery design (SPEC.md ss0).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .crypto import digest_of
from .errors import AICError
from .timestamps import stamp


class AppendOnlyLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._last_digest: str | None = None
        self._next_seq = 0
        if path.exists():
            for entry in self.entries():
                self._last_digest = entry["digest"]
                self._next_seq = entry["seq"] + 1

    def append(self, kind: str, detail: dict[str, Any]) -> dict[str, Any]:
        entry = {"seq": self._next_seq, "at": stamp(), "kind": kind, "detail": detail, "prev_digest": self._last_digest}
        entry["digest"] = digest_of(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        self._last_digest = entry["digest"]
        self._next_seq += 1
        return entry

    def entries(self, kind: str | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return [row for row in rows if kind is None or row["kind"] == kind]

    @property
    def last_digest(self) -> str | None:
        return self._last_digest

    def verify(self) -> None:
        """Walk the whole chain and raise AICError at the first break --
        a wrong `seq`, a `prev_digest` that doesn't match the entry
        before it, or a `digest` that doesn't match its own recomputed
        value (i.e. this exact line was edited after being written)."""
        expected_seq = 0
        expected_prev: str | None = None
        for entry in self.entries():
            if entry["seq"] != expected_seq:
                raise AICError("log.sequence_broken", f"Expected seq {expected_seq}, found {entry['seq']}.")
            if entry["prev_digest"] != expected_prev:
                raise AICError("log.chain_broken", f"Entry seq {entry['seq']} does not chain from the previous entry.")
            recomputed = digest_of({key: value for key, value in entry.items() if key != "digest"})
            if recomputed != entry["digest"]:
                raise AICError("log.tampered", f"Entry seq {entry['seq']} was altered after being written.")
            expected_seq += 1
            expected_prev = entry["digest"]
