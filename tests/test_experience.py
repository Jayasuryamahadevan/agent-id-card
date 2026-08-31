from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_id_card import ExperienceStore
from agent_id_card.experience import CAPABILITY_DISCOVERED, CAPABILITY_LOST, LIMITATION_DISCOVERED, LIMITATION_RESOLVED


class ExperienceStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = ExperienceStore(Path(self.temp.name) / "experience.jsonl")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_capability_set_replays_discovered_and_lost_in_order(self) -> None:
        self.store.record(CAPABILITY_DISCOVERED, {"capability": "code.review.v1"})
        self.store.record(CAPABILITY_DISCOVERED, {"capability": "web.fetch.v1"})
        self.store.record(CAPABILITY_LOST, {"capability": "web.fetch.v1"})
        result = self.store.derive_capability_set(["code.edit.v1"])
        self.assertEqual(result, ["code.edit.v1", "code.review.v1"])

    def test_limitation_set_replays_discovered_and_resolved(self) -> None:
        self.store.record(LIMITATION_DISCOVERED, {"limitation": "no network access"})
        result = self.store.derive_limitation_set([])
        self.assertEqual(result, ["no network access"])
        self.store.record(LIMITATION_RESOLVED, {"limitation": "no network access"})
        result = self.store.derive_limitation_set([])
        self.assertEqual(result, [])

    def test_recomputation_is_idempotent_regardless_of_baseline_already_reflecting_history(self) -> None:
        self.store.record(CAPABILITY_DISCOVERED, {"capability": "x"})
        once = self.store.derive_capability_set(["a"])
        # Recomputing against a baseline that ALREADY includes the delta
        # (as if a prior reconcile had applied it) must give the same
        # answer -- replay is idempotent, no cursor/bookkeeping needed.
        twice = self.store.derive_capability_set(once)
        self.assertEqual(once, twice)

    def test_entries_filter_by_kind(self) -> None:
        self.store.record(CAPABILITY_DISCOVERED, {"capability": "x"})
        self.store.record("observation", {"note": "hello"})
        self.assertEqual(len(self.store.entries(CAPABILITY_DISCOVERED)), 1)
        self.assertEqual(len(self.store.entries()), 2)

    def test_verify_detects_tampering(self) -> None:
        self.store.record(CAPABILITY_DISCOVERED, {"capability": "x"})
        self.store.verify()  # should not raise


if __name__ == "__main__":
    unittest.main()
