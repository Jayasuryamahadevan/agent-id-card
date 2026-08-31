from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent_id_card import AICError, AppendOnlyLog


class AppendOnlyLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "log.jsonl"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_entries_chain_and_verify(self) -> None:
        log = AppendOnlyLog(self.path)
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        log.append("c", {"x": 3})
        entries = log.entries()
        self.assertEqual([e["seq"] for e in entries], [0, 1, 2])
        self.assertIsNone(entries[0]["prev_digest"])
        self.assertEqual(entries[1]["prev_digest"], entries[0]["digest"])
        self.assertEqual(entries[2]["prev_digest"], entries[1]["digest"])
        log.verify()

    def test_reopening_continues_the_same_chain(self) -> None:
        AppendOnlyLog(self.path).append("a", {})
        second = AppendOnlyLog(self.path)
        entry = second.append("b", {})
        self.assertEqual(entry["seq"], 1)
        second.verify()

    def test_filtering_by_kind(self) -> None:
        log = AppendOnlyLog(self.path)
        log.append("observation", {"n": 1})
        log.append("lesson", {"n": 2})
        log.append("observation", {"n": 3})
        self.assertEqual(len(log.entries("observation")), 2)
        self.assertEqual(len(log.entries("lesson")), 1)

    def test_editing_a_previous_line_is_detected(self) -> None:
        log = AppendOnlyLog(self.path)
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        lines = self.path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["detail"]["x"] = 999  # edited without recomputing the digest
        lines[0] = json.dumps(tampered)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with self.assertRaises(AICError) as raised:
            AppendOnlyLog(self.path).verify()
        self.assertEqual(raised.exception.code, "log.tampered")

    def test_reordering_lines_breaks_the_chain(self) -> None:
        log = AppendOnlyLog(self.path)
        log.append("a", {})
        log.append("b", {})
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")

        with self.assertRaises(AICError) as raised:
            AppendOnlyLog(self.path).verify()
        self.assertIn(raised.exception.code, {"log.sequence_broken", "log.chain_broken"})


if __name__ == "__main__":
    unittest.main()
