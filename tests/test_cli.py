"""End-to-end CLI walk: init -> renew -> update-capabilities -> rotate-key
-> attest (from a second agent) -> delegate -> bundle -> verify."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent_id_card.cli import build_parser


def run(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_full_lifecycle_produces_a_verifiable_bundle(self) -> None:
        alice_dir = self.root / "alice"
        auditor_dir = self.root / "auditor"

        self.assertEqual(run(["init", "--state-dir", str(alice_dir), "--name", "alice", "--purpose", "demo", "--capabilities", "observe.,coordinate."]), 0)
        self.assertEqual(run(["renew", "--state-dir", str(alice_dir)]), 0)
        self.assertEqual(run(["update-capabilities", "--state-dir", str(alice_dir), "--capabilities", "observe.,coordinate.,reversible."]), 0)
        self.assertEqual(run(["rotate-key", "--state-dir", str(alice_dir)]), 0)

        self.assertEqual(run(["bundle", "--state-dir", str(alice_dir), "--out", str(self.root / "alice_bundle.json")]), 0)
        self.assertEqual(run(["verify", "--bundle", str(self.root / "alice_bundle.json")]), 0)

        self.assertEqual(run(["init", "--state-dir", str(auditor_dir), "--name", "auditor", "--purpose", "audits agents", "--capabilities", "observe."]), 0)
        self.assertEqual(run([
            "attest", "--state-dir", str(auditor_dir),
            "--subject-bundle", str(self.root / "alice_bundle.json"),
            "--kind", "endorsement", "--claim", json.dumps({"note": "passed audit"}),
            "--out", str(self.root / "endorsement.json"),
        ]), 0)

        self.assertEqual(run([
            "delegate", "--state-dir", str(alice_dir),
            "--scope", "observe.", "--purpose", "one-off task", "--hours", "1",
            "--out", str(self.root / "delegate.json"), "--delegate-key-out", str(self.root / "delegate_key.json"),
        ]), 0)

        self.assertEqual(run([
            "bundle", "--state-dir", str(alice_dir),
            "--attestations", str(self.root / "endorsement.json"),
            "--delegate", str(self.root / "delegate.json"),
            "--out", str(self.root / "full_bundle.json"),
        ]), 0)
        self.assertEqual(run(["verify", "--bundle", str(self.root / "full_bundle.json")]), 0)

        bundle = json.loads((self.root / "full_bundle.json").read_text())
        self.assertEqual(len(bundle["epoch_chain"]), 3)  # genesis, capability_update, key_rotation
        self.assertEqual(len(bundle["attestations"]), 1)
        self.assertIsNotNone(bundle["delegate"])


if __name__ == "__main__":
    unittest.main()
