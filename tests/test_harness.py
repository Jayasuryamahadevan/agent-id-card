from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from agent_id_card import AgentHarness, AgentIdentity, AICError, verify_bundle
from agent_id_card.delegate import verify_delegate


class _FakeAdapter:
    def __init__(self, capabilities: list[str]) -> None:
        self._capabilities = capabilities

    def capabilities(self) -> list[str]:
        return self._capabilities


class AgentHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp.name) / ".aic"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_bootstrap_produces_a_verifiable_bundle(self) -> None:
        harness = AgentHarness(self.state_dir)
        self.assertFalse(harness.is_bootstrapped)
        harness.bootstrap("test-agent", "Runs tests.", ["code.edit.v1"], known_limitations=["no persistent memory"])
        self.assertTrue(harness.is_bootstrapped)
        result = verify_bundle(harness.bundle())
        self.assertTrue(result.ok)
        self.assertEqual(harness.state.detail["known_limitations"], ["no persistent memory"])

    def test_double_bootstrap_is_rejected(self) -> None:
        harness = AgentHarness(self.state_dir)
        harness.bootstrap("test-agent", "Runs tests.", [])
        with self.assertRaises(AICError) as raised:
            harness.bootstrap("test-agent", "Runs tests.", [])
        self.assertEqual(raised.exception.code, "harness.already_bootstrapped")

    def test_reconcile_without_auto_apply_only_reports(self) -> None:
        harness = AgentHarness(self.state_dir)
        harness.bootstrap("test-agent", "Runs tests.", ["code.edit.v1"])
        harness.record_experience("capability_discovered", {"capability": "code.review.v1"})
        report = harness.reconcile(auto_apply=False)
        self.assertTrue(report["changed"])
        self.assertNotIn("new_epoch_number", report)
        self.assertEqual(harness.current_epoch["epoch_number"], 0)

    def test_reconcile_with_auto_apply_mints_a_capability_update(self) -> None:
        harness = AgentHarness(self.state_dir)
        harness.bootstrap("test-agent", "Runs tests.", ["code.edit.v1"])
        harness.record_experience("capability_discovered", {"capability": "code.review.v1"})
        report = harness.reconcile(auto_apply=True)
        self.assertTrue(report["changed"])
        self.assertEqual(report["new_epoch_number"], 1)
        self.assertEqual(harness.current_epoch["epoch_number"], 1)
        self.assertEqual(harness.state.detail["declared_capabilities"], ["code.edit.v1", "code.review.v1"])
        result = verify_bundle(harness.bundle())
        self.assertTrue(result.ok)

    def test_attached_adapter_drift_is_recorded_and_reconciled(self) -> None:
        harness = AgentHarness(self.state_dir, adapter=_FakeAdapter(["code.edit.v1", "web.fetch.v1"]))
        harness.bootstrap("test-agent", "Runs tests.", ["code.edit.v1"])
        report = harness.reconcile(auto_apply=True)
        self.assertEqual(report["capabilities"]["after"], ["code.edit.v1", "web.fetch.v1"])
        discovered = harness.experience.entries("capability_discovered")
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["detail"]["capability"], "web.fetch.v1")

    def test_no_change_does_not_mint_a_new_epoch(self) -> None:
        harness = AgentHarness(self.state_dir)
        harness.bootstrap("test-agent", "Runs tests.", ["code.edit.v1"])
        report = harness.reconcile(auto_apply=True)
        self.assertFalse(report["changed"])
        self.assertEqual(harness.current_epoch["epoch_number"], 0)

    def test_rotate_key_preserves_agent_id_and_re_signs_tiers_forward(self) -> None:
        harness = AgentHarness(self.state_dir)
        genesis = harness.bootstrap("test-agent", "Runs tests.", ["code.edit.v1"])
        epoch = harness.rotate_key()
        self.assertEqual(epoch["agent_id"], genesis["agent_id"])
        self.assertEqual(epoch["transition"], "key_rotation")
        self.assertNotEqual(epoch["public_key"], genesis["public_key"])
        self.assertEqual(harness.state.detail["epoch_number"], 1)
        result = verify_bundle(harness.bundle())
        self.assertTrue(result.ok)

    def test_delegate_is_scoped_and_verifiable(self) -> None:
        harness = AgentHarness(self.state_dir)
        harness.bootstrap("test-agent", "Runs tests.", ["observe."])
        delegate_identity = AgentIdentity.generate()
        delegate = harness.delegate(delegate_identity, ["observe.sensors."], "one task", timedelta(minutes=10))
        verify_delegate(delegate, harness.current_epoch, harness.state.detail)
        bundle = harness.bundle(delegate=delegate)
        result = verify_bundle(bundle)
        self.assertTrue(result.ok)
        self.assertTrue(result.delegate_ok)

    def test_action_log_and_experience_both_verify_after_a_full_lifecycle(self) -> None:
        harness = AgentHarness(self.state_dir)
        harness.bootstrap("test-agent", "Runs tests.", ["code.edit.v1"])
        harness.log_action("tool.invoked", {"tool": "bash"})
        harness.record_experience("lesson", {"note": "retries help"})
        harness.rotate_key()
        harness.reconcile(auto_apply=True)
        harness.action_log.verify()
        harness.experience.verify()


if __name__ == "__main__":
    unittest.main()
