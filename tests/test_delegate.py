from __future__ import annotations

import unittest
from datetime import timedelta

from agent_id_card import AgentIdentity, AICError, create_delegate, create_genesis_epoch, delegate_permits, verify_delegate
from agent_id_card.timestamps import now


class DelegateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parent_identity = AgentIdentity.generate()
        self.genesis = create_genesis_epoch(self.parent_identity, "alice", "demo", ["observe.", "coordinate."])
        self.delegate_identity = AgentIdentity.generate()

    def test_narrowing_scope_verifies_and_permits_matching_capabilities(self) -> None:
        delegate = create_delegate(self.genesis, self.parent_identity, self.delegate_identity, ["observe.sensors."], "sensor task", timedelta(minutes=10))
        verify_delegate(delegate, self.genesis)
        self.assertTrue(delegate_permits(delegate, "observe.sensors.lidar.v1"))
        self.assertFalse(delegate_permits(delegate, "coordinate.chat.v1"))

    def test_widening_scope_is_rejected_at_minting_time(self) -> None:
        with self.assertRaises(AICError) as raised:
            create_delegate(self.genesis, self.parent_identity, self.delegate_identity, ["actuate.motors."], "escalation", timedelta(minutes=10))
        self.assertEqual(raised.exception.code, "delegate.scope_not_narrowing")

    def test_forged_scope_widening_after_signing_fails_verification(self) -> None:
        delegate = create_delegate(self.genesis, self.parent_identity, self.delegate_identity, ["observe.sensors."], "sensor task", timedelta(minutes=10))
        delegate["scope_capability_prefixes"] = ["observe.", "coordinate.", "actuate."]
        with self.assertRaises(AICError) as raised:
            verify_delegate(delegate, self.genesis)
        self.assertEqual(raised.exception.code, "signature.invalid")

    def test_expired_delegate_is_rejected(self) -> None:
        delegate = create_delegate(self.genesis, self.parent_identity, self.delegate_identity, ["observe."], "sensor task", timedelta(seconds=1))
        with self.assertRaises(AICError) as raised:
            verify_delegate(delegate, self.genesis, at=now() + timedelta(seconds=5))
        self.assertEqual(raised.exception.code, "delegate.expired")

    def test_validity_beyond_the_cap_is_rejected(self) -> None:
        with self.assertRaises(AICError) as raised:
            create_delegate(self.genesis, self.parent_identity, self.delegate_identity, ["observe."], "sensor task", timedelta(hours=13))
        self.assertEqual(raised.exception.code, "delegate.validity_too_long")

    def test_delegate_signed_by_the_wrong_key_is_rejected(self) -> None:
        impostor = AgentIdentity.generate()
        with self.assertRaises(AICError) as raised:
            create_delegate(self.genesis, impostor, self.delegate_identity, ["observe."], "sensor task", timedelta(minutes=10))
        self.assertEqual(raised.exception.code, "delegate.wrong_key")


if __name__ == "__main__":
    unittest.main()
