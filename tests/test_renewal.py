from __future__ import annotations

import unittest
from datetime import timedelta

from agent_id_card import AgentIdentity, AICError, create_detail, create_genesis_epoch, renew, verify_renewal
from agent_id_card.renewal import MAX_VALIDITY
from agent_id_card.timestamps import now


class RenewalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = AgentIdentity.generate()
        detail = create_detail(self.identity.agent_id, 0, self.identity, ["observe."])
        self.genesis = create_genesis_epoch(self.identity, "alice", "demo", detail)

    def test_fresh_renewal_verifies(self) -> None:
        renewal = renew(self.genesis, self.identity)
        verify_renewal(renewal, self.genesis)

    def test_renewal_from_the_wrong_key_is_rejected(self) -> None:
        with self.assertRaises(AICError) as raised:
            renew(self.genesis, AgentIdentity.generate())
        self.assertEqual(raised.exception.code, "renewal.wrong_key")

    def test_expired_renewal_is_rejected(self) -> None:
        renewal = renew(self.genesis, self.identity, timedelta(seconds=1))
        with self.assertRaises(AICError) as raised:
            verify_renewal(renewal, self.genesis, at=now() + timedelta(seconds=5))
        self.assertEqual(raised.exception.code, "renewal.expired")

    def test_renewal_referencing_a_different_epoch_is_rejected(self) -> None:
        other_identity = AgentIdentity.generate()
        other_detail = create_detail(other_identity.agent_id, 0, other_identity, ["observe."])
        other_epoch = create_genesis_epoch(other_identity, "bob", "demo", other_detail)
        renewal = renew(self.genesis, self.identity)
        with self.assertRaises(AICError) as raised:
            verify_renewal(renewal, other_epoch)
        self.assertEqual(raised.exception.code, "renewal.epoch_mismatch")

    def test_validity_beyond_the_cap_is_rejected(self) -> None:
        with self.assertRaises(AICError) as raised:
            renew(self.genesis, self.identity, MAX_VALIDITY + timedelta(seconds=1))
        self.assertEqual(raised.exception.code, "renewal.validity_too_long")


if __name__ == "__main__":
    unittest.main()
