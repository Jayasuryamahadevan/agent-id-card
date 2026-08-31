from __future__ import annotations

import unittest

from agent_id_card import AgentIdentity, AICError, create_detail, create_genesis_epoch, create_sensitive, verify_detail, verify_sensitive
from agent_id_card.tiers import derive_capability_categories


class TiersTests(unittest.TestCase):
    def test_capability_categories_are_sorted_and_deduplicated(self) -> None:
        self.assertEqual(
            derive_capability_categories(["observe.a.v1", "observe.b.v1", "actuate.c.v1"]),
            ["actuate", "observe"],
        )

    def test_detail_verifies_against_its_committing_epoch(self) -> None:
        identity = AgentIdentity.generate()
        detail = create_detail(identity.agent_id, 0, identity, ["observe.status.v1"], known_limitations=["no network"])
        genesis = create_genesis_epoch(identity, "alice", "demo", detail)
        verify_detail(detail, genesis)

    def test_detail_digest_mismatch_is_rejected(self) -> None:
        identity = AgentIdentity.generate()
        detail = create_detail(identity.agent_id, 0, identity, ["observe.status.v1"])
        genesis = create_genesis_epoch(identity, "alice", "demo", detail)
        other_detail = create_detail(identity.agent_id, 0, identity, ["observe.status.v1", "coordinate.chat.v1"])
        with self.assertRaises(AICError) as raised:
            verify_detail(other_detail, genesis)
        self.assertEqual(raised.exception.code, "tier2.digest_mismatch")

    def test_epoch_capability_categories_must_match_disclosed_detail(self) -> None:
        identity = AgentIdentity.generate()
        detail = create_detail(identity.agent_id, 0, identity, ["observe.status.v1"])
        genesis = create_genesis_epoch(identity, "alice", "demo", detail)
        # Forge a detail whose digest happens not to be checked (bypassing
        # create_genesis_epoch's own honest derivation) to simulate an
        # epoch that dishonestly under/over-stated its Tier 1 categories.
        genesis_lying = dict(genesis)
        genesis_lying["capability_categories"] = ["observe", "actuate"]
        with self.assertRaises(AICError) as raised:
            verify_detail(detail, genesis_lying)
        self.assertEqual(raised.exception.code, "tier1.categories_dishonest")

    def test_sensitive_verifies_and_rejects_digest_mismatch(self) -> None:
        identity = AgentIdentity.generate()
        detail = create_detail(identity.agent_id, 0, identity, ["observe.status.v1"])
        sensitive = create_sensitive(
            identity.agent_id, 0, identity,
            model_name="test-model", model_version="1.0",
            hardware={"os": "Linux"}, software_stack={"runtime": "cpython"},
        )
        genesis = create_genesis_epoch(identity, "alice", "demo", detail, sensitive)
        verify_sensitive(sensitive, genesis)

        other_sensitive = create_sensitive(identity.agent_id, 0, identity, model_name="different-model", model_version="1.0")
        with self.assertRaises(AICError) as raised:
            verify_sensitive(other_sensitive, genesis)
        self.assertEqual(raised.exception.code, "tier3.digest_mismatch")


if __name__ == "__main__":
    unittest.main()
