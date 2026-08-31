from __future__ import annotations

import unittest

from agent_id_card import AgentIdentity, AICError, create_detail, create_genesis_epoch, create_successor_epoch, verify_epoch


def _detail(agent_id: str, epoch_number: int, identity: AgentIdentity, capabilities: list[str]) -> dict:
    return create_detail(agent_id, epoch_number, identity, capabilities)


class EpochTests(unittest.TestCase):
    def test_genesis_epoch_is_self_consistent(self) -> None:
        identity = AgentIdentity.generate()
        detail = _detail(identity.agent_id, 0, identity, ["observe.status.v1"])
        genesis = create_genesis_epoch(identity, "alice", "demo", detail)
        verify_epoch(genesis)
        self.assertEqual(genesis["agent_id"], identity.agent_id)
        self.assertEqual(genesis["epoch_number"], 0)
        self.assertIsNone(genesis["prior_epoch_digest"])
        self.assertEqual(genesis["capability_categories"], ["observe"])

    def test_capability_update_keeps_the_same_key_and_agent_id(self) -> None:
        identity = AgentIdentity.generate()
        genesis = create_genesis_epoch(identity, "alice", "demo", _detail(identity.agent_id, 0, identity, ["observe.status.v1"]))
        new_detail = _detail(identity.agent_id, 1, identity, ["observe.status.v1", "coordinate.chat.v1"])
        updated = create_successor_epoch(genesis, identity, "capability_update", new_detail)
        verify_epoch(updated, prior_epoch=genesis)
        self.assertEqual(updated["public_key"], genesis["public_key"])
        self.assertEqual(updated["agent_id"], genesis["agent_id"])
        self.assertEqual(updated["capability_categories"], ["coordinate", "observe"])

    def test_key_rotation_preserves_agent_id_and_requires_predecessor_signature(self) -> None:
        old_identity = AgentIdentity.generate()
        new_identity = AgentIdentity.generate()
        genesis = create_genesis_epoch(old_identity, "alice", "demo", _detail(old_identity.agent_id, 0, old_identity, ["observe.status.v1"]))
        rotated_detail = _detail(genesis["agent_id"], 1, new_identity, ["observe.status.v1"])
        rotated = create_successor_epoch(genesis, old_identity, "key_rotation", rotated_detail, new_identity=new_identity)
        verify_epoch(rotated, prior_epoch=genesis)
        self.assertEqual(rotated["agent_id"], genesis["agent_id"])
        self.assertEqual(rotated["public_key"], new_identity.public_b64)
        self.assertIn("predecessor_signature", rotated)

    def test_key_change_without_rotation_transition_is_rejected(self) -> None:
        old_identity = AgentIdentity.generate()
        new_identity = AgentIdentity.generate()
        genesis = create_genesis_epoch(old_identity, "alice", "demo", _detail(old_identity.agent_id, 0, old_identity, ["observe.status.v1"]))
        detail = _detail(genesis["agent_id"], 1, old_identity, ["observe.status.v1"])
        # Forge a "capability_update" epoch but sneak in a different key --
        # this must never verify, since nothing proves the new key belongs
        # to the same continuing entity.
        forged = create_successor_epoch(genesis, old_identity, "capability_update", detail)
        forged["public_key"] = new_identity.public_b64
        forged = {k: v for k, v in forged.items() if k != "signature"}
        from agent_id_card.crypto import sign

        forged = sign(forged, new_identity.private_key)
        with self.assertRaises(AICError) as raised:
            verify_epoch(forged, prior_epoch=genesis)
        self.assertEqual(raised.exception.code, "epoch.unauthorized_key_change")

    def test_someone_elses_key_cannot_mint_a_successor(self) -> None:
        identity = AgentIdentity.generate()
        impostor = AgentIdentity.generate()
        genesis = create_genesis_epoch(identity, "alice", "demo", _detail(identity.agent_id, 0, identity, ["observe.status.v1"]))
        detail = _detail(genesis["agent_id"], 1, impostor, ["observe.status.v1"])
        with self.assertRaises(AICError) as raised:
            create_successor_epoch(genesis, impostor, "capability_update", detail)
        self.assertEqual(raised.exception.code, "epoch.wrong_key")

    def test_broken_chain_link_is_rejected(self) -> None:
        identity = AgentIdentity.generate()
        genesis = create_genesis_epoch(identity, "alice", "demo", _detail(identity.agent_id, 0, identity, ["observe.status.v1"]))
        decoy = create_genesis_epoch(AgentIdentity.generate(), "decoy", "demo", _detail("decoy", 0, AgentIdentity.generate(), ["observe.status.v1"]))
        detail = _detail(genesis["agent_id"], 1, identity, ["observe.status.v1"])
        updated = create_successor_epoch(genesis, identity, "capability_update", detail)
        # Point at a digest that isn't genesis's real one, while otherwise
        # keeping agent_id/epoch_number consistent, so this specifically
        # exercises the digest-linkage check rather than the agent_id one.
        from agent_id_card.crypto import digest_of, sign

        forged = {**updated, "prior_epoch_digest": digest_of(decoy)}
        forged = sign({k: v for k, v in forged.items() if k != "signature"}, identity.private_key)
        with self.assertRaises(AICError) as raised:
            verify_epoch(forged, prior_epoch=genesis)
        self.assertEqual(raised.exception.code, "epoch.chain_broken")


if __name__ == "__main__":
    unittest.main()
