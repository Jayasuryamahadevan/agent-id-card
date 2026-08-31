from __future__ import annotations

import unittest

from agent_id_card import AgentIdentity, AICError, create_attestation, create_detail, create_genesis_epoch, verify_attestation


class AttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.subject_identity = AgentIdentity.generate()
        self.detail = create_detail(self.subject_identity.agent_id, 0, self.subject_identity, ["observe."])
        self.genesis = create_genesis_epoch(self.subject_identity, "alice", "demo", self.detail)
        self.issuer = AgentIdentity.generate()

    def test_agent_level_attestation_survives_a_capability_update(self) -> None:
        from agent_id_card import create_successor_epoch

        attestation = create_attestation(self.genesis["agent_id"], self.issuer, "operator", {"contact": "ops@example.com"})
        verify_attestation(attestation, self.genesis["agent_id"])
        new_detail = create_detail(self.genesis["agent_id"], 1, self.subject_identity, ["observe.", "coordinate."])
        updated = create_successor_epoch(self.genesis, self.subject_identity, "capability_update", new_detail)
        # Still valid: it was never scoped to one epoch.
        verify_attestation(attestation, updated["agent_id"])

    def test_epoch_scoped_attestation_does_not_apply_to_a_different_epoch(self) -> None:
        from agent_id_card import create_successor_epoch

        attestation = create_attestation(self.genesis["agent_id"], self.issuer, "endorsement", {"note": "epoch 0 behaved well"}, subject_epoch=self.genesis)
        verify_attestation(attestation, self.genesis["agent_id"], subject_epoch=self.genesis)
        new_detail = create_detail(self.genesis["agent_id"], 1, self.subject_identity, ["observe."])
        updated = create_successor_epoch(self.genesis, self.subject_identity, "capability_update", new_detail)
        with self.assertRaises(AICError) as raised:
            verify_attestation(attestation, updated["agent_id"], subject_epoch=updated)
        self.assertEqual(raised.exception.code, "attestation.epoch_mismatch")

    def test_forged_issuer_public_key_is_rejected(self) -> None:
        attestation = create_attestation(self.genesis["agent_id"], self.issuer, "operator", {})
        attestation["issuer_public_key"] = AgentIdentity.generate().public_b64
        with self.assertRaises(AICError) as raised:
            verify_attestation(attestation, self.genesis["agent_id"])
        self.assertEqual(raised.exception.code, "attestation.issuer_key_mismatch")

    def test_tampered_claim_fails_signature_verification(self) -> None:
        attestation = create_attestation(self.genesis["agent_id"], self.issuer, "incident", {"severity": "low"})
        attestation["claim"]["severity"] = "critical"
        with self.assertRaises(AICError) as raised:
            verify_attestation(attestation, self.genesis["agent_id"])
        self.assertEqual(raised.exception.code, "signature.invalid")


if __name__ == "__main__":
    unittest.main()
