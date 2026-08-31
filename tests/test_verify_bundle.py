from __future__ import annotations

import unittest
from datetime import timedelta

from agent_id_card import (
    AgentIdentity,
    build_bundle,
    create_attestation,
    create_genesis_epoch,
    create_successor_epoch,
    renew,
    verify_bundle,
)
from agent_id_card.timestamps import now


class VerifyBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = AgentIdentity.generate()
        self.genesis = create_genesis_epoch(self.identity, "alice", "demo", ["observe."])

    def test_happy_path_is_ok(self) -> None:
        renewal = renew(self.genesis, self.identity)
        bundle = build_bundle([self.genesis], renewal=renewal)
        result = verify_bundle(bundle)
        self.assertTrue(result.ok)
        self.assertTrue(result.chain_valid)
        self.assertTrue(result.live)
        self.assertFalse(result.revoked)

    def test_missing_renewal_fails_when_liveness_is_required_but_not_otherwise(self) -> None:
        bundle = build_bundle([self.genesis])
        strict = verify_bundle(bundle, require_live=True)
        self.assertFalse(strict.ok)
        self.assertFalse(strict.live)
        lenient = verify_bundle(bundle, require_live=False)
        self.assertTrue(lenient.ok)

    def test_untrusted_revocation_does_not_count_when_trusted_revokers_is_restricted(self) -> None:
        renewal = renew(self.genesis, self.identity)
        random_party = AgentIdentity.generate()
        revocation = create_attestation(self.genesis["agent_id"], random_party, "revocation", {"reason": "spam"})
        bundle = build_bundle([self.genesis], renewal=renewal, attestations=[revocation])

        permissive = verify_bundle(bundle)  # no trusted_revokers -> any valid revocation counts
        self.assertFalse(permissive.ok)
        self.assertTrue(permissive.revoked)

        restricted = verify_bundle(bundle, trusted_revokers={"aic:agent:someone-else"})
        self.assertTrue(restricted.ok)
        self.assertFalse(restricted.revoked)

    def test_trusted_operator_revocation_makes_the_bundle_untrusted(self) -> None:
        renewal = renew(self.genesis, self.identity)
        operator = AgentIdentity.generate()
        revocation = create_attestation(self.genesis["agent_id"], operator, "revocation", {"reason": "compromised"})
        bundle = build_bundle([self.genesis], renewal=renewal, attestations=[revocation])
        result = verify_bundle(bundle, trusted_revokers={operator.agent_id})
        self.assertFalse(result.ok)
        self.assertTrue(result.revoked)

    def test_epoch_scoped_attestation_is_matched_against_chain_history_not_just_the_tip(self) -> None:
        issuer = AgentIdentity.generate()
        endorsement = create_attestation(self.genesis["agent_id"], issuer, "endorsement", {"note": "epoch 0 audited"}, subject_epoch=self.genesis)
        updated = create_successor_epoch(self.genesis, self.identity, "capability_update", declared_capabilities=["observe.", "coordinate."])
        renewal = renew(updated, self.identity)
        bundle = build_bundle([self.genesis, updated], renewal=renewal, attestations=[endorsement])
        result = verify_bundle(bundle)
        self.assertTrue(result.ok)
        self.assertEqual(len(result.attestation_checks), 1)
        self.assertTrue(result.attestation_checks[0].valid)

    def test_invalid_chain_link_is_reported_and_fails(self) -> None:
        decoy = create_genesis_epoch(AgentIdentity.generate(), "mallory", "demo", ["observe."])
        bundle = build_bundle([self.genesis, decoy])
        result = verify_bundle(bundle, require_live=False)
        self.assertFalse(result.ok)
        self.assertFalse(result.chain_valid)
        self.assertTrue(result.errors)

    def test_clock_skew_beyond_tolerance_is_rejected(self) -> None:
        renewal = renew(self.genesis, self.identity, timedelta(hours=1))
        bundle = build_bundle([self.genesis], renewal=renewal)
        far_future = verify_bundle(bundle, at=now() + timedelta(hours=2))
        self.assertFalse(far_future.ok)
        self.assertFalse(far_future.live)


if __name__ == "__main__":
    unittest.main()
