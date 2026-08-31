"""Property test: mutating any single top-level field of a signed epoch
(other than the signature itself, which mutation is covered separately)
must break verification. This is the one property that actually matters
for a signature scheme -- it's easy to write a canonicalizer/signer pair
that happens to work on the happy path but silently ignores some field."""

from __future__ import annotations

import copy
import unittest

from hypothesis import given
from hypothesis import strategies as st

from agent_id_card import AgentIdentity, AICError, create_detail, create_genesis_epoch, verify_epoch

MUTABLE_FIELDS = ["display_name", "purpose", "epoch_number", "issued_at", "transition", "agent_id", "detailed_digest"]


def _genesis() -> dict:
    identity = AgentIdentity.generate()
    detail = create_detail(identity.agent_id, 0, identity, ["observe."])
    return create_genesis_epoch(identity, "alice", "demo", detail)


class TamperPropertyTests(unittest.TestCase):
    @given(field=st.sampled_from(MUTABLE_FIELDS))
    def test_mutating_any_signed_field_breaks_verification(self, field: str) -> None:
        genesis = _genesis()
        tampered = copy.deepcopy(genesis)
        current = tampered[field]
        tampered[field] = (current + 1) if isinstance(current, int) else f"{current}-tampered"
        with self.assertRaises(AICError):
            verify_epoch(tampered)

    @given(garbage=st.text(min_size=1, max_size=40))
    def test_a_signature_value_that_isnt_the_real_one_never_verifies(self, garbage: str) -> None:
        genesis = _genesis()
        tampered = copy.deepcopy(genesis)
        if garbage == tampered["signature"]["value"]:
            return
        tampered["signature"]["value"] = garbage
        with self.assertRaises(AICError):
            verify_epoch(tampered)


if __name__ == "__main__":
    unittest.main()
