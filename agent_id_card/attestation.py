"""Attestations: independent, appendable, third-party claims about an
agent -- the web-of-trust layer.

A card is never just one issuer's signature. Anyone who holds a key --
the agent's operator, the model provider, another agent it has worked
with, a human auditor -- can attach an attestation to an agent_id (and,
optionally, one exact epoch of it), independently of the agent and of
every other attestor, without asking anyone's permission and without
needing to reissue anything. A verifier decides for itself which issuers
and which kinds it trusts; there is no single certificate authority whose
compromise or absence blocks verification of everything else.

`subject_epoch_digest` is nullable by design: a slowly-changing,
identity-level fact ("who operates this agent") shouldn't need
re-issuing every time a capability list changes, so it is left null and
pinned to `subject_agent_id` alone; a claim about one exact snapshot of
behavior ("epoch #3 passed this audit", "epoch #2 did this specific bad
thing") pins the digest too, and stops applying the moment that epoch is
superseded (a verifier checking a LATER epoch simply won't have that
attestation apply -- it must be re-issued against the new epoch if still
true).

Well-known kinds (a verifier may treat an unknown kind as informational
only, but MUST NOT reject it as invalid -- new kinds are meant to be
addable without a spec revision):

  operator     -- who is accountable for running this agent (contact,
                  jurisdiction, deployment context). Usually agent-level.
  provenance   -- what this agent is built from (base model, fine-tune,
                  training data lineage, build/commit reference). Usually
                  epoch-scoped (provenance changes when the model does).
  endorsement  -- a free-form positive claim from a peer, auditor, or
                  user ("I have used this agent for X and it behaved
                  correctly").
  incident     -- a negative or cautionary claim (a failure, a policy
                  violation, a safety event) -- never deleted, only ever
                  added to, so a bad record cannot be quietly erased.
  revocation   -- "do not trust this agent_id starting now, regardless of
                  any valid renewal" -- almost always agent-level (a
                  compromised entity should not be trusted merely because
                  it rotated to a new epoch). The one kind `verify.py`
                  treats as fatal by default.
"""

from __future__ import annotations

from typing import Any

from .crypto import AgentIdentity, digest_of, sign, verify
from .errors import AICError
from .timestamps import now, parse_stamp, stamp

WELL_KNOWN_KINDS = frozenset({"operator", "provenance", "endorsement", "incident", "revocation"})


def create_attestation(
    subject_agent_id: str,
    issuer_identity: AgentIdentity,
    kind: str,
    claim: dict[str, Any],
    *,
    subject_epoch: dict[str, Any] | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(kind, str) or not kind:
        raise AICError("attestation.schema_invalid", "kind must be a non-empty string.")
    attestation = {
        "aic": "1.0",
        "type": "attestation",
        "subject_agent_id": subject_agent_id,
        "subject_epoch_digest": digest_of(subject_epoch) if subject_epoch is not None else None,
        "kind": kind,
        "issuer_id": issuer_identity.agent_id,
        "issuer_public_key": issuer_identity.public_b64,
        "claim": claim,
        "issued_at": stamp(),
        "expires_at": expires_at,
    }
    return sign(attestation, issuer_identity.private_key)


def verify_attestation(attestation: dict[str, Any], subject_agent_id: str, *, subject_epoch: dict[str, Any] | None = None, at: Any = None) -> None:
    required = {"aic", "type", "subject_agent_id", "subject_epoch_digest", "kind", "issuer_id", "issuer_public_key", "claim", "issued_at", "signature"}
    if not required.issubset(attestation) or attestation.get("type") != "attestation":
        raise AICError("attestation.schema_invalid", "Attestation is missing required fields.")
    if AgentIdentity.agent_id_for(attestation["issuer_public_key"]) != attestation["issuer_id"]:
        raise AICError("attestation.issuer_key_mismatch", "issuer_public_key does not derive issuer_id.")
    if attestation["subject_agent_id"] != subject_agent_id:
        raise AICError("attestation.subject_mismatch", "Attestation does not reference this agent_id.")
    if attestation["subject_epoch_digest"] is not None:
        if subject_epoch is None or attestation["subject_epoch_digest"] != digest_of(subject_epoch):
            raise AICError("attestation.epoch_mismatch", "Attestation is scoped to a different epoch than the one being checked.")
    verify(attestation, attestation["issuer_public_key"])
    moment = at or now()
    if attestation["expires_at"] is not None and parse_stamp(attestation["expires_at"]) <= moment:
        raise AICError("attestation.expired", "Attestation's validity window has passed.")
