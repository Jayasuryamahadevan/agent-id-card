"""Renewals: the cheap, frequent heartbeat that makes an epoch's identity
content separable from its liveness.

This is the design's answer to revocation lists. Rather than a long-lived
credential that stays trusted until someone remembers to revoke it,
default validity is short (`DEFAULT_VALIDITY`) and renewal is nearly free
(re-sign four fields, no chain growth, no new epoch). An agent that goes
away -- decommissioned, compromised, crashed -- simply stops renewing,
and every open renewal quietly expires on schedule. A verifier that wants
stronger assurance than "not yet expired" can require a renewal signed
within the last few minutes, not just before `valid_until`. Explicit
compromise handling (immediate untrust, not just waiting out an expiry)
is what `attestation.py`'s `revocation` kind is for.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .crypto import AgentIdentity, digest_of, sign, verify
from .errors import AICError
from .timestamps import now, parse_stamp, stamp

DEFAULT_VALIDITY = timedelta(hours=24)
MAX_VALIDITY = timedelta(days=7)


def renew(epoch: dict[str, Any], identity: AgentIdentity, validity: timedelta = DEFAULT_VALIDITY) -> dict[str, Any]:
    if identity.public_b64 != epoch["public_key"]:
        raise AICError("renewal.wrong_key", "identity does not hold this epoch's key.")
    if validity > MAX_VALIDITY:
        raise AICError("renewal.validity_too_long", f"Renewal validity may not exceed {MAX_VALIDITY}.")
    issued = now()
    renewal = {
        "aic": "1.0",
        "type": "renewal",
        "agent_id": epoch["agent_id"],
        "epoch_digest": digest_of(epoch),
        "renewed_at": stamp(issued),
        "valid_until": stamp(issued + validity),
    }
    return sign(renewal, identity.private_key)


def verify_renewal(renewal: dict[str, Any], epoch: dict[str, Any], *, at: Any = None) -> None:
    required = {"aic", "type", "agent_id", "epoch_digest", "renewed_at", "valid_until", "signature"}
    if not required.issubset(renewal) or renewal.get("type") != "renewal":
        raise AICError("renewal.schema_invalid", "Renewal is missing required fields.")
    if renewal["agent_id"] != epoch["agent_id"] or renewal["epoch_digest"] != digest_of(epoch):
        raise AICError("renewal.epoch_mismatch", "Renewal does not reference this exact epoch.")
    verify(renewal, epoch["public_key"])
    moment = at or now()
    if parse_stamp(renewal["valid_until"]) <= moment:
        raise AICError("renewal.expired", "Renewal's validity window has passed.")
    if parse_stamp(renewal["renewed_at"]) > moment + timedelta(seconds=60):
        raise AICError("renewal.issued_in_future", "Renewal is issued too far in the future (clock skew?).")
