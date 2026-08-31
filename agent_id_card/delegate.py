"""Delegate cards: short-lived, capability-narrowed sub-identities.

An agent that spins up a per-session worker, hands a task to a sub-agent,
or calls a tool with a fresh key for isolation needs that sub-identity to
be independently verifiable AND provably constrained by its parent --
never able to claim more authority than the parent epoch itself declared.
A delegate card is the parent epoch's key signing "this freshly generated
key may act, within this narrower scope, until this (short) deadline."

Mirrors the same narrowing discipline FASP's grants use for capability
prefixes: a delegate's scope can equal or narrow its parent's declared
capabilities, never widen them -- enforced at MINTING time here, not
merely checked later by a downstream authorizer.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .crypto import AgentIdentity, digest_of, sign, verify
from .errors import AICError
from .tiers import verify_detail
from .timestamps import now, parse_stamp, stamp

MAX_DELEGATE_VALIDITY = timedelta(hours=12)


def _is_narrowing(scope_prefixes: list[str], parent_prefixes: list[str]) -> bool:
    return bool(scope_prefixes) and all(any(scope.startswith(parent) for parent in parent_prefixes) for scope in scope_prefixes)


def create_delegate(
    parent_epoch: dict[str, Any],
    parent_detail: dict[str, Any],
    parent_identity: AgentIdentity,
    delegate_identity: AgentIdentity,
    scope_capability_prefixes: list[str],
    purpose: str,
    validity: timedelta,
    max_actions: int | None = None,
) -> dict[str, Any]:
    """`parent_detail` is the parent epoch's own Tier 2 content
    (`tiers.py`) -- `declared_capabilities` lives there now, not in the
    epoch itself, so minting a delegate always re-verifies that Tier 2
    content against the epoch's own commitment first (the parent agent
    necessarily holds its own Tier 2/3 content already; this is a tamper
    check, not a privilege check)."""
    if parent_identity.public_b64 != parent_epoch["public_key"]:
        raise AICError("delegate.wrong_key", "parent_identity does not hold the parent epoch's key.")
    if validity > MAX_DELEGATE_VALIDITY:
        raise AICError("delegate.validity_too_long", f"Delegate validity may not exceed {MAX_DELEGATE_VALIDITY}.")
    verify_detail(parent_detail, parent_epoch)
    if not _is_narrowing(scope_capability_prefixes, parent_detail["declared_capabilities"]):
        raise AICError("delegate.scope_not_narrowing", "Delegate scope must narrow the parent epoch's declared capabilities, never widen them.")
    if max_actions is not None and max_actions < 1:
        raise AICError("delegate.schema_invalid", "max_actions must be a positive integer or None.")
    issued = now()
    delegate = {
        "aic": "1.0",
        "type": "delegate",
        "parent_agent_id": parent_epoch["agent_id"],
        "parent_epoch_digest": digest_of(parent_epoch),
        "delegate_public_key": delegate_identity.public_b64,
        "scope_capability_prefixes": list(scope_capability_prefixes),
        "purpose": purpose,
        "max_actions": max_actions,
        "issued_at": stamp(issued),
        "valid_until": stamp(issued + validity),
    }
    return sign(delegate, parent_identity.private_key)


def verify_delegate(delegate: dict[str, Any], parent_epoch: dict[str, Any], parent_detail: dict[str, Any], *, at: Any = None) -> None:
    required = {"aic", "type", "parent_agent_id", "parent_epoch_digest", "delegate_public_key", "scope_capability_prefixes", "issued_at", "valid_until", "signature"}
    if not required.issubset(delegate) or delegate.get("type") != "delegate":
        raise AICError("delegate.schema_invalid", "Delegate card is missing required fields.")
    if delegate["parent_agent_id"] != parent_epoch["agent_id"] or delegate["parent_epoch_digest"] != digest_of(parent_epoch):
        raise AICError("delegate.parent_mismatch", "Delegate does not reference this exact parent epoch.")
    verify(delegate, parent_epoch["public_key"])
    verify_detail(parent_detail, parent_epoch)
    if not _is_narrowing(delegate["scope_capability_prefixes"], parent_detail["declared_capabilities"]):
        raise AICError("delegate.scope_not_narrowing", "Delegate scope is not a narrowing of the parent epoch's declared capabilities.")
    moment = at or now()
    if parse_stamp(delegate["valid_until"]) <= moment:
        raise AICError("delegate.expired", "Delegate card's validity window has passed.")


def delegate_permits(delegate: dict[str, Any], capability: str) -> bool:
    return any(capability.startswith(prefix) for prefix in delegate["scope_capability_prefixes"])
