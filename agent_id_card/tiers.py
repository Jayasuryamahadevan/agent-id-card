"""Tiered, privilege-gated disclosure -- SPEC.md ss5.

  Tier 1 (public, IN the epoch itself)
      Who this is, in broad strokes: agent_id, display_name, a short
      factual purpose, and coarse capability CATEGORIES (e.g.
      "observe", "coordinate") -- enough for anyone to know roughly what
      they're talking to, nothing that requires trust to hand out freely.

  Tier 2 ("detail" -- a separate signed object, DIGEST-committed by the epoch)
      The exact declared_capabilities list, operator/accountability info,
      which protocols it speaks, and (optionally) known_limitations --
      what this agent honestly cannot do. More informative, still not
      sensitive.

  Tier 3 ("sensitive" -- also digest-committed, separately signed)
      Exact model name/version, weights digest, base-model lineage,
      hardware and driver versions, software stack -- genuinely
      sensitive, genuinely useful to a privileged auditor.

An epoch commits to Tier 2/3 via SHA-256 digests rather than embedding
them: a verifier who is only shown the epoch already knows Tier 2/3
content EXISTS and is bound to this exact identity, without being able
to read it, and once disclosed, it is checked against the commitment
made at signing time, so it can never be swapped for something
friendlier after the fact. Which tiers to send to which verifier is an
application-level policy decision -- this module only makes each tier
independently, honestly verifiable.
"""

from __future__ import annotations

from typing import Any

from .crypto import AgentIdentity, digest_of, sign, verify
from .errors import AICError
from .timestamps import stamp

LEVEL_PUBLIC = 1
LEVEL_DETAILED = 2
LEVEL_SENSITIVE = 3


def derive_capability_categories(declared_capabilities: list[str]) -> list[str]:
    """The coarse, Tier-1-safe summary of a Tier-2 capability list --
    always MECHANICALLY derived, never separately hand-typed, so a
    verifier who later sees Tier 2 can catch a mismatch instead of
    trusting an independently-asserted summary (SPEC.md ss5.4)."""
    return sorted({capability.split(".", 1)[0] for capability in declared_capabilities if capability})


def create_detail(
    agent_id: str,
    epoch_number: int,
    identity: AgentIdentity,
    declared_capabilities: list[str],
    *,
    operator: dict[str, Any] | None = None,
    protocols: list[str] | None = None,
    known_limitations: list[str] | None = None,
) -> dict[str, Any]:
    detail = {
        "aic": "1.0",
        "type": "tier2_detail",
        "agent_id": agent_id,
        "epoch_number": epoch_number,
        "declared_capabilities": list(declared_capabilities),
        "operator": operator,
        "protocols": list(protocols) if protocols is not None else [],
        "known_limitations": list(known_limitations) if known_limitations is not None else [],
        "issued_at": stamp(),
    }
    return sign(detail, identity.private_key)


def verify_detail(detail: dict[str, Any], epoch: dict[str, Any]) -> None:
    required = {"aic", "type", "agent_id", "epoch_number", "declared_capabilities", "issued_at", "signature"}
    if not required.issubset(detail) or detail.get("type") != "tier2_detail":
        raise AICError("tier2.schema_invalid", "Tier 2 detail is missing required fields.")
    if detail["agent_id"] != epoch["agent_id"] or detail["epoch_number"] != epoch["epoch_number"]:
        raise AICError("tier2.epoch_mismatch", "Tier 2 detail does not reference this exact epoch.")
    if epoch.get("detailed_digest") != digest_of(detail):
        raise AICError("tier2.digest_mismatch", "Epoch's detailed_digest does not match this Tier 2 content.")
    verify(detail, epoch["public_key"])
    if epoch.get("capability_categories") != derive_capability_categories(detail["declared_capabilities"]):
        raise AICError("tier1.categories_dishonest", "Epoch's Tier 1 capability_categories do not match the categories implied by Tier 2's actual declared_capabilities.")


def create_sensitive(
    agent_id: str,
    epoch_number: int,
    identity: AgentIdentity,
    *,
    model_name: str,
    model_version: str,
    weights_digest: str | None = None,
    base_model: str | None = None,
    hardware: dict[str, Any] | None = None,
    software_stack: dict[str, Any] | None = None,
    build_reference: str | None = None,
) -> dict[str, Any]:
    sensitive = {
        "aic": "1.0",
        "type": "tier3_sensitive",
        "agent_id": agent_id,
        "epoch_number": epoch_number,
        "model_name": model_name,
        "model_version": model_version,
        "weights_digest": weights_digest,
        "base_model": base_model,
        "hardware": hardware or {},
        "software_stack": software_stack or {},
        "build_reference": build_reference,
        "issued_at": stamp(),
    }
    return sign(sensitive, identity.private_key)


def verify_sensitive(sensitive: dict[str, Any], epoch: dict[str, Any]) -> None:
    required = {"aic", "type", "agent_id", "epoch_number", "model_name", "model_version", "hardware", "software_stack", "issued_at", "signature"}
    if not required.issubset(sensitive) or sensitive.get("type") != "tier3_sensitive":
        raise AICError("tier3.schema_invalid", "Tier 3 sensitive content is missing required fields.")
    if sensitive["agent_id"] != epoch["agent_id"] or sensitive["epoch_number"] != epoch["epoch_number"]:
        raise AICError("tier3.epoch_mismatch", "Tier 3 content does not reference this exact epoch.")
    if epoch.get("sensitive_digest") != digest_of(sensitive):
        raise AICError("tier3.digest_mismatch", "Epoch's sensitive_digest does not match this Tier 3 content.")
    verify(sensitive, epoch["public_key"])
