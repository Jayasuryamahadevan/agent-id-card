"""Epochs: the identity-content backbone of an AIC lineage.

An agent's `agent_id` is fixed forever at genesis (derived from the
genesis key), but the KEY that currently speaks for it, its declared
purpose, and its declared capabilities can all change over an agent's
life -- a model gets upgraded, an operator rotates a compromised key, a
capability gets added or withdrawn. Each such change is a new epoch,
hash-linked to the one before it (`prior_epoch_digest`), so the full
history is an append-only, tamper-evident chain -- exactly the reasoning
FASP_PROTOCOL-style audit chains apply to an event log, applied instead
to identity content itself.

A `key_rotation` epoch carries TWO signatures: the new key's own (proving
possession of the new key) and the prior epoch's key's `predecessor_
signature` (proving the entity that held the OLD key endorses the new one
as its successor). Without that second signature, anyone who has ever
seen your chain could mint a plausible-looking "next epoch" for your
agent_id using a key of their own -- a hash link alone only proves
ordering, never continuity of control.
"""

from __future__ import annotations

from typing import Any

from .crypto import AgentIdentity, digest_of, sign, sign_predecessor, verify
from .errors import AICError
from .timestamps import stamp

TRANSITIONS = frozenset({"genesis", "capability_update", "key_rotation"})


def create_genesis_epoch(identity: AgentIdentity, display_name: str, purpose: str, declared_capabilities: list[str]) -> dict[str, Any]:
    epoch = {
        "aic": "1.0",
        "type": "epoch",
        "agent_id": identity.agent_id,
        "epoch_number": 0,
        "transition": "genesis",
        "prior_epoch_digest": None,
        "public_key": identity.public_b64,
        "display_name": display_name,
        "purpose": purpose,
        "declared_capabilities": list(declared_capabilities),
        "issued_at": stamp(),
    }
    return sign(epoch, identity.private_key)


def create_successor_epoch(
    prior_epoch: dict[str, Any],
    current_identity: AgentIdentity,
    transition: str,
    *,
    new_identity: AgentIdentity | None = None,
    display_name: str | None = None,
    purpose: str | None = None,
    declared_capabilities: list[str] | None = None,
) -> dict[str, Any]:
    """Mint epoch N+1 from epoch N. `current_identity` must hold the prior
    epoch's key (it authors the self-signature for `capability_update`, and
    the `predecessor_signature` for `key_rotation`). For `key_rotation`,
    `new_identity` is the freshly generated key that becomes epoch N+1's
    active key and authors its own self-signature."""
    if transition not in TRANSITIONS or transition == "genesis":
        raise AICError("epoch.invalid_transition", f"transition must be one of {sorted(TRANSITIONS - {'genesis'})}.")
    verify(prior_epoch, prior_epoch["public_key"])
    if current_identity.public_b64 != prior_epoch["public_key"]:
        raise AICError("epoch.wrong_key", "current_identity does not hold the prior epoch's key.")
    if transition == "key_rotation" and new_identity is None:
        raise AICError("epoch.missing_new_identity", "key_rotation requires new_identity.")

    active_identity = new_identity if transition == "key_rotation" else current_identity
    epoch = {
        "aic": "1.0",
        "type": "epoch",
        "agent_id": prior_epoch["agent_id"],
        "epoch_number": prior_epoch["epoch_number"] + 1,
        "transition": transition,
        "prior_epoch_digest": digest_of(prior_epoch),
        "public_key": active_identity.public_b64,
        "display_name": display_name if display_name is not None else prior_epoch["display_name"],
        "purpose": purpose if purpose is not None else prior_epoch["purpose"],
        "declared_capabilities": list(declared_capabilities) if declared_capabilities is not None else list(prior_epoch["declared_capabilities"]),
        "issued_at": stamp(),
    }
    epoch = sign(epoch, active_identity.private_key)
    if transition == "key_rotation":
        epoch = sign_predecessor(epoch, current_identity.private_key)
    return epoch


def verify_epoch(epoch: dict[str, Any], *, prior_epoch: dict[str, Any] | None = None) -> None:
    """Verify one epoch in isolation (self-signature, and predecessor
    signature/chain linkage if `prior_epoch` is supplied). Verifying an
    entire chain from genesis is `verify.py`'s job, which calls this once
    per link."""
    required = {"aic", "type", "agent_id", "epoch_number", "transition", "public_key", "issued_at", "signature"}
    if not required.issubset(epoch) or epoch.get("type") != "epoch":
        raise AICError("epoch.schema_invalid", "Epoch is missing required fields.")
    if epoch["transition"] not in TRANSITIONS:
        raise AICError("epoch.schema_invalid", f"Unknown transition {epoch['transition']!r}.")
    verify(epoch, epoch["public_key"])
    if prior_epoch is None:
        if epoch["epoch_number"] != 0 or epoch["transition"] != "genesis" or epoch["prior_epoch_digest"] is not None:
            raise AICError("epoch.not_genesis", "First epoch in a chain must be epoch_number 0 with no prior_epoch_digest.")
        return
    if epoch["epoch_number"] != prior_epoch["epoch_number"] + 1:
        raise AICError("epoch.out_of_order", "Epoch numbers must increase by exactly one.")
    if epoch["agent_id"] != prior_epoch["agent_id"]:
        raise AICError("epoch.agent_id_mismatch", "Successor epoch must keep the same agent_id.")
    if epoch["prior_epoch_digest"] != digest_of(prior_epoch):
        raise AICError("epoch.chain_broken", "prior_epoch_digest does not match the actual prior epoch's digest.")
    if epoch["transition"] == "key_rotation":
        verify(epoch, prior_epoch["public_key"], field="predecessor_signature")
    elif epoch["public_key"] != prior_epoch["public_key"]:
        raise AICError("epoch.unauthorized_key_change", "Key changed without a key_rotation transition and predecessor_signature.")
