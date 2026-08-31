"""The verification engine: turn a bundle (epoch chain + renewal +
attestations + optional delegate) into a structured, inspectable report.

Deliberately returns a report object rather than raising on the first
problem: a verifier often wants to know EVERYTHING that's wrong (or
right) about a card at once -- which attestations check out, whether it's
merely stale versus actively revoked, whether a delegate's scope is the
problem versus its parent chain -- not just the first exception hit.
`result.ok` is the single yes/no a caller in a hurry can check; every
field behind it is there for a caller that wants to make its own
trust decision instead of accepting this library's default one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .attestation import verify_attestation
from .crypto import digest_of
from .delegate import verify_delegate
from .epoch import verify_epoch
from .errors import AICError
from .renewal import verify_renewal
from .tiers import verify_detail, verify_sensitive
from .timestamps import now


@dataclass
class AttestationCheck:
    kind: str
    issuer_id: str
    valid: bool
    error: str | None
    claim: dict[str, Any]
    scoped_to_epoch: bool

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "issuer_id": self.issuer_id, "valid": self.valid, "error": self.error, "claim": self.claim, "scoped_to_epoch": self.scoped_to_epoch}


@dataclass
class VerificationResult:
    ok: bool
    agent_id: str | None
    chain_length: int
    chain_valid: bool
    current_epoch: dict[str, Any] | None
    live: bool | None
    revoked: bool
    disclosed_tiers: list[int] = field(default_factory=lambda: [1])
    detail_ok: bool | None = None
    sensitive_ok: bool | None = None
    attestation_checks: list[AttestationCheck] = field(default_factory=list)
    delegate_ok: bool | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "agent_id": self.agent_id,
            "chain_length": self.chain_length,
            "chain_valid": self.chain_valid,
            "current_epoch": self.current_epoch,
            "live": self.live,
            "revoked": self.revoked,
            "disclosed_tiers": self.disclosed_tiers,
            "detail_ok": self.detail_ok,
            "sensitive_ok": self.sensitive_ok,
            "attestation_checks": [check.to_dict() for check in self.attestation_checks],
            "delegate_ok": self.delegate_ok,
            "errors": self.errors,
        }


def _verify_chain(epoch_chain: list[dict[str, Any]], errors: list[str]) -> bool:
    if not epoch_chain:
        errors.append("epoch_chain is empty.")
        return False
    try:
        verify_epoch(epoch_chain[0])
    except AICError as exc:
        errors.append(f"genesis epoch: {exc.code}: {exc.detail}")
        return False
    for index in range(1, len(epoch_chain)):
        try:
            verify_epoch(epoch_chain[index], prior_epoch=epoch_chain[index - 1])
        except AICError as exc:
            errors.append(f"epoch #{index}: {exc.code}: {exc.detail}")
            return False
    return True


def verify_bundle(
    bundle: dict[str, Any],
    *,
    at: Any = None,
    require_live: bool = True,
    trusted_revokers: set[str] | None = None,
) -> VerificationResult:
    """`trusted_revokers`, if given, restricts which issuer_ids' `revocation`
    attestations count -- omit it only for a quick, permissive check (any
    correctly-signed revocation claim is honored); a real deployment should
    almost always pass the set of issuers it has independently decided to
    trust for that purpose (e.g. from its own prior `operator` attestations)."""
    moment = at or now()
    errors: list[str] = []
    epoch_chain = bundle.get("epoch_chain") or []
    chain_valid = _verify_chain(epoch_chain, errors)
    current_epoch = epoch_chain[-1] if chain_valid else None
    agent_id = current_epoch["agent_id"] if current_epoch else (epoch_chain[0].get("agent_id") if epoch_chain else None)

    disclosed_tiers = bundle.get("disclosed_tiers") or [1]
    detail, sensitive = bundle.get("detail"), bundle.get("sensitive")
    if (2 in disclosed_tiers) != (detail is not None) or (3 in disclosed_tiers) != (sensitive is not None):
        errors.append("bundle.disclosed_tiers does not match which of detail/sensitive are actually present.")

    detail_ok: bool | None = None
    if chain_valid and detail is not None:
        try:
            verify_detail(detail, current_epoch)
            detail_ok = True
        except AICError as exc:
            detail_ok = False
            errors.append(f"tier2 detail: {exc.code}: {exc.detail}")

    sensitive_ok: bool | None = None
    if chain_valid and sensitive is not None:
        try:
            verify_sensitive(sensitive, current_epoch)
            sensitive_ok = True
        except AICError as exc:
            sensitive_ok = False
            errors.append(f"tier3 sensitive: {exc.code}: {exc.detail}")

    live: bool | None = None
    if chain_valid:
        renewal = bundle.get("renewal")
        if renewal is None:
            live = False
            if require_live:
                errors.append("no renewal present.")
        else:
            try:
                verify_renewal(renewal, current_epoch, at=moment)
                live = True
            except AICError as exc:
                live = False
                errors.append(f"renewal: {exc.code}: {exc.detail}")

    revoked = False
    attestation_checks: list[AttestationCheck] = []
    for attestation in bundle.get("attestations") or []:
        kind = attestation.get("kind", "?")
        issuer_id = attestation.get("issuer_id", "?")
        scoped = attestation.get("subject_epoch_digest") is not None
        try:
            subject_epoch = current_epoch if scoped else None
            # An epoch-scoped attestation may reference an OLDER epoch than
            # the chain's current tip -- search the whole chain, not just
            # the tip, so history-scoped claims keep verifying after a
            # later renewal/rotation.
            if scoped and current_epoch is not None and attestation["subject_epoch_digest"] != digest_of(current_epoch):
                subject_epoch = next((e for e in epoch_chain if digest_of(e) == attestation["subject_epoch_digest"]), None)
            verify_attestation(attestation, agent_id, subject_epoch=subject_epoch, at=moment)
            attestation_checks.append(AttestationCheck(kind, issuer_id, True, None, attestation.get("claim", {}), scoped))
            if kind == "revocation" and (trusted_revokers is None or issuer_id in trusted_revokers):
                revoked = True
        except AICError as exc:
            attestation_checks.append(AttestationCheck(kind, issuer_id, False, f"{exc.code}: {exc.detail}", attestation.get("claim", {}), scoped))

    delegate_ok: bool | None = None
    delegate = bundle.get("delegate")
    if delegate is not None and chain_valid:
        if detail is None:
            delegate_ok = False
            errors.append("delegate: cannot verify a delegate's scope narrowing without Tier 2 detail also being disclosed.")
        else:
            try:
                verify_delegate(delegate, current_epoch, detail, at=moment)
                delegate_ok = True
            except AICError as exc:
                delegate_ok = False
                errors.append(f"delegate: {exc.code}: {exc.detail}")

    if revoked:
        errors.append("a trusted revocation attestation is in force.")

    ok = (
        chain_valid
        and (live is not False or not require_live)
        and not revoked
        and delegate_ok is not False
        and detail_ok is not False
        and sensitive_ok is not False
        and not any("disclosed_tiers does not match" in error for error in errors)
    )
    return VerificationResult(
        ok=ok,
        agent_id=agent_id,
        chain_length=len(epoch_chain),
        chain_valid=chain_valid,
        current_epoch=current_epoch,
        live=live,
        revoked=revoked,
        disclosed_tiers=disclosed_tiers,
        detail_ok=detail_ok,
        sensitive_ok=sensitive_ok,
        attestation_checks=attestation_checks,
        delegate_ok=delegate_ok,
        errors=errors,
    )
