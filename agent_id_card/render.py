"""A small, honest text rendering of a verification result -- for a human
skimming a terminal or log, not a substitute for reading the structured
report yourself. The library's primary artifact is the data and the
verification logic, not this presentation."""

from __future__ import annotations

from .verify import VerificationResult


def describe_trust_tier(result: VerificationResult) -> str:
    """A convenience label, not an authoritative score -- derived
    transparently from what's actually IN the bundle (never a hidden or
    externally-computed reputation number). Always prefer reading
    `attestation_checks` yourself for the real data behind this label."""
    if not result.ok:
        return "untrusted"
    valid_kinds = {check.kind for check in result.attestation_checks if check.valid}
    if "endorsement" in valid_kinds and "operator" in valid_kinds:
        return "attested"
    if "operator" in valid_kinds:
        return "operated"
    return "self-asserted"


def render_text(result: VerificationResult) -> str:
    lines = [
        f"agent_id      {result.agent_id}",
        f"status        {'OK' if result.ok else 'FAILED'}  (trust tier: {describe_trust_tier(result)})",
        f"chain         {'valid' if result.chain_valid else 'INVALID'}, {result.chain_length} epoch(s)",
        f"live          {result.live}",
        f"revoked       {result.revoked}",
    ]
    if result.current_epoch is not None:
        epoch = result.current_epoch
        lines.append(f"display_name  {epoch.get('display_name')}")
        lines.append(f"purpose       {epoch.get('purpose')}")
        lines.append(f"categories    {', '.join(epoch.get('capability_categories', []))}  (Tier 1)")
    lines.append(f"disclosed     Tier {result.disclosed_tiers}")
    if result.detail_ok is not None:
        lines.append(f"tier2 detail  {'valid' if result.detail_ok else 'INVALID'}")
    if result.sensitive_ok is not None:
        lines.append(f"tier3 sensitive {'valid' if result.sensitive_ok else 'INVALID'}")
    if result.attestation_checks:
        lines.append("attestations:")
        for check in result.attestation_checks:
            mark = "OK" if check.valid else "FAIL"
            lines.append(f"  [{mark}] {check.kind:<12} issuer={check.issuer_id}  {'' if check.valid else check.error}")
    if result.delegate_ok is not None:
        lines.append(f"delegate      {'valid' if result.delegate_ok else 'INVALID'}")
    if result.errors:
        lines.append("errors:")
        lines.extend(f"  - {error}" for error in result.errors)
    return "\n".join(lines)
