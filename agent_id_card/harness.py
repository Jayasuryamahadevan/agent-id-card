"""AgentHarness: the operational layer around any AI backend that turns
SPEC.md + HARNESS_BOOTSTRAP.md into a running thing, not just a document.

Wraps: identity lifecycle (bootstrap once, renew and update over time),
the append-only action log (every movement -- ss4), and the experience
store (what was learned -- experience.py). The one new idea this module
adds on top of the base library is `reconcile()`: an ID card is only
honest for as long as it keeps matching reality, and an agent's real
capabilities and limitations are usually not fully known at bootstrap --
they're discovered by actually operating. `reconcile()` is how
accumulated experience (and, if an `AgentAdapter` is attached, live
capability drift) flows back into a new `capability_update` epoch,
instead of the card silently going stale the moment reality moves on
from whatever was true at bootstrap.

This module wraps ANY AI backend: `AgentAdapter` asks only for a
`capabilities()` method, so a harness can sit in front of an LLM API
client, a robot controller, a tool-calling agent framework, or nothing
more than a human operator manually reporting what changed -- the
harness does not care what is actually generating the agent's behavior.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol

from .bundle import build_bundle
from .crypto import AgentIdentity, sign
from .delegate import create_delegate
from .epoch import create_genesis_epoch, create_successor_epoch
from .errors import AICError
from .experience import CAPABILITY_DISCOVERED, CAPABILITY_LOST, ExperienceStore
from .log import AppendOnlyLog
from .renewal import DEFAULT_VALIDITY, renew, verify_renewal
from .state import AgentState, save_identity
from .tiers import create_detail, create_sensitive
from .timestamps import now


class AgentAdapter(Protocol):
    """The one thing a harness needs from whatever AI it wraps: an
    honest, current list of what it can actually do right now. Anything
    else (how it decides, what it says, what it acts on) is the wrapped
    AI's own business, not the harness's."""

    def capabilities(self) -> list[str]: ...


class AgentHarness:
    def __init__(self, state_dir: Path, adapter: AgentAdapter | None = None) -> None:
        self.state = AgentState(state_dir)
        self.adapter = adapter
        self.action_log = AppendOnlyLog(self.state.action_log_path)
        self.experience = ExperienceStore(self.state.experience_path)

    @property
    def is_bootstrapped(self) -> bool:
        return self.state.identity_path.exists()

    @property
    def current_epoch(self) -> dict[str, Any]:
        chain = self.state.chain
        if not chain:
            raise AICError("harness.not_bootstrapped", "No epoch chain found; call bootstrap() first.")
        return chain[-1]

    # ------------------------------------------------------------------
    # Identity lifecycle
    # ------------------------------------------------------------------

    def bootstrap(
        self,
        display_name: str,
        purpose: str,
        declared_capabilities: list[str],
        *,
        operator: dict[str, Any] | None = None,
        protocols: list[str] | None = None,
        known_limitations: list[str] | None = None,
        sensitive: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """`sensitive`, if given, is the kwargs for `tiers.create_sensitive`
        (model_name, model_version, hardware, software_stack, ...) -- pass
        `provenance.collect_runtime_provenance()`'s output for `hardware`/
        `software_stack` to populate it honestly rather than by hand."""
        if self.is_bootstrapped:
            raise AICError("harness.already_bootstrapped", "This state directory already has an identity; use renew()/reconcile()/rotate_key() instead.")
        self.action_log.append("bootstrap.started", {"display_name": display_name})

        identity = AgentIdentity.generate()
        detail = create_detail(
            identity.agent_id, 0, identity, declared_capabilities,
            operator=operator, protocols=protocols, known_limitations=known_limitations,
        )
        sensitive_content = create_sensitive(identity.agent_id, 0, identity, **sensitive) if sensitive else None
        genesis = create_genesis_epoch(identity, display_name, purpose, detail, sensitive_content)

        save_identity(identity, self.state.identity_path)
        self.state.save_chain([genesis])
        self.state.save_detail(detail)
        if sensitive_content is not None:
            self.state.save_sensitive(sensitive_content)
        self.state.save_renewal(renew(genesis, identity))

        self.action_log.append("bootstrap.completed", {"agent_id": identity.agent_id, "epoch_digest": genesis["signature"]["value"][:16] + "..."})
        return genesis

    def ensure_live(self, validity: timedelta = DEFAULT_VALIDITY) -> dict[str, Any]:
        """Renew now if there is no renewal, or the existing one is
        invalid/expired -- the ongoing-operation half of HARNESS_
        BOOTSTRAP.md ss7's "check whether your renewal is still valid and
        renew if not." Safe to call on every startup."""
        epoch = self.current_epoch
        existing = self.state.renewal
        if existing is not None:
            try:
                verify_renewal(existing, epoch, at=now())
                return existing
            except AICError:
                pass
        return self.renew(validity)

    def renew(self, validity: timedelta = DEFAULT_VALIDITY) -> dict[str, Any]:
        renewal = renew(self.current_epoch, self.state.identity, validity)
        self.state.save_renewal(renewal)
        self.action_log.append("identity.renewed", {"valid_until": renewal["valid_until"]})
        return renewal

    def rotate_key(self) -> dict[str, Any]:
        old_identity = self.state.identity
        new_identity = AgentIdentity.generate()
        prior_epoch, prior_detail, prior_sensitive = self.current_epoch, self.state.detail, self.state.sensitive
        next_number = prior_epoch["epoch_number"] + 1

        detail = _resigned_for_next_epoch(prior_detail, next_number, new_identity)
        sensitive_content = _resigned_for_next_epoch(prior_sensitive, next_number, new_identity) if prior_sensitive else None
        epoch = create_successor_epoch(prior_epoch, old_identity, "key_rotation", detail, sensitive=sensitive_content, new_identity=new_identity)

        save_identity(new_identity, self.state.identity_path)
        self._commit_new_epoch(epoch, detail, sensitive_content, new_identity)
        self.action_log.append("identity.key_rotated", {"epoch_number": epoch["epoch_number"]})
        return epoch

    # ------------------------------------------------------------------
    # Action log / experience
    # ------------------------------------------------------------------

    def log_action(self, kind: str, detail: dict[str, Any]) -> dict[str, Any]:
        return self.action_log.append(kind, detail)

    def record_experience(self, kind: str, content: dict[str, Any]) -> dict[str, Any]:
        return self.experience.record(kind, content)

    # ------------------------------------------------------------------
    # Reconciliation: experience -> a card that keeps matching reality
    # ------------------------------------------------------------------

    def reconcile(self, *, auto_apply: bool = False) -> dict[str, Any]:
        """Compare the current Tier 2 content against (a) accumulated
        experience and (b) the attached adapter's live `capabilities()`,
        if any. Returns a report either way; only mints a new
        `capability_update` epoch (and re-signs Tier 3 forward) if
        `auto_apply` is True and something actually changed -- reconcile
        is safe to call speculatively/read-only as often as you like."""
        detail = self.state.detail
        if detail is None:
            raise AICError("harness.not_bootstrapped", "No Tier 2 detail found; call bootstrap() first.")
        baseline_capabilities = detail["declared_capabilities"]
        baseline_limitations = detail.get("known_limitations", [])

        if self.adapter is not None:
            live_capabilities = set(self.adapter.capabilities())
            for capability in sorted(live_capabilities - set(baseline_capabilities)):
                self.record_experience(CAPABILITY_DISCOVERED, {"capability": capability, "source": "adapter"})
            for capability in sorted(set(baseline_capabilities) - live_capabilities):
                self.record_experience(CAPABILITY_LOST, {"capability": capability, "source": "adapter"})

        new_capabilities = self.experience.derive_capability_set(baseline_capabilities)
        new_limitations = self.experience.derive_limitation_set(baseline_limitations)
        changed = new_capabilities != baseline_capabilities or new_limitations != baseline_limitations

        report: dict[str, Any] = {
            "changed": changed,
            "capabilities": {"before": baseline_capabilities, "after": new_capabilities},
            "limitations": {"before": baseline_limitations, "after": new_limitations},
        }
        if changed and auto_apply:
            epoch = self.update_capabilities(new_capabilities, new_limitations)
            report["new_epoch_number"] = epoch["epoch_number"]
            self.action_log.append("identity.reconciled", {"epoch_number": epoch["epoch_number"], "capabilities": new_capabilities, "limitations": new_limitations})
        return report

    def update_capabilities(self, declared_capabilities: list[str], known_limitations: list[str]) -> dict[str, Any]:
        """Mint a `capability_update` epoch directly with an explicit new
        declared_capabilities/known_limitations list. `reconcile(auto_apply=True)`
        is the usual, experience-driven way to reach this same outcome;
        this is the direct path for when you already know exactly what
        changed and don't need to consult accumulated experience first."""
        identity = self.state.identity
        prior_epoch, prior_detail, prior_sensitive = self.current_epoch, self.state.detail, self.state.sensitive
        next_number = prior_epoch["epoch_number"] + 1

        detail = create_detail(
            prior_epoch["agent_id"], next_number, identity, declared_capabilities,
            operator=prior_detail.get("operator"), protocols=prior_detail.get("protocols"), known_limitations=known_limitations,
        )
        sensitive_content = _resigned_for_next_epoch(prior_sensitive, next_number, identity) if prior_sensitive else None
        epoch = create_successor_epoch(prior_epoch, identity, "capability_update", detail, sensitive=sensitive_content)
        self._commit_new_epoch(epoch, detail, sensitive_content, identity)
        return epoch

    def _commit_new_epoch(self, epoch: dict[str, Any], detail: dict[str, Any], sensitive_content: dict[str, Any] | None, active_identity: AgentIdentity) -> None:
        """`active_identity` MUST hold the private key matching
        `epoch["public_key"]` -- the caller's job to ensure (and, for a
        key_rotation epoch, to have already persisted via save_identity
        before calling this, since renewal below needs it)."""
        chain = self.state.chain
        chain.append(epoch)
        self.state.save_chain(chain)
        self.state.save_detail(detail)
        if sensitive_content is not None:
            self.state.save_sensitive(sensitive_content)
        self.state.save_renewal(renew(epoch, active_identity))

    # ------------------------------------------------------------------
    # Delegation and sharing
    # ------------------------------------------------------------------

    def delegate(self, delegate_identity: AgentIdentity, scope_capability_prefixes: list[str], purpose: str, validity: timedelta, max_actions: int | None = None) -> dict[str, Any]:
        detail = self.state.detail
        if detail is None:
            raise AICError("harness.not_bootstrapped", "No Tier 2 detail found; call bootstrap() first.")
        delegate_card = create_delegate(self.current_epoch, detail, self.state.identity, delegate_identity, scope_capability_prefixes, purpose, validity, max_actions)
        self.action_log.append("delegate.issued", {"scope": scope_capability_prefixes, "purpose": purpose})
        return delegate_card

    def bundle(self, *, disclose_tier2: bool = True, disclose_tier3: bool = False, attestations: list[dict[str, Any]] | None = None, delegate: dict[str, Any] | None = None) -> dict[str, Any]:
        return build_bundle(
            self.state.chain,
            detail=self.state.detail if disclose_tier2 else None,
            sensitive=self.state.sensitive if disclose_tier3 else None,
            renewal=self.state.renewal,
            attestations=attestations,
            delegate=delegate,
        )


def _resigned_for_next_epoch(content: dict[str, Any], epoch_number: int, identity: AgentIdentity) -> dict[str, Any]:
    """Re-affirm Tier 2/3 content for a new epoch_number without changing
    anything else about it -- every epoch's tier commitments are epoch-
    scoped (epoch.py), so even an unchanged Tier 3 blob must be re-signed
    referencing the new epoch_number rather than silently carried over."""
    updated = {key: value for key, value in content.items() if key not in ("epoch_number", "signature")}
    updated["epoch_number"] = epoch_number
    return sign(updated, identity.private_key)
