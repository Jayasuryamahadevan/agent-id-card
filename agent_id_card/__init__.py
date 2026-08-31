"""AIC: a living, self-renewing identity chain for autonomous agents.

Quick tour:
  - `epoch.py`        Tier 1 identity content, hash-chained across its
                       whole life
  - `tiers.py`         Tier 2 (detailed) and Tier 3 (sensitive) content,
                       digest-committed by the epoch rather than embedded
  - `renewal.py`       the cheap heartbeat that makes liveness separable
                       from identity content (no revocation list needed
                       for the common "it just went away" case)
  - `attestation.py`   independent, appendable third-party claims
                       (web of trust, not one certificate authority)
  - `delegate.py`      short-lived, capability-narrowed sub-identities
  - `bundle.py`        the one JSON object actually exchanged/shown
  - `verify.py`        turns a bundle into a structured verification report
  - `log.py`           a generic append-only, hash-chained JSON Lines log
  - `experience.py`    what an agent has learned about itself over time
  - `harness.py`       AgentHarness -- ties identity, the action log, and
                       experience-driven reconciliation into one runtime
"""

from __future__ import annotations

from .attestation import WELL_KNOWN_KINDS, create_attestation, verify_attestation
from .bundle import build_bundle, load_bundle, save_bundle
from .crypto import AgentIdentity
from .delegate import create_delegate, delegate_permits, verify_delegate
from .epoch import create_genesis_epoch, create_successor_epoch, verify_epoch
from .errors import AICError
from .experience import ExperienceStore
from .harness import AgentAdapter, AgentHarness
from .log import AppendOnlyLog
from .renewal import renew, verify_renewal
from .tiers import create_detail, create_sensitive, derive_capability_categories, verify_detail, verify_sensitive
from .verify import AttestationCheck, VerificationResult, verify_bundle

__all__ = [
    "WELL_KNOWN_KINDS",
    "AICError",
    "AgentAdapter",
    "AgentHarness",
    "AgentIdentity",
    "AppendOnlyLog",
    "AttestationCheck",
    "ExperienceStore",
    "VerificationResult",
    "build_bundle",
    "create_attestation",
    "create_delegate",
    "create_detail",
    "create_genesis_epoch",
    "create_sensitive",
    "create_successor_epoch",
    "delegate_permits",
    "derive_capability_categories",
    "load_bundle",
    "renew",
    "save_bundle",
    "verify_attestation",
    "verify_bundle",
    "verify_delegate",
    "verify_detail",
    "verify_epoch",
    "verify_renewal",
    "verify_sensitive",
]
