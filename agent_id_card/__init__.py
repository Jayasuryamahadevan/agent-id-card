"""AIC: a living, self-renewing identity chain for autonomous agents.

Quick tour:
  - `epoch.py`       identity content, hash-chained across its whole life
  - `renewal.py`      the cheap heartbeat that makes liveness separable
                       from identity content (no revocation list needed
                       for the common "it just went away" case)
  - `attestation.py`  independent, appendable third-party claims
                       (web of trust, not one certificate authority)
  - `delegate.py`     short-lived, capability-narrowed sub-identities
  - `bundle.py`        the one JSON object actually exchanged/shown
  - `verify.py`        turns a bundle into a structured verification report
"""

from __future__ import annotations

from .attestation import WELL_KNOWN_KINDS, create_attestation, verify_attestation
from .bundle import build_bundle, load_bundle, save_bundle
from .crypto import AgentIdentity
from .delegate import create_delegate, delegate_permits, verify_delegate
from .epoch import create_genesis_epoch, create_successor_epoch, verify_epoch
from .errors import AICError
from .renewal import renew, verify_renewal
from .verify import AttestationCheck, VerificationResult, verify_bundle

__all__ = [
    "WELL_KNOWN_KINDS",
    "AICError",
    "AgentIdentity",
    "AttestationCheck",
    "VerificationResult",
    "build_bundle",
    "create_attestation",
    "create_delegate",
    "create_genesis_epoch",
    "create_successor_epoch",
    "delegate_permits",
    "load_bundle",
    "renew",
    "save_bundle",
    "verify_attestation",
    "verify_bundle",
    "verify_delegate",
    "verify_epoch",
    "verify_renewal",
]
