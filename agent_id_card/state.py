"""Local on-disk state for one agent's own identity: private key, epoch
chain, and latest renewal. Deliberately separate from `bundle.py` (which
is the shareable, no-private-key artifact) -- this module is the only
place a private key touches disk, and it always does so at 0600."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .crypto import AgentIdentity, unb64


def _atomic_write(path: Path, text: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def save_identity(identity: AgentIdentity, path: Path) -> None:
    _atomic_write(path, json.dumps({"agent_id": identity.agent_id, "public_key": identity.public_b64, "private_key": identity.private_b64}) + "\n")


def load_identity(path: Path) -> AgentIdentity:
    record = json.loads(path.read_text(encoding="utf-8"))
    return AgentIdentity.from_private_bytes(unb64(record["private_key"]))


def save_json(value: Any, path: Path) -> None:
    _atomic_write(path, json.dumps(value, indent=2) + "\n", mode=0o644)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


class AgentState:
    """The on-disk files that make up one agent's local state directory:
    identity (private key), the epoch chain, the latest Tier 2/3 content,
    the latest renewal, received attestations, and (via `harness.py`) the
    append-only action log and experience store."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.identity_path = directory / "identity.json"
        self.chain_path = directory / "chain.json"
        self.detail_path = directory / "detail.json"
        self.sensitive_path = directory / "sensitive.json"
        self.renewal_path = directory / "renewal.json"
        self.attestations_path = directory / "attestations_received.json"
        self.action_log_path = directory / "action_log.jsonl"
        self.experience_path = directory / "experience.jsonl"

    @property
    def identity(self) -> AgentIdentity:
        return load_identity(self.identity_path)

    @property
    def chain(self) -> list[dict[str, Any]]:
        return load_json(self.chain_path, [])

    def save_chain(self, chain: list[dict[str, Any]]) -> None:
        save_json(chain, self.chain_path)

    @property
    def detail(self) -> dict[str, Any] | None:
        return load_json(self.detail_path, None)

    def save_detail(self, detail: dict[str, Any]) -> None:
        save_json(detail, self.detail_path)

    @property
    def sensitive(self) -> dict[str, Any] | None:
        return load_json(self.sensitive_path, None)

    def save_sensitive(self, sensitive: dict[str, Any]) -> None:
        save_json(sensitive, self.sensitive_path)

    @property
    def renewal(self) -> dict[str, Any] | None:
        return load_json(self.renewal_path, None)

    def save_renewal(self, renewal: dict[str, Any]) -> None:
        save_json(renewal, self.renewal_path)

    @property
    def attestations_received(self) -> list[dict[str, Any]]:
        return load_json(self.attestations_path, [])

    def add_attestation_received(self, attestation: dict[str, Any]) -> None:
        attestations = self.attestations_received
        attestations.append(attestation)
        save_json(attestations, self.attestations_path)
