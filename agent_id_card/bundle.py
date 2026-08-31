"""A bundle is the one JSON object actually exchanged between agents or
shown to a human: a full epoch chain plus whatever Tier 2/3 content,
renewal, attestations, and delegate card the presenter chooses to
include. `verify.py` consumes exactly this shape. See SPEC.md ss9."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def build_bundle(
    epoch_chain: list[dict[str, Any]],
    *,
    detail: dict[str, Any] | None = None,
    sensitive: dict[str, Any] | None = None,
    renewal: dict[str, Any] | None = None,
    attestations: list[dict[str, Any]] | None = None,
    delegate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    disclosed_tiers = [1]
    if detail is not None:
        disclosed_tiers.append(2)
    if sensitive is not None:
        disclosed_tiers.append(3)
    return {
        "aic": "1.0",
        "type": "bundle",
        "disclosed_tiers": disclosed_tiers,
        "epoch_chain": epoch_chain,
        "detail": detail,
        "sensitive": sensitive,
        "renewal": renewal,
        "attestations": attestations or [],
        "delegate": delegate,
    }


def save_bundle(bundle: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(bundle, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def load_bundle(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
