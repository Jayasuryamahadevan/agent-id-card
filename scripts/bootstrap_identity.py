#!/usr/bin/env python3
"""Reference implementation of HARNESS_BOOTSTRAP.md's discovery + identity
generation steps, using `agent_id_card.harness.AgentHarness` and
`agent_id_card.provenance`. Run this once, the first time a coding-agent
harness operates in a new environment/workspace, to produce a real,
signed AIC genesis epoch (Tier 1/2/3) plus the first entries of an
append-only, hash-chained action log.

If your harness's runtime is not Python, read this file (and
harness.py/provenance.py/log.py) as a worked example of the exact
procedure to reimplement -- everything it does is fully specified in
SPEC.md, and NO_PYTHON.md covers the common case of having no Python
interpreter available at all.

Usage:
    python3 scripts/bootstrap_identity.py --state-dir .aic \
        --purpose "Assists with development in this repository." \
        --extra-packages cryptography,rfc8785

Safe to re-run: refuses to overwrite an existing identity (use the `aic`
CLI's `renew`/`update-capabilities`/`rotate-key`/`reconcile` commands for
an agent that already has one -- see README.md).
"""

from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_id_card.harness import AgentHarness  # noqa: E402
from agent_id_card.provenance import collect_runtime_provenance, infer_purpose  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--state-dir", type=Path, default=Path(".aic"))
    parser.add_argument("--name", default=platform.node() or "agent")
    parser.add_argument("--purpose")
    parser.add_argument("--capabilities", default="", help="comma-separated declared capability ids/prefixes")
    parser.add_argument("--limitations", default="", help="comma-separated known limitations, in addition to the discovered environment")
    parser.add_argument("--extra-packages", default="", help="comma-separated PyPI package names to report exact installed versions for")
    parser.add_argument("--model-name", default="unknown")
    parser.add_argument("--model-version", default="unknown")
    args = parser.parse_args()

    def split(value: str) -> list[str]:
        return [item.strip() for item in value.split(",") if item.strip()]

    harness = AgentHarness(args.state_dir)
    if harness.is_bootstrapped:
        raise SystemExit(f"{harness.state.identity_path} already exists -- this agent already has an identity. Use the `aic` CLI to renew/update/rotate/reconcile it instead.")

    harness.log_action("bootstrap.started", {"argv": sys.argv[1:]})
    provenance = collect_runtime_provenance(split(args.extra_packages))
    harness.log_action("environment.discovered", provenance)

    genesis = harness.bootstrap(
        args.name,
        infer_purpose(args.purpose),
        split(args.capabilities),
        known_limitations=split(args.limitations),
        sensitive={"model_name": args.model_name, "model_version": args.model_version, **provenance},
    )
    harness.log_action("bootstrap.completed", {"agent_id": genesis["agent_id"]})

    print(f"agent_id: {genesis['agent_id']}")
    print(f"purpose:  {genesis['purpose']}")
    print(f"capability_categories: {genesis['capability_categories']}")
    print(f"state + action log saved under {harness.state.directory}/")
    print("Waiting for instructions.")


if __name__ == "__main__":
    main()
