"""`aic`: a reference command-line tool over the agent_id_card library --
init a lineage, renew it, rotate its key, update its capabilities, log
actions, record and reconcile experience, attest to someone else's, mint
a delegate, assemble a bundle, and verify one. Thin argument parsing over
`harness.AgentHarness` -- see that module for the actual logic."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

from .attestation import create_attestation
from .bundle import load_bundle, save_bundle
from .crypto import AgentIdentity
from .errors import AICError
from .harness import AgentHarness
from .render import render_text
from .renewal import DEFAULT_VALIDITY
from .state import save_identity
from .verify import verify_bundle


def _split_csv(value: str | None) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()] if value else []


def cmd_init(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    operator = json.loads(args.operator) if args.operator else None
    genesis = harness.bootstrap(
        args.name, args.purpose, _split_csv(args.capabilities),
        operator=operator, protocols=_split_csv(args.protocols), known_limitations=_split_csv(args.limitations),
    )
    print(f"agent_id: {genesis['agent_id']}")
    print(f"state saved under {harness.state.directory}")
    return 0


def cmd_renew(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    renewal = harness.renew(timedelta(hours=args.hours))
    print(f"renewed until {renewal['valid_until']}")
    return 0


def cmd_rotate_key(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    epoch = harness.rotate_key()
    print(f"rotated to epoch #{epoch['epoch_number']}")
    return 0


def cmd_update_capabilities(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    detail = harness.state.detail
    capabilities = _split_csv(args.capabilities) if args.capabilities else detail["declared_capabilities"]
    limitations = _split_csv(args.limitations) if args.limitations else detail.get("known_limitations", [])
    epoch = harness.update_capabilities(capabilities, limitations)
    print(f"updated to epoch #{epoch['epoch_number']}")
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    entry = harness.log_action(args.kind, json.loads(args.detail) if args.detail else {})
    print(f"logged seq {entry['seq']}: {entry['digest']}")
    return 0


def cmd_experience_record(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    entry = harness.record_experience(args.kind, json.loads(args.content) if args.content else {})
    print(f"recorded seq {entry['seq']}: {entry['digest']}")
    return 0


def cmd_experience_list(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    for entry in harness.experience.entries(args.kind):
        print(json.dumps(entry))
    return 0


def cmd_reconcile(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    report = harness.reconcile(auto_apply=args.apply)
    print(json.dumps(report, indent=2))
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    issuer_harness = AgentHarness(Path(args.state_dir))
    subject_bundle = load_bundle(Path(args.subject_bundle))
    subject_epoch = subject_bundle["epoch_chain"][-1]
    claim = json.loads(args.claim) if args.claim else {}
    attestation = create_attestation(
        subject_epoch["agent_id"], issuer_harness.state.identity, args.kind, claim,
        subject_epoch=subject_epoch if args.scope_to_epoch else None,
        expires_at=args.expires_at,
    )
    Path(args.out).write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
    print(f"wrote attestation ({args.kind}) to {args.out}")
    return 0


def cmd_delegate(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    delegate_identity = AgentIdentity.generate()
    delegate = harness.delegate(delegate_identity, _split_csv(args.scope), args.purpose, timedelta(hours=args.hours), max_actions=args.max_actions)
    Path(args.out).write_text(json.dumps(delegate, indent=2) + "\n", encoding="utf-8")
    save_identity(delegate_identity, Path(args.delegate_key_out))
    print(f"wrote delegate card to {args.out}, delegate key to {args.delegate_key_out}")
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    harness = AgentHarness(Path(args.state_dir))
    attestations: list[dict[str, Any]] = [json.loads(Path(path).read_text(encoding="utf-8")) for path in _split_csv(args.attestations)]
    delegate = json.loads(Path(args.delegate).read_text(encoding="utf-8")) if args.delegate else None
    bundle = harness.bundle(disclose_tier2=not args.tier1_only, disclose_tier3=args.disclose_tier3, attestations=attestations, delegate=delegate)
    save_bundle(bundle, Path(args.out))
    print(f"wrote bundle to {args.out} (disclosed tiers: {bundle['disclosed_tiers']})")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.bundle))
    result = verify_bundle(bundle, require_live=not args.no_require_live, trusted_revokers=set(_split_csv(args.trusted_revokers)) or None)
    print(render_text(result))
    return 0 if result.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aic", description="Agent ID Card: a living, self-renewing identity chain for autonomous agents.")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Generate a new agent identity (genesis epoch, Tier 1/2).")
    init.add_argument("--state-dir", required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--purpose", required=True)
    init.add_argument("--capabilities", help="comma-separated capability ids this agent actually has right now")
    init.add_argument("--limitations", help="comma-separated known limitations")
    init.add_argument("--protocols", help="comma-separated agent-to-agent protocols spoken")
    init.add_argument("--operator", help="JSON object describing who operates this agent")
    init.set_defaults(func=cmd_init)

    renew_parser = sub.add_parser("renew", help="Heartbeat: extend the current epoch's liveness window.")
    renew_parser.add_argument("--state-dir", required=True)
    renew_parser.add_argument("--hours", type=float, default=DEFAULT_VALIDITY.total_seconds() / 3600)
    renew_parser.set_defaults(func=cmd_renew)

    rotate = sub.add_parser("rotate-key", help="Mint a key_rotation epoch (compromise recovery or routine rotation).")
    rotate.add_argument("--state-dir", required=True)
    rotate.set_defaults(func=cmd_rotate_key)

    update = sub.add_parser("update-capabilities", help="Mint a capability_update epoch directly (see also `reconcile`).")
    update.add_argument("--state-dir", required=True)
    update.add_argument("--capabilities", help="comma-separated; replaces the declared list")
    update.add_argument("--limitations", help="comma-separated; replaces known_limitations")
    update.set_defaults(func=cmd_update_capabilities)

    log = sub.add_parser("log", help="Append one entry to the action log -- every movement (HARNESS_BOOTSTRAP.md ss4).")
    log.add_argument("--state-dir", required=True)
    log.add_argument("kind")
    log.add_argument("--detail", help="JSON object")
    log.set_defaults(func=cmd_log)

    experience = sub.add_parser("experience", help="Record or list experience entries (experience.py).")
    experience_sub = experience.add_subparsers(dest="experience_command", required=True)
    record = experience_sub.add_parser("record")
    record.add_argument("--state-dir", required=True)
    record.add_argument("kind")
    record.add_argument("--content", help="JSON object")
    record.set_defaults(func=cmd_experience_record)
    listing = experience_sub.add_parser("list")
    listing.add_argument("--state-dir", required=True)
    listing.add_argument("--kind")
    listing.set_defaults(func=cmd_experience_list)

    reconcile = sub.add_parser("reconcile", help="Compare recorded experience (and an attached adapter, if any) against the current card; optionally mint an update.")
    reconcile.add_argument("--state-dir", required=True)
    reconcile.add_argument("--apply", action="store_true", help="mint a capability_update epoch if anything changed")
    reconcile.set_defaults(func=cmd_reconcile)

    attest = sub.add_parser("attest", help="Issue a signed attestation about someone else's bundle.")
    attest.add_argument("--state-dir", required=True, help="the ISSUER's own state dir")
    attest.add_argument("--subject-bundle", required=True)
    attest.add_argument("--kind", required=True)
    attest.add_argument("--claim", help="JSON object")
    attest.add_argument("--scope-to-epoch", action="store_true")
    attest.add_argument("--expires-at")
    attest.add_argument("--out", required=True)
    attest.set_defaults(func=cmd_attest)

    delegate = sub.add_parser("delegate", help="Mint a short-lived, capability-narrowed delegate card.")
    delegate.add_argument("--state-dir", required=True)
    delegate.add_argument("--scope", required=True, help="comma-separated capability prefixes, must narrow the parent's")
    delegate.add_argument("--purpose", required=True)
    delegate.add_argument("--hours", type=float, required=True)
    delegate.add_argument("--max-actions", type=int)
    delegate.add_argument("--out", required=True)
    delegate.add_argument("--delegate-key-out", required=True)
    delegate.set_defaults(func=cmd_delegate)

    bundle = sub.add_parser("bundle", help="Assemble a shareable bundle from local state.")
    bundle.add_argument("--state-dir", required=True)
    bundle.add_argument("--tier1-only", action="store_true", help="omit Tier 2 detail even though it exists locally")
    bundle.add_argument("--disclose-tier3", action="store_true", help="include Tier 3 sensitive content")
    bundle.add_argument("--attestations", help="comma-separated attestation JSON file paths")
    bundle.add_argument("--delegate", help="delegate card JSON file path")
    bundle.add_argument("--out", required=True)
    bundle.set_defaults(func=cmd_bundle)

    verify = sub.add_parser("verify", help="Verify a bundle and print a report.")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--no-require-live", action="store_true")
    verify.add_argument("--trusted-revokers", help="comma-separated agent_ids whose revocation attestations are honored")
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        sys.exit(args.func(args))
    except AICError as error:
        print(f"error: {error.code}: {error.detail}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
