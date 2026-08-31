"""`aic`: a reference command-line tool over the agent_id_card library --
init a lineage, renew it, rotate its key, update its capabilities, attest
to someone else's, mint a delegate, assemble a bundle, and verify one."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

from .attestation import create_attestation
from .bundle import build_bundle, load_bundle, save_bundle
from .crypto import AgentIdentity
from .delegate import create_delegate
from .epoch import create_genesis_epoch, create_successor_epoch
from .errors import AICError
from .render import render_text
from .renewal import DEFAULT_VALIDITY, renew
from .state import AgentState, save_identity
from .verify import verify_bundle


def _split_csv(value: str | None) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()] if value else []


def cmd_init(args: argparse.Namespace) -> int:
    state = AgentState(Path(args.state_dir))
    if state.identity_path.exists():
        print(f"error: {state.identity_path} already exists -- this agent already has an identity.", file=sys.stderr)
        return 1
    identity = AgentIdentity.generate()
    genesis = create_genesis_epoch(identity, args.name, args.purpose, _split_csv(args.capabilities))
    save_identity(identity, state.identity_path)
    state.save_chain([genesis])
    state.save_renewal(renew(genesis, identity, timedelta(hours=args.renew_hours)))
    print(f"agent_id: {identity.agent_id}")
    print(f"state saved under {state.directory}")
    return 0


def cmd_renew(args: argparse.Namespace) -> int:
    state = AgentState(Path(args.state_dir))
    identity, chain = state.identity, state.chain
    renewal = renew(chain[-1], identity, timedelta(hours=args.hours))
    state.save_renewal(renewal)
    print(f"renewed until {renewal['valid_until']}")
    return 0


def cmd_rotate_key(args: argparse.Namespace) -> int:
    state = AgentState(Path(args.state_dir))
    old_identity, chain = state.identity, state.chain
    new_identity = AgentIdentity.generate()
    successor = create_successor_epoch(chain[-1], old_identity, "key_rotation", new_identity=new_identity)
    state.save_chain([*chain, successor])
    save_identity(new_identity, state.identity_path)
    (state.directory / f"identity.epoch{chain[-1]['epoch_number']}.json").write_text(
        json.dumps({"agent_id": old_identity.agent_id, "public_key": old_identity.public_b64}) + "\n", encoding="utf-8"
    )
    state.save_renewal(renew(successor, new_identity, DEFAULT_VALIDITY))
    print(f"rotated to epoch #{successor['epoch_number']}")
    return 0


def cmd_update_capabilities(args: argparse.Namespace) -> int:
    state = AgentState(Path(args.state_dir))
    identity, chain = state.identity, state.chain
    successor = create_successor_epoch(
        chain[-1], identity, "capability_update",
        purpose=args.purpose, display_name=args.name,
        declared_capabilities=_split_csv(args.capabilities) if args.capabilities else None,
    )
    state.save_chain([*chain, successor])
    state.save_renewal(renew(successor, identity, DEFAULT_VALIDITY))
    print(f"updated to epoch #{successor['epoch_number']}")
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    issuer_state = AgentState(Path(args.state_dir))
    issuer_identity = issuer_state.identity
    subject_bundle = load_bundle(Path(args.subject_bundle))
    subject_epoch = subject_bundle["epoch_chain"][-1]
    claim = json.loads(args.claim) if args.claim else {}
    attestation = create_attestation(
        subject_epoch["agent_id"], issuer_identity, args.kind, claim,
        subject_epoch=subject_epoch if args.scope_to_epoch else None,
        expires_at=args.expires_at,
    )
    Path(args.out).write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
    print(f"wrote attestation ({args.kind}) to {args.out}")
    return 0


def cmd_delegate(args: argparse.Namespace) -> int:
    state = AgentState(Path(args.state_dir))
    identity, chain = state.identity, state.chain
    delegate_identity = AgentIdentity.generate()
    delegate = create_delegate(
        chain[-1], identity, delegate_identity, _split_csv(args.scope), args.purpose,
        timedelta(hours=args.hours), max_actions=args.max_actions,
    )
    Path(args.out).write_text(json.dumps(delegate, indent=2) + "\n", encoding="utf-8")
    save_identity(delegate_identity, Path(args.delegate_key_out))
    print(f"wrote delegate card to {args.out}, delegate key to {args.delegate_key_out}")
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    state = AgentState(Path(args.state_dir))
    attestations: list[dict[str, Any]] = [json.loads(Path(path).read_text(encoding="utf-8")) for path in _split_csv(args.attestations)]
    delegate = json.loads(Path(args.delegate).read_text(encoding="utf-8")) if args.delegate else None
    bundle = build_bundle(state.chain, renewal=state.renewal, attestations=attestations, delegate=delegate)
    save_bundle(bundle, Path(args.out))
    print(f"wrote bundle to {args.out}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    bundle = load_bundle(Path(args.bundle))
    result = verify_bundle(bundle, require_live=not args.no_require_live, trusted_revokers=set(_split_csv(args.trusted_revokers)) or None)
    print(render_text(result))
    return 0 if result.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aic", description="Agent ID Card: a living, self-renewing identity chain for autonomous agents.")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Generate a new agent identity (genesis epoch).")
    init.add_argument("--state-dir", required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--purpose", required=True)
    init.add_argument("--capabilities", help="comma-separated capability prefixes/ids")
    init.add_argument("--renew-hours", type=float, default=DEFAULT_VALIDITY.total_seconds() / 3600)
    init.set_defaults(func=cmd_init)

    renew_parser = sub.add_parser("renew", help="Heartbeat: extend the current epoch's liveness window.")
    renew_parser.add_argument("--state-dir", required=True)
    renew_parser.add_argument("--hours", type=float, default=DEFAULT_VALIDITY.total_seconds() / 3600)
    renew_parser.set_defaults(func=cmd_renew)

    rotate = sub.add_parser("rotate-key", help="Mint a key_rotation epoch (compromise recovery or routine rotation).")
    rotate.add_argument("--state-dir", required=True)
    rotate.set_defaults(func=cmd_rotate_key)

    update = sub.add_parser("update-capabilities", help="Mint a capability_update epoch.")
    update.add_argument("--state-dir", required=True)
    update.add_argument("--name")
    update.add_argument("--purpose")
    update.add_argument("--capabilities", help="comma-separated; replaces the declared list")
    update.set_defaults(func=cmd_update_capabilities)

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
