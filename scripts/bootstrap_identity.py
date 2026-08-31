#!/usr/bin/env python3
"""Reference implementation of HARNESS_BOOTSTRAP.md's discovery + identity
generation steps. Run this once, the first time a coding-agent harness
operates in a new environment/workspace, to produce a real, signed AIC
genesis epoch (Tier 1/2/3) plus the first entries of an append-only,
hash-chained action log -- see HARNESS_BOOTSTRAP.md for the full
procedure this implements and for what to do with the result.

This script is a convenience, not a dependency of `agent_id_card` itself
-- it only imports the library's existing crypto primitives (nothing here
required changing the core package). If your harness's runtime is not
Python, read this file as a worked example of the exact procedure to
reimplement: everything it does is fully specified in SPEC.md.

Usage:
    python3 scripts/bootstrap_identity.py --state-dir .aic \
        --purpose "Assists with development in this repository." \
        --extra-packages cryptography,rfc8785

Safe to re-run: refuses to overwrite an existing identity (use the `aic`
CLI's `renew`/`update-capabilities`/`rotate-key` commands for an agent
that already has one -- see README.md).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_id_card.crypto import AgentIdentity, digest_of, sign  # noqa: E402
from agent_id_card.timestamps import stamp  # noqa: E402

UNKNOWN = "unknown"
COMMON_RUNTIMES = ["python3", "node", "go", "rustc", "java", "ruby", "php", "dotnet"]
COMMON_TOOLS = ["git", "docker", "kubectl", "uv", "pip", "npm", "cargo", "make", "curl", "openssl"]


# --------------------------------------------------------------------------
# 1. Curiosity: environment discovery. Every function here is best-effort
#    and MUST degrade to "unknown" (or an empty list) rather than raise --
#    a locked-down sandbox with no subprocess access at all is a valid,
#    expected environment to discover, not an error.
# --------------------------------------------------------------------------

def _safe_run(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _version_of(binary: str) -> str:
    for flag in ("--version", "-version", "version"):
        output = _safe_run([binary, flag])
        if output:
            return output.splitlines()[0][:200]
    return UNKNOWN


def discover_hardware() -> dict[str, Any]:
    nvidia = _safe_run(["nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"])
    if nvidia:
        name, _, driver = nvidia.splitlines()[0].partition(",")
        accelerator, driver_version = name.strip(), driver.strip() or UNKNOWN
    else:
        accelerator, driver_version = "cpu-only", "n/a"
    try:
        disk = shutil.disk_usage(".")
        disk_free_gb = round(disk.free / (1024**3), 1)
    except OSError:
        disk_free_gb = UNKNOWN
    return {
        "cpu": platform.processor() or platform.machine() or UNKNOWN,
        "cpu_count": os.cpu_count() or UNKNOWN,
        "os": platform.system() or UNKNOWN,
        "os_version": platform.release() or UNKNOWN,
        "accelerator": accelerator,
        "accelerator_driver_version": driver_version,
        "disk_free_gb": disk_free_gb,
    }


def discover_software_stack(extra_packages: list[str]) -> dict[str, Any]:
    runtimes = {name: _version_of(name) for name in COMMON_RUNTIMES if shutil.which(name)}
    tools = {name: _version_of(name) for name in COMMON_TOOLS if shutil.which(name)}
    library_versions: dict[str, str] = {}
    from importlib import metadata

    for package in extra_packages:
        try:
            library_versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            library_versions[package] = UNKNOWN
    return {
        "runtime": "cpython" if platform.python_implementation() == "CPython" else platform.python_implementation().lower(),
        "runtime_version": platform.python_version(),
        "available_language_runtimes": runtimes,
        "available_tools": tools,
        "library_versions": library_versions,
    }


def discover_permissions_and_network() -> dict[str, Any]:
    try:
        uid = os.getuid()
        running_as_root = uid == 0
    except AttributeError:
        uid, running_as_root = UNKNOWN, UNKNOWN
    try:
        socket.setdefaulttimeout(2)
        socket.gethostbyname("github.com")
        network_reachable = True
    except OSError:
        network_reachable = False
    sandbox_hints = [key for key in ("CI", "CODESPACES", "GITPOD_WORKSPACE_ID", "DOCKER_CONTAINER", "container") if os.environ.get(key)]
    return {"uid": uid, "running_as_root": running_as_root, "network_reachable": network_reachable, "sandbox_hints": sandbox_hints}


def infer_purpose(explicit_purpose: str | None) -> str:
    if explicit_purpose:
        return explicit_purpose
    for candidate, key in ((Path("package.json"), "description"), (Path("pyproject.toml"), None)):
        if candidate.exists():
            try:
                text = candidate.read_text(encoding="utf-8")
                if key:
                    data = json.loads(text)
                    if data.get(key):
                        return str(data[key])[:300]
                elif "description" in text:
                    for line in text.splitlines():
                        if line.strip().startswith("description"):
                            return line.split("=", 1)[-1].strip().strip('"\'')[:300]
            except (OSError, json.JSONDecodeError):
                continue
    return "Purpose not yet determined -- ask the operator, then mint a capability_update epoch with the real answer."


# --------------------------------------------------------------------------
# 2. Append-only, hash-chained action log (see HARNESS_BOOTSTRAP.md ss4).
# --------------------------------------------------------------------------

class ActionLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._last_digest: str | None = None
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._last_digest = json.loads(line)["digest"]

    def append(self, kind: str, detail: dict[str, Any]) -> dict[str, Any]:
        entry = {"seq": self._next_seq(), "at": stamp(), "kind": kind, "detail": detail, "prev_digest": self._last_digest}
        entry["digest"] = digest_of(entry)  # computed before "digest" itself exists in the dict
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        os.chmod(self.path, 0o644)
        self._last_digest = entry["digest"]
        return entry

    def _next_seq(self) -> int:
        if not self.path.exists():
            return 0
        return sum(1 for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip())


# --------------------------------------------------------------------------
# 3. Build and sign the genesis epoch (Tier 1/2/3), per SPEC.md ss3.1/ss5.
# --------------------------------------------------------------------------

def derive_capability_categories(declared_capabilities: list[str]) -> list[str]:
    return sorted({capability.split(".", 1)[0] for capability in declared_capabilities if capability})


def bootstrap(state_dir: Path, display_name: str, purpose: str, declared_capabilities: list[str], known_limitations: list[str], extra_packages: list[str]) -> None:
    if (state_dir / "identity.json").exists():
        raise SystemExit(f"{state_dir / 'identity.json'} already exists -- this agent already has an identity. Use the `aic` CLI to renew/update/rotate it instead.")

    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    log = ActionLog(state_dir / "action_log.jsonl")
    log.append("bootstrap.started", {"argv": sys.argv[1:]})

    hardware = discover_hardware()
    software_stack = discover_software_stack(extra_packages)
    permissions = discover_permissions_and_network()
    log.append("environment.discovered", {"hardware": hardware, "software_stack": software_stack, "permissions": permissions})

    identity = AgentIdentity.generate()

    detail = sign({
        "aic": "1.0", "type": "tier2_detail",
        "agent_id": identity.agent_id, "epoch_number": 0,
        "declared_capabilities": declared_capabilities,
        "operator": None,
        "protocols": [],
        "known_limitations": known_limitations,
        "issued_at": stamp(),
    }, identity.private_key)

    sensitive = sign({
        "aic": "1.0", "type": "tier3_sensitive",
        "agent_id": identity.agent_id, "epoch_number": 0,
        "model_name": UNKNOWN, "model_version": UNKNOWN, "weights_digest": None, "base_model": None,
        "hardware": hardware, "software_stack": software_stack, "build_reference": None,
        "issued_at": stamp(),
    }, identity.private_key)

    genesis = sign({
        "aic": "1.0", "type": "epoch",
        "agent_id": identity.agent_id, "epoch_number": 0, "transition": "genesis", "prior_epoch_digest": None,
        "public_key": identity.public_b64,
        "display_name": display_name,
        "purpose": purpose,
        "capability_categories": derive_capability_categories(declared_capabilities),
        "detailed_digest": digest_of(detail),
        "sensitive_digest": digest_of(sensitive),
        "issued_at": stamp(),
    }, identity.private_key)

    log.append("identity.generated", {"agent_id": identity.agent_id, "epoch_digest": digest_of(genesis)})

    (state_dir / "identity.json").write_text(json.dumps({"agent_id": identity.agent_id, "public_key": identity.public_b64, "private_key": identity.private_b64}) + "\n", encoding="utf-8")
    os.chmod(state_dir / "identity.json", 0o600)
    (state_dir / "chain.json").write_text(json.dumps([genesis], indent=2) + "\n", encoding="utf-8")
    (state_dir / "detail.json").write_text(json.dumps(detail, indent=2) + "\n", encoding="utf-8")
    (state_dir / "sensitive.json").write_text(json.dumps(sensitive, indent=2) + "\n", encoding="utf-8")

    log.append("bootstrap.completed", {"agent_id": identity.agent_id})

    print(f"agent_id: {identity.agent_id}")
    print(f"purpose:  {purpose}")
    print(f"capability_categories: {genesis['capability_categories']}")
    print(f"state + action log saved under {state_dir}/")
    print("Waiting for instructions.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--state-dir", type=Path, default=Path(".aic"))
    parser.add_argument("--name", default=f"{platform.node() or 'agent'}")
    parser.add_argument("--purpose")
    parser.add_argument("--capabilities", default="", help="comma-separated declared capability ids/prefixes")
    parser.add_argument("--limitations", default="", help="comma-separated known limitations, in addition to the discovered environment")
    parser.add_argument("--extra-packages", default="", help="comma-separated PyPI package names to report exact installed versions for")
    args = parser.parse_args()

    bootstrap(
        args.state_dir,
        args.name,
        infer_purpose(args.purpose),
        [item.strip() for item in args.capabilities.split(",") if item.strip()],
        [item.strip() for item in args.limitations.split(",") if item.strip()],
        [item.strip() for item in args.extra_packages.split(",") if item.strip()],
    )


if __name__ == "__main__":
    main()
