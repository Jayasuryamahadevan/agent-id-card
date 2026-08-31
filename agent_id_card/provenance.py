"""Automatic runtime provenance collection, for Tier 3 ("sensitive")
content -- see `tiers.py` and HARNESS_BOOTSTRAP.md.

The point of this module is to make lying by omission hard: rather than
hand-typing "torch 2.3" and trusting someone remembers to update it,
`collect_runtime_provenance()` actually introspects the process it's
called from. A field that genuinely cannot be determined on this
platform is reported as the literal string `"unknown"`, never simply
left out -- an absent key looks identical to "we forgot to check"; an
explicit "unknown" value looks identical to "we checked and could not
tell," which is the honest state of affairs and is itself falsifiable
(a verifier who happens to know better can call it out).

Every subprocess/library call here is wrapped and degrades to "unknown"
rather than raising -- this MUST be safe to call on a bare Raspberry Pi
with no GPU, inside a container with no `nvidia-smi`, or in a locked-down
sandbox with no subprocess access at all.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
from importlib import metadata
from typing import Any

UNKNOWN = "unknown"
COMMON_RUNTIMES = ["python3", "node", "go", "rustc", "java", "ruby", "php", "dotnet"]
COMMON_TOOLS = ["git", "docker", "kubectl", "uv", "pip", "npm", "cargo", "make", "curl", "openssl"]


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
        disk_free_gb = round(shutil.disk_usage(".").free / (1024**3), 1)
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


def discover_software_stack(extra_packages: list[str] | None = None) -> dict[str, Any]:
    runtimes = {name: _version_of(name) for name in COMMON_RUNTIMES if shutil.which(name)}
    tools = {name: _version_of(name) for name in COMMON_TOOLS if shutil.which(name)}
    library_versions: dict[str, str] = {}
    for package in extra_packages or []:
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
        uid: Any = os.getuid()
        running_as_root: Any = uid == 0
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


def collect_runtime_provenance(extra_packages: list[str] | None = None) -> dict[str, dict[str, Any]]:
    """Introspect THIS process's actual runtime -- OS, CPU, accelerator,
    driver, interpreter, and any caller-named library versions. Returns
    `{"hardware": ..., "software_stack": ...}`, ready to spread into
    `AgentHarness.bootstrap(..., sensitive={...})`."""
    return {"hardware": discover_hardware(), "software_stack": discover_software_stack(extra_packages)}


def infer_purpose(explicit_purpose: str | None, workspace: str = ".") -> str:
    """Best-effort inference from the actual workspace -- README/package
    metadata -- never invented. Falls back to an honest "not yet
    determined" rather than a generic placeholder purpose."""
    import json as _json
    from pathlib import Path as _Path

    if explicit_purpose:
        return explicit_purpose
    root = _Path(workspace)
    package_json = root / "package.json"
    if package_json.exists():
        try:
            data = _json.loads(package_json.read_text(encoding="utf-8"))
            if data.get("description"):
                return str(data["description"])[:300]
        except (OSError, _json.JSONDecodeError):
            pass
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            for line in pyproject.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("description"):
                    return line.split("=", 1)[-1].strip().strip("\"'")[:300]
        except OSError:
            pass
    return "Purpose not yet determined -- ask the operator, then mint a capability_update epoch with the real answer."
