"""Ed25519 signing over RFC 8785 canonical bytes, and agent-key identity.

Every AIC object (epoch, renewal, attestation, delegate card) is a plain
dict signed the same way: canonicalize the object with its `signature`
key removed, sign those bytes, attach `signature: {"alg", "value"}`. Who
the signer *is* (which public key to verify against) is never embedded
in the signature block itself -- it always comes from context (the
object's own `public_key` field for a self-signature, the prior epoch's
key for a predecessor signature, the issuer's known key for an
attestation, the parent epoch's key for a delegate grant). That keeps a
signature block minimal and forces every verifier to be explicit about
*why* a given key is the right one to check against, rather than trusting
a self-declared "who signed this" hint.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonicalize
from .errors import AICError

ALG = "Ed25519"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_of(record: dict[str, Any]) -> str:
    """The content digest of a signed record, INCLUDING its signature(s) --
    this is what later records pin (`prior_epoch_digest`, `epoch_digest`,
    `parent_epoch_digest`) to unambiguously reference one exact, already-
    signed object, not just its unsigned content."""
    return digest(canonicalize(record))


def unsigned(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in ("signature", "predecessor_signature")}


def sign(record: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    payload = canonicalize(unsigned(record))
    return {**record, "signature": {"alg": ALG, "value": b64(private_key.sign(payload))}}


def sign_predecessor(record: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """A second, independent signature over the same unsigned content, by a
    DIFFERENT key -- used only for `epoch.transition == "key_rotation"`,
    where the prior epoch's key attests that the new key is its legitimate
    successor. Computed over the same unsigned payload as the primary
    self-signature so both signatures authenticate identical content."""
    payload = canonicalize(unsigned(record))
    return {**record, "predecessor_signature": {"alg": ALG, "value": b64(private_key.sign(payload))}}


def verify(record: dict[str, Any], public_key_b64: str, *, field: str = "signature") -> None:
    block = record.get(field)
    if not isinstance(block, dict) or block.get("alg") != ALG or not isinstance(block.get("value"), str):
        raise AICError("signature.missing", f"Record has no valid {field}.")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(unb64(public_key_b64))
        public_key.verify(unb64(block["value"]), canonicalize(unsigned(record)))
    except (InvalidSignature, ValueError) as exc:
        raise AICError("signature.invalid", f"{field} does not verify against the given public key.") from exc


class AgentIdentity:
    """One Ed25519 keypair and the self-certifying agent_id derived from it.

    `agent_id` is deterministic from the public key alone (`aic:agent:` +
    base64url(sha256(public_key))) -- exactly like a self-signed root of
    trust: no external authority assigns it, and anyone can independently
    recompute it from the key to check a claimed agent_id is genuine.
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key
        self.public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> AgentIdentity:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> AgentIdentity:
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @property
    def private_b64(self) -> str:
        raw = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()
        )
        return b64(raw)

    @property
    def public_b64(self) -> str:
        raw = self.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return b64(raw)

    @property
    def agent_id(self) -> str:
        raw = self.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return "aic:agent:" + b64(hashlib.sha256(raw).digest())

    @staticmethod
    def agent_id_for(public_key_b64: str) -> str:
        return "aic:agent:" + b64(hashlib.sha256(unb64(public_key_b64)).digest())
