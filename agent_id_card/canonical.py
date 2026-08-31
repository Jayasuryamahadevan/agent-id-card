"""RFC 8785 JSON Canonicalization Scheme (JCS): the exact byte string every
AIC signature is computed over and verified against.

Uses the `rfc8785` package (Trail of Bits, Apache-2.0, zero dependencies)
rather than a hand-rolled canonicalizer -- canonicalization bugs are
signature-verification bugs, and this is a small, focused, audited
implementation of a narrow spec rather than a general JSON library doing
canonicalization as an afterthought. Pinned to an exact version: any
change in a canonicalizer's output for the same input is a breaking change
for every previously-issued signature.
"""

from __future__ import annotations

from typing import Any

import rfc8785


def canonicalize(value: dict[str, Any]) -> bytes:
    return rfc8785.dumps(value)
