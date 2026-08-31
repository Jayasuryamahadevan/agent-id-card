"""AIC error codes. Every error a verifier or issuer can raise is one of
these -- machine-readable, never a raw exception message, so a caller can
branch on `error.code` instead of parsing text."""

from __future__ import annotations


class AICError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
