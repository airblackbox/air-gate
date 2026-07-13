"""
Pluggable signers for the audit chain.

Two algorithms:

  HMAC-SHA256 (default, zero dependencies)
    Symmetric: the same secret both signs and verifies. Anyone holding the key
    can forge and re-sign the whole chain, so it proves integrity only to
    parties who do NOT hold the key. Good enough for a single trusted service.

  Ed25519 (optional, requires `cryptography`)
    Asymmetric: a private key signs; the public key verifies. A verifier (an
    auditor, a regulator) can confirm integrity WITHOUT the power to forge,
    because they only ever hold the public key. This is what lets you hand the
    audit chain plus the public key to a third party as tamper-evident evidence.

Both expose the same interface so `EventStore` does not care which is in use:

    signer.algorithm            -> str stored on each event
    signer.sign(content: bytes) -> hex str
    signer.verify(content, sig) -> bool
    signer.can_sign             -> bool (Ed25519 verify-only keys can't sign)
    signer.public_key_hex       -> str | None (Ed25519 public key, for sharing)
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional


class HMACSigner:
    """HMAC-SHA256 signer. Symmetric; the default."""

    algorithm = "HMAC-SHA256"
    can_sign = True
    public_key_hex = None

    def __init__(self, key: str):
        self._key = key.encode("utf-8") if isinstance(key, str) else key

    def sign(self, content: bytes) -> str:
        return hmac.new(self._key, content, hashlib.sha256).hexdigest()

    def verify(self, content: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(content), signature)


class Ed25519Signer:
    """
    Ed25519 signer/verifier. Asymmetric; requires the `cryptography` package.

    Construct with a private key (can sign and verify) or, for an auditor who
    only needs to check a chain, with a public key alone (verify-only).
    """

    algorithm = "Ed25519"

    def __init__(self, private_key=None, public_key=None):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
        except ImportError as e:  # pragma: no cover - exercised via factory
            raise ImportError(
                "Ed25519 signing requires the 'cryptography' package: "
                "pip install air-gate[crypto]"
            ) from e

        self._Ed25519PublicKey = Ed25519PublicKey
        self._private = private_key
        if private_key is not None:
            self._public = private_key.public_key()
        elif public_key is not None:
            self._public = public_key
        else:
            raise ValueError("Ed25519Signer needs a private_key or a public_key")

    # ── construction helpers ────────────────────────────────────────────

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        """Create a brand-new keypair (useful for tests and key bootstrapping)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return cls(private_key=Ed25519PrivateKey.generate())

    @classmethod
    def from_private_hex(cls, private_hex: str) -> "Ed25519Signer":
        """Load a signer from a 32-byte hex-encoded Ed25519 seed."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return cls(private_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex)))

    @classmethod
    def from_public_hex(cls, public_hex: str) -> "Ed25519Signer":
        """Load a verify-only signer from a 32-byte hex-encoded public key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return cls(public_key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)))

    # ── interface ───────────────────────────────────────────────────────

    @property
    def can_sign(self) -> bool:
        return self._private is not None

    @property
    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization
        raw = self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    @property
    def private_key_hex(self) -> Optional[str]:
        if self._private is None:
            return None
        from cryptography.hazmat.primitives import serialization
        raw = self._private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return raw.hex()

    def sign(self, content: bytes) -> str:
        if self._private is None:
            raise RuntimeError("This Ed25519Signer is verify-only (no private key)")
        return self._private.sign(content).hex()

    def verify(self, content: bytes, signature: str) -> bool:
        from cryptography.exceptions import InvalidSignature
        try:
            self._public.verify(bytes.fromhex(signature), content)
            return True
        except (InvalidSignature, ValueError):
            return False


def build_signer(
    signing_key: Optional[str] = None,
    algorithm: str = "HMAC-SHA256",
    ed25519_private_hex: Optional[str] = None,
    ed25519_public_hex: Optional[str] = None,
):
    """
    Build a signer from simple config.

    - algorithm="HMAC-SHA256" (default): uses signing_key.
    - algorithm="Ed25519": uses ed25519_private_hex (sign+verify) or
      ed25519_public_hex (verify-only).
    """
    algo = (algorithm or "HMAC-SHA256").upper()
    if algo in ("HMAC-SHA256", "HMAC"):
        return HMACSigner(signing_key or "change-me-in-production")
    if algo == "ED25519":
        if ed25519_private_hex:
            return Ed25519Signer.from_private_hex(ed25519_private_hex)
        if ed25519_public_hex:
            return Ed25519Signer.from_public_hex(ed25519_public_hex)
        raise ValueError("Ed25519 selected but no ed25519_private_hex/ed25519_public_hex provided")
    raise ValueError(f"Unknown signature algorithm: {algorithm}")
