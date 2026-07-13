"""HMAC-SHA256 signer (node) and verifier (gateway).

The shared secret is per-key-id, so keys can be rotated and revoked without
touching the domain. On real hardware the node stores its key in secure
storage; here it's injected. HMAC gives integrity + authenticity: an attacker
who can publish MQTT still can't forge a frame without the key.

`hmac`/`hashlib` live in the adapter, never in the core — the domain stays
MicroPython-safe (MicroPython has `hashlib` + `hmac` in most ports, but keeping
it adapter-side preserves the boundary).
"""

import hashlib
import hmac

from lab.domain.model import SignedFrame
from lab.domain.ports import SignerPort, VerifierPort


def _tag(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


class HmacSigner(SignerPort):
    def __init__(self, key: bytes, key_id: str = "k1"):
        if not key:
            raise ValueError("signing key must not be empty")
        self._key = key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: bytes) -> SignedFrame:
        return SignedFrame(payload, _tag(self._key, payload), self._key_id)


class HmacVerifier(VerifierPort):
    """Holds a keyring {key_id: key}. Verifies using the key the frame claims,
    with a constant-time compare to avoid timing side-channels."""

    def __init__(self, keyring: dict):
        if not keyring:
            raise ValueError("keyring must not be empty")
        self._keyring = dict(keyring)

    def verify(self, signed) -> bool:
        key = self._keyring.get(signed.key_id)
        if key is None:
            return False   # unknown / revoked key id
        expected = _tag(key, signed.payload)
        return hmac.compare_digest(expected, signed.tag)
