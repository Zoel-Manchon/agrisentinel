"""Per-node HMAC keyring — derive, rotate and revoke node keys.

Each field node gets its OWN key, derived deterministically from a single master
secret via HMAC-SHA256. The key_id equals the node-id (which also equals the
node's mTLS certificate CN), so identity is consistent across the HMAC layer,
the transport layer and the application logic. Provisioning stays trivial (one
master secret) while the gateway can revoke a single node by dropping its key_id.
"""
import hashlib
import hmac


def derive_key(master: bytes, node_id: str) -> bytes:
    """Deterministic per-node key: HMAC-SHA256(master, node_id)."""
    if not master:
        raise ValueError("master secret must not be empty")
    return hmac.new(master, node_id.encode("utf-8"), hashlib.sha256).digest()


def build_keyring(master: bytes, node_ids) -> dict:
    """Gateway keyring {node_id: key} for every known node."""
    return {node_id: derive_key(master, node_id) for node_id in node_ids}


def rotate(master: bytes, node_id: str, version: int):
    """Rotate a node key. Returns (key_id, key) where key_id carries the version
    (e.g. 'crop-01.v2'), so old and new keys can coexist during a rollover."""
    key_id = "%s.v%d" % (node_id, version)
    return key_id, derive_key(master, key_id)


def revoke(keyring: dict, key_id: str) -> dict:
    """Return a new keyring without key_id (an unknown key_id fails verify)."""
    return {k: v for k, v in keyring.items() if k != key_id}
