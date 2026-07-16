from lab.adapters.security.hmac_signer import HmacSigner, HmacVerifier
from lab.adapters.security.keyring import build_keyring, derive_key, revoke, rotate

MASTER = b"agrisentinel-master-secret-for-tests"
NODES = ["crop-01", "water-01", "herd-01"]


def _signed(node_id, claim=None, payload=b"reading"):
    signer = HmacSigner(derive_key(MASTER, node_id), key_id=claim or node_id)
    return signer.sign(payload)


def test_each_node_has_a_distinct_key():
    ring = build_keyring(MASTER, NODES)
    assert len(set(ring.values())) == len(NODES)


def test_node_frame_verifies_with_its_own_key():
    verifier = HmacVerifier(build_keyring(MASTER, NODES))
    assert verifier.verify(_signed("crop-01")) is True


def test_frame_cannot_impersonate_another_node():
    verifier = HmacVerifier(build_keyring(MASTER, NODES))
    # signed with crop-01's key but claiming water-01 -> tag mismatch
    assert verifier.verify(_signed("crop-01", claim="water-01")) is False


def test_revoked_node_is_rejected():
    ring = revoke(build_keyring(MASTER, NODES), "herd-01")
    verifier = HmacVerifier(ring)
    assert verifier.verify(_signed("herd-01")) is False


def test_rotation_produces_a_new_key():
    key_id, key = rotate(MASTER, "crop-01", 2)
    assert key_id == "crop-01.v2"
    assert key != derive_key(MASTER, "crop-01")
