from lab.adapters.security.audit_log import AuditLog


def test_empty_log_verifies():
    assert AuditLog().verify() is True


def test_appends_chain_and_verify():
    log = AuditLog()
    log.append({"kind": "replay", "device_id": "crop-01"})
    log.append({"kind": "out_of_range", "device_id": "water-01"})
    assert len(log) == 2
    assert log.verify() is True
    assert log.entries[1]["prev"] == log.entries[0]["hash"]


def test_tampering_is_detected():
    log = AuditLog()
    log.append({"kind": "replay", "device_id": "crop-01"})
    log.append({"kind": "forged", "device_id": "herd-01"})
    log._entries[0]["event"]["device_id"] = "attacker"   # edit after the fact
    assert log.verify() is False


def test_reorder_is_detected():
    log = AuditLog()
    log.append({"a": 1})
    log.append({"b": 2})
    log._entries[0], log._entries[1] = log._entries[1], log._entries[0]
    assert log.verify() is False
