"""Tamper-evident audit log for security events (hash-chained).

Each entry is linked to the previous one by a SHA-256 hash, so any insertion,
deletion, reordering or edit breaks the chain and is caught by verify(). Same
idea as the audit ledger in aegis-zero-trust, kept adapter-side so the domain
stays pure.
"""
import hashlib
import json

GENESIS = "0" * 64


def _digest(prev_hash: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self):
        self._entries = []

    def append(self, event: dict) -> dict:
        prev = self._entries[-1]["hash"] if self._entries else GENESIS
        core = {"seq": len(self._entries), "prev": prev, "event": event}
        record = dict(core)
        record["hash"] = _digest(prev, core)
        self._entries.append(record)
        return record

    def record_alert(self, alert) -> dict:
        """Append a SecurityAlert-like object (uses .to_dict() if present)."""
        to_dict = getattr(alert, "to_dict", None)
        event = to_dict() if callable(to_dict) else dict(alert)
        return self.append(event)

    def verify(self) -> bool:
        prev = GENESIS
        for i, e in enumerate(self._entries):
            core = {"seq": e["seq"], "prev": e["prev"], "event": e["event"]}
            if e["seq"] != i or e["prev"] != prev or _digest(prev, core) != e["hash"]:
                return False
            prev = e["hash"]
        return True

    @property
    def entries(self):
        return [dict(e) for e in self._entries]

    def __len__(self):
        return len(self._entries)
