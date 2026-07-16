"""Architecture fitness — the hexagon boundary is enforced in CI.

The pure core (lab/domain, lab/application) must depend only on ports and plain
data — never on adapters, I/O, wire formats or crypto. This guarantees raw bytes
from the wire never reach the core: only typed domain objects cross the boundary.
"""
import ast
import pathlib

CORE_DIRS = ["lab/domain", "lab/application"]
FORBIDDEN = {"hashlib", "hmac", "json", "socket", "ssl", "paho", "machine"}
FORBIDDEN_PREFIXES = ("lab.adapters", "gateway", "runner")

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _imported_modules(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            yield node.module or ""


def test_core_never_imports_io_or_adapters():
    offenders = []
    for d in CORE_DIRS:
        for path in (ROOT / d).rglob("*.py"):
            for mod in _imported_modules(path):
                if mod in FORBIDDEN or mod.startswith(FORBIDDEN_PREFIXES):
                    offenders.append("%s imports %s" % (path.relative_to(ROOT), mod))
    assert not offenders, "hexagon boundary violated:\n" + "\n".join(offenders)
