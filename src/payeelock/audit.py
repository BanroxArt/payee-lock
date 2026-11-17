"""Append-only, hash-chained decision log.

One JSON object per line. Each entry carries the SHA-256 of the previous
line's canonical form, so deleting, reordering or editing an entry breaks the
chain from that point on and ``verify`` names the first bad line. This makes
tampering evident; it does not prevent it. Ship the file, or just its last
hash, somewhere the payments team cannot write if that matters to you.

Entries hold the destination fingerprint and the masked form, never the full
account number, IBAN or wallet address.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .guard import Decision

GENESIS = "0" * 64


def _canon(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(obj: dict[str, Any]) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def last_hash(path: Path) -> tuple[int, str]:
    if not path.exists() or path.stat().st_size == 0:
        return 0, GENESIS
    lines = path.read_text(encoding="utf-8").splitlines()
    tail = json.loads(lines[-1])
    return int(tail["seq"]), str(tail["hash"])


def append(path: str | Path, decision: Decision, actor: str = "") -> dict[str, Any]:
    """Append one decision and return the entry as written."""
    p = Path(path)
    seq, prev = last_hash(p)
    body: dict[str, Any] = {
        "seq": seq + 1,
        "prev": prev,
        "actor": actor,
        "decision": decision.to_dict(),
    }
    body["hash"] = _digest(body)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(_canon(body) + "\n")
    return body


def verify(path: str | Path) -> tuple[bool, int, str]:
    """Return (ok, entries checked, message). Stops at the first broken link."""
    prev, n = GENESIS, 0
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, n - 1, f"line {n}: not JSON"
        claimed = entry.pop("hash", None)
        if entry.get("seq") != n:
            return False, n - 1, f"line {n}: sequence {entry.get('seq')} where {n} was expected"
        if entry.get("prev") != prev:
            return False, n - 1, f"line {n}: previous-hash link is broken"
        if claimed != _digest(entry):
            return False, n - 1, f"line {n}: entry was modified after it was written"
        prev = str(claimed)
    return True, n, f"{n} entries, chain intact, head {prev[:16]}"
