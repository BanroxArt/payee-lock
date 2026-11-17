"""Command line.

    payeelock check --policy p.toml --vendors v.json --request r.json [--at T] [--log audit.jsonl]
    payeelock verify-log audit.jsonl
    payeelock validate '{"kind": "iban", "iban": "GB82 WEST 1234 5698 7654 32"}'

``check`` exits 0 on allow, 2 on hold, 3 on block, 1 on bad input, so a
payment job can gate on the exit code alone.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import audit
from .guard import check
from .instruments import InvalidInstrument, parse
from .model import RecordError, request_from, ts, vendors_from
from .policy import Policy, PolicyError, load

EXIT = {"allow": 0, "hold": 2, "block": 3}


def _json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cmd_check(a: argparse.Namespace) -> int:
    policy = load(a.policy) if a.policy else Policy()
    vendors = vendors_from(_json(a.vendors))
    doc = _json(a.request)
    reqs = doc if isinstance(doc, list) else [doc]
    worst = 0
    for raw in reqs:
        req = request_from(raw)
        d = check(policy, vendors, req, ts(a.at, "--at") if a.at else None)
        if a.log:
            audit.append(a.log, d, a.actor)
        if a.json:
            print(json.dumps(d.to_dict(), indent=2))
        else:
            amount = f"{d.amount_cents / 100:,.2f}"
            print(
                f"{d.outcome.upper():5}  {d.request_id}  {d.vendor_id}  {d.instrument}  {amount} via {d.rail}"
            )
            for f in d.findings:
                print(f"       {f.action:5}  {f.code}: {f.message}")
                if f.clears_by and f.action != "info":
                    print(f"              -> {f.clears_by}")
        worst = max(worst, EXIT[d.outcome])
    return worst


def _cmd_verify(a: argparse.Namespace) -> int:
    ok, _, msg = audit.verify(a.log)
    print(("ok    " if ok else "BROKEN ") + msg)
    return 0 if ok else 3


def _cmd_validate(a: argparse.Namespace) -> int:
    inst = parse(json.loads(a.instrument))
    print(f"valid  {inst.masked()}  fingerprint {inst.fingerprint()[:16]}")
    if not inst.checksummed:
        print("note   address has no EIP-55 checksum")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="payeelock", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="evaluate one request (or a JSON list of them)")
    c.add_argument("--policy")
    c.add_argument("--vendors", required=True)
    c.add_argument("--request", required=True)
    c.add_argument("--at", help="intended send time, ISO 8601 with offset; default requested_at")
    c.add_argument("--log", help="append each decision to this hash-chained JSONL file")
    c.add_argument("--actor", default="", help="who ran the check, recorded in the log")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=_cmd_check)
    v = sub.add_parser("verify-log", help="check the hash chain of an audit log")
    v.add_argument("log")
    v.set_defaults(fn=_cmd_verify)
    w = sub.add_parser("validate", help="validate one instrument given as JSON")
    w.add_argument("instrument")
    w.set_defaults(fn=_cmd_validate)
    a = ap.parse_args(argv)
    try:
        rc: int = a.fn(a)
    except (InvalidInstrument, RecordError, PolicyError, json.JSONDecodeError, KeyError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
