"""Checks per second on the example vendors with synthetic requests."""

from __future__ import annotations

import datetime as dt
import json
import time
from pathlib import Path

from payeelock import Policy, check, request_from, vendors_from

EX = Path(__file__).resolve().parents[1] / "examples"


def main() -> None:
    vendors = vendors_from(json.loads((EX / "vendors.json").read_text()))
    reqs = [request_from(r) for r in json.loads((EX / "requests.json").read_text())]
    policy = Policy()
    at = dt.datetime(2026, 11, 19, tzinfo=dt.UTC)
    n = 20_000
    t0 = time.perf_counter()
    for i in range(n):
        check(policy, vendors, reqs[i % len(reqs)], at)
    dt_s = time.perf_counter() - t0
    print(f"{n} checks in {dt_s:.2f}s, {n / dt_s:,.0f} per second")


if __name__ == "__main__":
    main()
