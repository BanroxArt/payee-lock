from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

EX = Path(__file__).resolve().parents[1] / "examples"
OLD = {"kind": "us_bank", "routing": "011000015", "account": "4402187731"}
NEW = {"kind": "us_bank", "routing": "021000021", "account": "9917730045"}


@pytest.fixture
def vendors_doc() -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((EX / "vendors.json").read_text())
    return doc


def request(**over: Any) -> dict[str, Any]:
    """A new-destination wire that passes every control at 2026-11-19T12:00Z."""
    base: dict[str, Any] = {
        "id": "r1",
        "vendor_id": "v-100",
        "amount_cents": 4_825_000,
        "rail": "wire",
        "instrument": copy.deepcopy(NEW),
        "requested_at": "2026-11-19T10:00:00+00:00",
        "initiator": "u-ap1",
        "sender": "ar@northwind-paper.example",
        "change": {
            "received_at": "2026-11-16T09:00:00+00:00",
            "via": "email",
            "sender": "ar@northwind-paper.example",
            "contact_supplied": "+1 212 555 0199",
        },
        "callbacks": [
            {
                "id": "cb1",
                "at": "2026-11-18T14:00:00+00:00",
                "by": "u-ap2",
                "dialed": "(212) 555-0142",
                "outcome": "confirmed",
                "read_back": True,
            }
        ],
        "approvals": [
            {"by": "u-ctl1", "at": "2026-11-19T10:30:00+00:00"},
            {"by": "u-ctl2", "at": "2026-11-19T11:00:00+00:00"},
        ],
    }
    base.update(over)
    return base
