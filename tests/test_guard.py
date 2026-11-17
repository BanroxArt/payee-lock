from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from conftest import NEW, OLD, request
from hypothesis import given, settings
from hypothesis import strategies as st

from payeelock import Policy, check, lookalike, request_from, vendors_from
from payeelock.policy import from_dict

SEND = dt.datetime(2026, 11, 19, 12, tzinfo=dt.UTC)


def run(vendors_doc: dict[str, Any], policy: Policy | None = None, at: dt.datetime = SEND, **over: Any):  # type: ignore[no-untyped-def]
    return check(policy or Policy(), vendors_from(vendors_doc), request_from(request(**over)), at)


def codes(d) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.code for f in d.findings if f.action != "info"}


def test_clean_new_destination_passes(vendors_doc: dict[str, Any]) -> None:
    d = run(vendors_doc)
    assert d.outcome == "allow", d.findings
    assert d.facts["new_instrument"] is True
    assert d.facts["approvers"] == ["u-ctl1", "u-ctl2"]


def test_known_destination_needs_no_callback(vendors_doc: dict[str, Any]) -> None:
    d = run(vendors_doc, instrument=OLD, change=None, callbacks=[], amount_cents=900_000)
    assert d.outcome == "allow"
    assert d.facts["new_instrument"] is False


def test_unknown_vendor_blocks(vendors_doc: dict[str, Any]) -> None:
    assert run(vendors_doc, vendor_id="v-999").outcome == "block"


def test_new_destination_without_change_record(vendors_doc: dict[str, Any]) -> None:
    d = run(vendors_doc, change=None)
    assert "PL-NO-CHANGE-RECORD" in codes(d)
    assert d.outcome == "hold"


@pytest.mark.parametrize(
    ("amount", "hours", "held"),
    [
        (900_000, 23, True),
        (900_000, 25, False),
        (2_500_000, 47, True),
        (2_500_000, 49, False),
        (10_000_000, 71, True),
    ],
)
def test_cooling_off_tiers(vendors_doc: dict[str, Any], amount: int, hours: int, held: bool) -> None:
    received = SEND - dt.timedelta(hours=hours)
    cb_at = SEND - dt.timedelta(hours=1)
    d = run(
        vendors_doc,
        amount_cents=amount,
        requested_at=(SEND - dt.timedelta(hours=2)).isoformat(),
        change={"received_at": received.isoformat(), "via": "email"},
        callbacks=[
            {
                "id": "c",
                "at": cb_at.isoformat(),
                "by": "u",
                "dialed": "2125550142",
                "outcome": "confirmed",
                "read_back": True,
            }
        ],
    )
    assert ("PL-COOLING-OFF" in codes(d)) is held


def test_cooling_off_is_advisory_on_reversible_rail(vendors_doc: dict[str, Any]) -> None:
    d = run(
        vendors_doc,
        rail="ach",
        change={"received_at": "2026-11-19T11:00:00+00:00", "via": "portal"},
        callbacks=[
            {
                "id": "c",
                "at": "2026-11-19T11:30:00+00:00",
                "by": "u",
                "dialed": "+12125550142",
                "outcome": "confirmed",
                "read_back": True,
            }
        ],
    )
    assert "PL-COOLING-OFF" not in codes(d)
    assert any(f.code == "PL-COOLING-OFF" and f.action == "info" for f in d.findings)
    assert any(f.code == "PL-REVERSIBLE-RAIL" for f in d.findings)


def test_callback_to_number_from_the_change_request(vendors_doc: dict[str, Any]) -> None:
    cb = {
        "id": "cb1",
        "at": "2026-11-18T14:00:00+00:00",
        "by": "u",
        "dialed": "212.555.0199",
        "outcome": "confirmed",
        "read_back": True,
    }
    d = run(vendors_doc, callbacks=[cb])
    assert codes(d) == {"PL-CALLBACK-SUPPLIED-CONTACT"}


def test_callback_problems(vendors_doc: dict[str, Any]) -> None:
    base = request()["callbacks"][0]
    cases = {
        "outcome": ({**base, "outcome": "no_answer"}, "not 'confirmed'"),
        "stale": ({**base, "at": "2026-11-16T09:30:00+00:00"}, "older than"),
        "before change": ({**base, "at": "2026-11-16T08:00:00+00:00"}, "before the new details"),
        "no read back": ({**base, "read_back": False}, "read the new details back"),
        "stranger": ({**base, "dialed": "+1 917 555 0123"}, "not on file"),
        "future": ({**base, "at": "2026-11-20T00:00:00+00:00"}, "after the send time"),
    }
    for name, (cb, text) in cases.items():
        d = run(vendors_doc, callbacks=[cb])
        assert d.outcome == "hold", name
        assert any(text in f.message for f in d.findings), (name, d.findings)


def test_one_good_callback_is_enough(vendors_doc: dict[str, Any]) -> None:
    good = request()["callbacks"][0]
    bad = {**good, "id": "cb0", "dialed": "2125550199"}
    assert run(vendors_doc, callbacks=[bad, good]).outcome == "allow"


def test_contact_put_on_file_just_before_change(vendors_doc: dict[str, Any]) -> None:
    vendors_doc["vendors"][0]["contacts"][0]["on_file_since"] = "2026-11-10T00:00:00+00:00"
    d = run(vendors_doc)
    assert codes(d) == {"PL-CONTACT-RECENT"}


def test_lookalike_and_unknown_senders(vendors_doc: dict[str, Any]) -> None:
    d = run(vendors_doc, sender="ar@northwind-papper.example")
    assert d.outcome == "block" and "PL-LOOKALIKE-SENDER" in codes(d)
    d = run(vendors_doc, sender="ar@unrelated.example")
    assert d.outcome == "hold" and codes(d) == {"PL-UNKNOWN-SENDER"}


@pytest.mark.parametrize(
    ("cand", "known", "hit"),
    [
        ("northwind-paper.example", "northwind-paper.example", False),
        ("northwlnd-paper.example", "northwind-paper.example", True),
        ("northwind-paper.co.example", "northwind-paper.example", True),
        ("arnazon.example", "amazon.example", True),
        ("c0ntoso.example", "contoso.example", True),
        ("contoso.example.invoices.test", "contoso.example", True),
        ("fabrikam.example", "contoso.example", False),
    ],
)
def test_lookalike(cand: str, known: str, hit: bool) -> None:
    assert lookalike(cand, known, 2) is hit


def test_country_change(vendors_doc: dict[str, Any]) -> None:
    inst = {"kind": "iban", "iban": "GB82WEST12345698765432"}
    d = run(vendors_doc, instrument=inst)
    assert codes(d) == {"PL-COUNTRY-CHANGE"}
    strict = from_dict({"checks": {"country_change": "block"}})
    assert run(vendors_doc, policy=strict, instrument=inst).outcome == "block"


def test_shared_destination_across_vendors(vendors_doc: dict[str, Any]) -> None:
    other = {"kind": "iban", "iban": "DE89370400440532013000"}
    d = run(vendors_doc, instrument=other)
    assert "PL-SHARED-INSTRUMENT" in codes(d)
    assert d.outcome == "block"


def test_dual_approval_excludes_initiator_and_editor(vendors_doc: dict[str, Any]) -> None:
    d = run(
        vendors_doc,
        approvals=[
            {"by": "u-ap1", "at": "2026-11-19T10:30:00+00:00"},
            {"by": "u-ctl1", "at": "2026-11-19T10:31:00+00:00"},
        ],
    )
    assert codes(d) == {"PL-DUAL-APPROVAL"}
    # On file since 2024 (no call-back needed), but the approver is the person who entered it.
    d = run(
        vendors_doc,
        instrument=OLD,
        change=None,
        callbacks=[],
        approvals=[
            {"by": "u-ap1", "at": "2026-11-19T10:30:00+00:00"},
            {"by": "u-ctl1", "at": "2026-11-19T10:31:00+00:00"},
        ],
        initiator="u-ap9",
    )
    assert codes(d) == {"PL-DUAL-APPROVAL"}


def test_approvals_must_fall_between_request_and_send(vendors_doc: dict[str, Any]) -> None:
    early = [
        {"by": "u-ctl1", "at": "2026-11-19T09:00:00+00:00"},
        {"by": "u-ctl2", "at": "2026-11-19T12:30:00+00:00"},
    ]
    assert codes(run(vendors_doc, approvals=early)) == {"PL-DUAL-APPROVAL"}


def test_below_threshold_needs_no_approvals(vendors_doc: dict[str, Any]) -> None:
    assert run(vendors_doc, amount_cents=2_499_999, approvals=[]).outcome == "allow"


def test_unchecksummed_wallet(vendors_doc: dict[str, Any]) -> None:
    w = {"kind": "evm", "address": "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "chain_id": 1}
    d = run(
        vendors_doc,
        vendor_id="v-300",
        instrument=w,
        sender="",
        change=None,
        callbacks=[],
        amount_cents=10_000,
    )
    assert codes(d) == {"PL-EVM-NO-CHECKSUM"}


def test_recent_on_file_destination_still_needs_callback(vendors_doc: dict[str, Any]) -> None:
    vendors_doc["vendors"][0]["instruments"].append(
        {"instrument": NEW, "added_at": "2026-11-10T00:00:00+00:00", "added_by": "u-ap3"}
    )
    d = run(vendors_doc, change=None, callbacks=[])
    assert codes(d) == {"PL-CALLBACK-MISSING"}


@settings(max_examples=60, deadline=None)
@given(
    hours_since_change=st.integers(0, 24 * 40),
    amount=st.integers(1, 20_000_000),
    has_callback=st.booleans(),
    approvers=st.integers(0, 3),
)
def test_never_allows_a_new_destination_without_every_control(
    hours_since_change: int, amount: int, has_callback: bool, approvers: int
) -> None:
    import json
    from pathlib import Path

    doc = json.loads((Path(__file__).resolve().parents[1] / "examples" / "vendors.json").read_text())
    p = Policy()
    received = SEND - dt.timedelta(hours=hours_since_change)
    cbs = (
        [
            {
                "id": "c",
                "at": (SEND - dt.timedelta(minutes=5)).isoformat(),
                "by": "u",
                "dialed": "2125550142",
                "outcome": "confirmed",
                "read_back": True,
            }
        ]
        if has_callback
        else []
    )
    apps = [{"by": f"u-c{i}", "at": (SEND - dt.timedelta(minutes=1)).isoformat()} for i in range(approvers)]
    d = run(
        doc,
        amount_cents=amount,
        requested_at=(SEND - dt.timedelta(minutes=10)).isoformat(),
        change={"received_at": received.isoformat(), "via": "email"},
        callbacks=cbs,
        approvals=apps,
    )
    if d.outcome == "allow":
        assert has_callback
        assert hours_since_change >= p.cooling_hours(amount)
        assert amount < p.dual_threshold_cents or approvers >= p.dual_approvers
