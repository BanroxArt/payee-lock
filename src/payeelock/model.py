"""Vendor master, payment request, call-back and approval records.

Everything is read from plain JSON so a team can export it from whatever AP,
treasury or digital-banking system holds it. Times are ISO 8601 with an
explicit offset; naive times are rejected because a cooling-off period
computed across a time-zone mistake is worthless.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any

from .instruments import Instrument, parse


class RecordError(ValueError):
    """A record is missing a field or has one in the wrong shape."""


def ts(value: object, what: str) -> dt.datetime:
    if not isinstance(value, str):
        raise RecordError(f"{what}: expected an ISO 8601 string")
    try:
        t = dt.datetime.fromisoformat(value)
    except ValueError as e:
        raise RecordError(f"{what}: {e}") from None
    if t.tzinfo is None:
        raise RecordError(f"{what}: time has no UTC offset")
    return t.astimezone(dt.UTC)


def _opt_ts(value: object, what: str) -> dt.datetime | None:
    return None if value is None else ts(value, what)


def _str(d: dict[str, Any], key: str, what: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v:
        raise RecordError(f"{what}: {key} must be a non-empty string")
    return v


def norm_contact(value: str) -> str:
    """Phone numbers compare on digits only; emails on the lower-cased address."""
    v = value.strip().lower()
    if "@" in v:
        return v
    digits = re.sub(r"\D", "", v)
    return digits[1:] if len(digits) == 11 and digits.startswith("1") else digits


@dataclass(frozen=True)
class Contact:
    id: str
    kind: str
    value: str
    on_file_since: dt.datetime


@dataclass(frozen=True)
class OnFile:
    instrument: Instrument
    added_at: dt.datetime
    added_by: str
    verified_at: dt.datetime | None = None


@dataclass(frozen=True)
class Vendor:
    id: str
    name: str
    country: str
    email_domains: tuple[str, ...]
    contacts: tuple[Contact, ...]
    instruments: tuple[OnFile, ...]

    def on_file(self, inst: Instrument) -> OnFile | None:
        fp = inst.fingerprint()
        return next((o for o in self.instruments if o.instrument.fingerprint() == fp), None)


@dataclass(frozen=True)
class ChangeRequest:
    """How the new instrument reached the payer, if it is new."""

    received_at: dt.datetime
    via: str
    sender: str = ""
    contact_supplied: str = ""


@dataclass(frozen=True)
class Callback:
    id: str
    at: dt.datetime
    by: str
    dialed: str
    outcome: str
    read_back: bool
    contact_id: str = ""


@dataclass(frozen=True)
class Approval:
    by: str
    at: dt.datetime


@dataclass(frozen=True)
class PaymentRequest:
    id: str
    vendor_id: str
    amount_cents: int
    currency: str
    rail: str
    instrument: Instrument
    requested_at: dt.datetime
    initiator: str
    sender: str = ""
    change: ChangeRequest | None = None
    callbacks: tuple[Callback, ...] = ()
    approvals: tuple[Approval, ...] = field(default_factory=tuple)


def vendor_from(d: dict[str, Any]) -> Vendor:
    vid = _str(d, "id", "vendor")
    what = f"vendor {vid}"
    contacts = tuple(
        Contact(
            _str(c, "id", what),
            _str(c, "kind", what),
            _str(c, "value", what),
            ts(c.get("on_file_since"), f"{what} contact on_file_since"),
        )
        for c in d.get("contacts", [])
    )
    insts = tuple(
        OnFile(
            parse(o["instrument"]),
            ts(o.get("added_at"), f"{what} instrument added_at"),
            _str(o, "added_by", what),
            _opt_ts(o.get("verified_at"), f"{what} instrument verified_at"),
        )
        for o in d.get("instruments", [])
    )
    return Vendor(
        vid,
        _str(d, "name", what),
        str(d.get("country", "")).upper(),
        tuple(str(x).lower() for x in d.get("email_domains", [])),
        contacts,
        insts,
    )


def vendors_from(doc: dict[str, Any]) -> dict[str, Vendor]:
    out: dict[str, Vendor] = {}
    for d in doc.get("vendors", []):
        v = vendor_from(d)
        if v.id in out:
            raise RecordError(f"vendor {v.id} appears twice")
        out[v.id] = v
    return out


def request_from(d: dict[str, Any]) -> PaymentRequest:
    rid = _str(d, "id", "request")
    what = f"request {rid}"
    amount = d.get("amount_cents")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise RecordError(f"{what}: amount_cents must be a positive integer")
    ch = d.get("change")
    change = (
        ChangeRequest(
            ts(ch.get("received_at"), f"{what} change received_at"),
            _str(ch, "via", what),
            str(ch.get("sender", "")),
            str(ch.get("contact_supplied", "")),
        )
        if isinstance(ch, dict)
        else None
    )
    callbacks = tuple(
        Callback(
            _str(c, "id", what),
            ts(c.get("at"), f"{what} callback at"),
            _str(c, "by", what),
            _str(c, "dialed", what),
            _str(c, "outcome", what),
            bool(c.get("read_back", False)),
            str(c.get("contact_id", "")),
        )
        for c in d.get("callbacks", [])
    )
    approvals = tuple(
        Approval(_str(a, "by", what), ts(a.get("at"), f"{what} approval at")) for a in d.get("approvals", [])
    )
    return PaymentRequest(
        rid,
        _str(d, "vendor_id", what),
        amount,
        str(d.get("currency", "USD")).upper(),
        _str(d, "rail", what).lower(),
        parse(d["instrument"]),
        ts(d.get("requested_at"), f"{what} requested_at"),
        _str(d, "initiator", what),
        str(d.get("sender", "")).lower(),
        change,
        callbacks,
        approvals,
    )
