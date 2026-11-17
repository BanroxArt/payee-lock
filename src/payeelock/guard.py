"""The pre-send check.

``check`` takes the policy, the vendor master and one payment request and
returns a decision: ``allow``, ``hold`` (with the actions that would clear it)
or ``block``. It never sends anything and never changes the vendor master. It
is meant to sit in front of the last step that makes money leave, the one
after which a wire, RTP or FedNow credit or a stablecoin transfer cannot be
pulled back.

The controls follow the FBI's advice for business email compromise: verify a
change in payment instructions through a second channel, using contact details
that were on file before the change, and do not trust the phone number or
address that arrived with the change request.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from typing import Literal

from .model import Callback, PaymentRequest, Vendor, norm_contact
from .policy import Action, Policy

Outcome = Literal["allow", "hold", "block"]
_RANK = {"info": 0, "hold": 1, "block": 2}


@dataclass(frozen=True)
class Finding:
    code: str
    action: Action
    message: str
    clears_by: str = ""


@dataclass(frozen=True)
class Decision:
    request_id: str
    vendor_id: str
    outcome: Outcome
    findings: tuple[Finding, ...]
    instrument: str
    fingerprint: str
    amount_cents: int
    rail: str
    evaluated_at: str
    policy_digest: str
    facts: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _osa(a: str, b: str) -> int:
    """Optimal string alignment distance (Levenshtein plus adjacent swaps)."""
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


_CONFUSABLE = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("i", "l"))


def _fold(s: str) -> str:
    s = s.lower()
    for a, b in _CONFUSABLE:
        s = s.replace(a, b)
    return s.replace("-", "").replace("_", "")


def lookalike(candidate: str, known: str, max_distance: int) -> bool:
    """True when ``candidate`` differs from ``known`` but would pass a quick read.

    Covers small edits (``northwind-paper`` / ``northwlnd-paper``), visual
    confusables (``rn`` for ``m``, ``0`` for ``o``), and the vendor's name
    used as a label inside some other domain (``northwind-paper.example.billing.test``).
    """
    c, k = candidate.lower(), known.lower()
    if c == k:
        return False
    if _osa(c, k) <= max_distance or _fold(c) == _fold(k):
        return True
    head = k.split(".")[0]
    return len(head) >= 5 and head in c.split(".")


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _hours(d: dt.timedelta) -> float:
    return d.total_seconds() / 3600


def _callback_problems(
    cb: Callback,
    vendor: Vendor,
    req: PaymentRequest,
    changed_at: dt.datetime | None,
    now: dt.datetime,
    policy: Policy,
) -> list[str]:
    out: list[str] = []
    if cb.outcome != "confirmed":
        out.append(f"call-back {cb.id} outcome is {cb.outcome!r}, not 'confirmed'")
    if cb.at > now:
        out.append(f"call-back {cb.id} is dated after the send time")
    elif _hours(now - cb.at) > policy.callback_max_age_hours:
        out.append(f"call-back {cb.id} is older than {policy.callback_max_age_hours} hours")
    if changed_at is not None and cb.at < changed_at:
        out.append(f"call-back {cb.id} happened before the new details arrived")
    if policy.require_read_back and not cb.read_back:
        out.append(f"call-back {cb.id} did not read the new details back to the vendor")
    dialed = norm_contact(cb.dialed)
    supplied = norm_contact(req.change.contact_supplied) if req.change and req.change.contact_supplied else ""
    match = next((c for c in vendor.contacts if norm_contact(c.value) == dialed), None)
    if match is None:
        if supplied and dialed == supplied:
            out.append(
                f"call-back {cb.id} used the contact that came with the change request, not one on file"
            )
        else:
            out.append(f"call-back {cb.id} used a contact that is not on file for the vendor")
    else:
        ref = changed_at or req.requested_at
        age_days = (ref - match.on_file_since).total_seconds() / 86400
        if age_days < policy.contact_min_age_days:
            out.append(
                f"contact {match.id} was put on file {age_days:.1f} days before the change; "
                f"policy needs {policy.contact_min_age_days}"
            )
    return out


def check(
    policy: Policy,
    vendors: dict[str, Vendor],
    req: PaymentRequest,
    now: dt.datetime | None = None,
) -> Decision:
    """Evaluate one payment request. ``now`` is the intended send time."""
    at = (now or req.requested_at).astimezone(dt.UTC)
    inst = req.instrument
    f: list[Finding] = []
    facts: dict[str, object] = {}

    def add(code: str, action: Action, message: str, clears_by: str = "") -> None:
        f.append(Finding(code, action, message, clears_by))

    vendor = vendors.get(req.vendor_id)
    if vendor is None:
        add("PL-UNKNOWN-VENDOR", "block", f"vendor {req.vendor_id} is not in the vendor master")
        return _decide(req, inst.masked(), inst.fingerprint(), f, at, policy, facts)

    irreversible = req.rail in policy.irreversible_rails
    facts["irreversible"] = irreversible
    if not irreversible:
        add(
            "PL-REVERSIBLE-RAIL",
            "info",
            f"rail {req.rail!r} is not listed as irreversible; findings still apply",
        )

    on_file = vendor.on_file(inst)
    fp = inst.fingerprint()
    others = sorted(v.id for v in vendors.values() if v.id != vendor.id and v.on_file(inst))
    if others:
        add(
            "PL-SHARED-INSTRUMENT",
            policy.on_shared_instrument,
            f"the same destination is on file for other vendors: {', '.join(others)}",
            "confirm with each vendor through a contact on file; one account rarely serves two firms",
        )

    changed_at: dt.datetime | None
    if on_file is None:
        changed_at = req.change.received_at if req.change else None
        facts["new_instrument"] = True
        if changed_at is None:
            add(
                "PL-NO-CHANGE-RECORD",
                "hold",
                "destination is not on file and there is no record of how it was received",
                "enter it through the vendor-change process so its arrival is recorded",
            )
    else:
        changed_at = on_file.added_at
        facts["new_instrument"] = False
    if changed_at is not None:
        facts["changed_at"] = changed_at.isoformat()
    recent = on_file is None or _hours(at - on_file.added_at) < policy.callback_recent_days * 24
    facts["recent"] = recent

    if changed_at is not None and recent:
        need = policy.cooling_hours(req.amount_cents)
        waited = _hours(at - changed_at)
        if waited < need:
            add(
                "PL-COOLING-OFF",
                "hold" if irreversible else "info",
                f"destination changed {waited:.1f} hours ago; policy needs {need} for this amount",
                f"wait until {(changed_at + dt.timedelta(hours=need)).isoformat()}",
            )

    if recent:
        problems = [_callback_problems(cb, vendor, req, changed_at, at, policy) for cb in req.callbacks]
        if not req.callbacks:
            add(
                "PL-CALLBACK-MISSING",
                "hold",
                "new or recently changed destination with no call-back on record",
                "call the vendor on a number that was on file before the change and read the details back",
            )
        elif all(problems):
            for p in sorted({p for ps in problems for p in ps}):
                code = (
                    "PL-CALLBACK-SUPPLIED-CONTACT"
                    if "came with the change request" in p
                    else "PL-CONTACT-RECENT"
                    if p.startswith("contact ")
                    else "PL-CALLBACK-INVALID"
                )
                add(code, "hold", p, "repeat the call-back to a contact on file before the change")

    for who, addr in (
        ("payment request", req.sender),
        ("change request", req.change.sender if req.change else ""),
    ):
        dom = _domain(addr)
        if not dom or not vendor.email_domains or dom in vendor.email_domains:
            continue
        if any(lookalike(dom, k, policy.lookalike_max_distance) for k in vendor.email_domains):
            add(
                "PL-LOOKALIKE-SENDER",
                "block",
                f"{who} came from {dom}, which resembles but is not {', '.join(vendor.email_domains)}",
                "treat as attempted fraud; report it and do not reply to that address",
            )
        else:
            add(
                "PL-UNKNOWN-SENDER",
                policy.on_unknown_sender,
                f"{who} came from {dom}, not a domain on file for the vendor",
                "confirm the sender through a contact on file",
            )

    if recent and vendor.country and inst.country and inst.country != vendor.country:
        add(
            "PL-COUNTRY-CHANGE",
            policy.on_country_change,
            f"vendor is on file in {vendor.country} but the new destination is in {inst.country}",
            "ask why on the call-back; a move to an account in another country is a common BEC tell",
        )

    if not inst.checksummed:
        add(
            "PL-EVM-NO-CHECKSUM",
            policy.on_unchecksummed_evm,
            "wallet address has no EIP-55 checksum, so a typo or swap cannot be detected",
            "get the address in checksummed form and compare every character on the call-back",
        )

    if req.amount_cents >= policy.dual_threshold_cents:
        excluded = set()
        if policy.exclude_initiator:
            excluded.add(req.initiator)
        if policy.exclude_instrument_editor and on_file is not None:
            excluded.add(on_file.added_by)
        ok = {a.by for a in req.approvals if req.requested_at <= a.at <= at and a.by not in excluded}
        facts["approvers"] = sorted(ok)
        if len(ok) < policy.dual_approvers:
            add(
                "PL-DUAL-APPROVAL",
                "hold",
                f"needs {policy.dual_approvers} approvers other than the initiator and the person "
                f"who entered the destination; has {len(ok)}",
                "get the missing approvals after the request was created",
            )

    return _decide(req, inst.masked(), fp, f, at, policy, facts)


def _decide(
    req: PaymentRequest,
    masked: str,
    fp: str,
    findings: list[Finding],
    at: dt.datetime,
    policy: Policy,
    facts: dict[str, object],
) -> Decision:
    worst = max((_RANK[x.action] for x in findings), default=0)
    outcome: Outcome = "block" if worst == 2 else "hold" if worst == 1 else "allow"
    return Decision(
        req.id,
        req.vendor_id,
        outcome,
        tuple(findings),
        masked,
        fp,
        req.amount_cents,
        req.rail,
        at.isoformat(),
        policy.digest,
        facts,
    )
