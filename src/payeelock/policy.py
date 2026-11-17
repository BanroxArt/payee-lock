"""Policy file: which rails are irreversible and what each control requires.

TOML, read with the standard library. Every key has a default so an empty
file is a valid (strict) policy; unknown keys are errors so a typo cannot
silently switch a control off.
"""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

Action = Literal["block", "hold", "info"]
_ACTIONS = ("block", "hold", "info")


class PolicyError(ValueError):
    """The policy file is malformed."""


@dataclass(frozen=True)
class Tier:
    min_cents: int
    hours: int


@dataclass(frozen=True)
class Policy:
    irreversible_rails: tuple[str, ...] = ("wire", "rtp", "fednow", "stablecoin", "book")
    cooling_default_hours: int = 24
    cooling_tiers: tuple[Tier, ...] = (Tier(2_500_000, 48), Tier(10_000_000, 72))
    callback_recent_days: int = 30
    callback_max_age_hours: int = 72
    contact_min_age_days: int = 30
    require_read_back: bool = True
    dual_threshold_cents: int = 2_500_000
    dual_approvers: int = 2
    exclude_initiator: bool = True
    exclude_instrument_editor: bool = True
    lookalike_max_distance: int = 2
    on_country_change: Action = "hold"
    on_shared_instrument: Action = "block"
    on_unchecksummed_evm: Action = "hold"
    on_unknown_sender: Action = "hold"
    digest: str = ""

    def cooling_hours(self, amount_cents: int) -> int:
        hours = self.cooling_default_hours
        for t in self.cooling_tiers:
            if amount_cents >= t.min_cents:
                hours = max(hours, t.hours)
        return hours


_SCHEMA: dict[str, tuple[str, ...]] = {
    "": ("irreversible_rails",),
    "cooling_off": ("default_hours", "tiers"),
    "callback": ("recent_days", "max_age_hours", "contact_min_age_days", "require_read_back"),
    "dual_approval": ("threshold_cents", "approvers", "exclude_initiator", "exclude_instrument_editor"),
    "checks": (
        "lookalike_max_distance",
        "country_change",
        "shared_instrument",
        "unchecksummed_evm",
        "unknown_sender",
    ),
}


def _int(v: Any, key: str, minimum: int = 0) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < minimum:
        raise PolicyError(f"{key} must be an integer >= {minimum}")
    return v


def _bool(v: Any, key: str) -> bool:
    if not isinstance(v, bool):
        raise PolicyError(f"{key} must be true or false")
    return v


def _action(v: Any, key: str) -> Action:
    if v not in _ACTIONS:
        raise PolicyError(f"{key} must be one of {', '.join(_ACTIONS)}")
    a: Action = v
    return a


def from_dict(doc: dict[str, Any], digest: str = "") -> Policy:
    for k, v in doc.items():
        if isinstance(v, dict):
            if k not in _SCHEMA or not k:
                raise PolicyError(f"unknown section [{k}]")
            for sub in v:
                if sub not in _SCHEMA[k]:
                    raise PolicyError(f"unknown key {k}.{sub}")
        elif k not in _SCHEMA[""]:
            raise PolicyError(f"unknown key {k}")
    p = Policy()
    rails = doc.get("irreversible_rails", list(p.irreversible_rails))
    if not isinstance(rails, list) or not all(isinstance(r, str) for r in rails):
        raise PolicyError("irreversible_rails must be a list of strings")
    co = doc.get("cooling_off", {})
    tiers_raw = co.get("tiers", [{"min_cents": t.min_cents, "hours": t.hours} for t in p.cooling_tiers])
    tiers = tuple(
        Tier(_int(t.get("min_cents"), "tiers.min_cents"), _int(t.get("hours"), "tiers.hours"))
        for t in tiers_raw
    )
    cb = doc.get("callback", {})
    da = doc.get("dual_approval", {})
    ck = doc.get("checks", {})
    return Policy(
        irreversible_rails=tuple(r.lower() for r in rails),
        cooling_default_hours=_int(co.get("default_hours", p.cooling_default_hours), "default_hours"),
        cooling_tiers=tiers,
        callback_recent_days=_int(cb.get("recent_days", p.callback_recent_days), "recent_days"),
        callback_max_age_hours=_int(cb.get("max_age_hours", p.callback_max_age_hours), "max_age_hours", 1),
        contact_min_age_days=_int(
            cb.get("contact_min_age_days", p.contact_min_age_days), "contact_min_age_days"
        ),
        require_read_back=_bool(cb.get("require_read_back", p.require_read_back), "require_read_back"),
        dual_threshold_cents=_int(da.get("threshold_cents", p.dual_threshold_cents), "threshold_cents"),
        dual_approvers=_int(da.get("approvers", p.dual_approvers), "approvers", 1),
        exclude_initiator=_bool(da.get("exclude_initiator", p.exclude_initiator), "exclude_initiator"),
        exclude_instrument_editor=_bool(
            da.get("exclude_instrument_editor", p.exclude_instrument_editor),
            "exclude_instrument_editor",
        ),
        lookalike_max_distance=_int(
            ck.get("lookalike_max_distance", p.lookalike_max_distance), "lookalike_max_distance"
        ),
        on_country_change=_action(ck.get("country_change", p.on_country_change), "country_change"),
        on_shared_instrument=_action(
            ck.get("shared_instrument", p.on_shared_instrument), "shared_instrument"
        ),
        on_unchecksummed_evm=_action(
            ck.get("unchecksummed_evm", p.on_unchecksummed_evm), "unchecksummed_evm"
        ),
        on_unknown_sender=_action(ck.get("unknown_sender", p.on_unknown_sender), "unknown_sender"),
        digest=digest,
    )


def load(path: str | Path) -> Policy:
    raw = Path(path).read_bytes()
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(str(e)) from None
    return from_dict(doc, hashlib.sha256(raw).hexdigest())
