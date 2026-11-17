"""Payment instruments: parse, validate, fingerprint.

An instrument is where money lands: a US routing and account number pair (for
ACH, wire, RTP or FedNow), an IBAN with an optional BIC, or an EVM wallet
address with its chain id. Two instruments are the same when their
fingerprints are equal, and the fingerprint is computed only from normalized
fields, so ``GB82 WEST 1234 5698 7654 32`` and ``gb82west12345698765432`` match
and a one-digit change in an account number does not.

Validation catches typos and lazy forgeries before anyone phones a vendor:
the ABA check digit, the ISO 13616 mod-97 check and the country length for
IBANs, and the EIP-55 mixed-case checksum for EVM addresses. A valid check
digit says nothing about who owns the account.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from .keccak import keccak256

Kind = Literal["us_bank", "iban", "evm"]
KINDS: tuple[Kind, ...] = ("us_bank", "iban", "evm")

# ISO 13616 IBAN lengths for the countries a US payer most often sends to.
# Countries not listed are checked for the generic 15 to 34 range only.
IBAN_LENGTHS: dict[str, int] = {
    "AE": 23,
    "AT": 20,
    "BE": 16,
    "CH": 21,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DK": 18,
    "EE": 20,
    "ES": 24,
    "FI": 18,
    "FR": 27,
    "GB": 22,
    "GR": 27,
    "HU": 28,
    "IE": 22,
    "IL": 23,
    "IT": 27,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "MT": 31,
    "NL": 18,
    "NO": 15,
    "PL": 28,
    "PT": 25,
    "RO": 24,
    "SA": 24,
    "SE": 24,
    "SI": 19,
    "SK": 24,
    "TR": 26,
}

_ABA = re.compile(r"^\d{9}$")
_ACCOUNT = re.compile(r"^[0-9A-Z]{4,17}$")
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
_BIC = re.compile(r"^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$")
_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")


class InvalidInstrument(ValueError):
    """The instrument fails a format or check-digit test."""


def aba_ok(routing: str) -> bool:
    """ABA routing number check digit: weights 3, 7, 1 repeated, sum divisible by 10."""
    if not _ABA.match(routing):
        return False
    weights = (3, 7, 1) * 3
    return sum(int(d) * w for d, w in zip(routing, weights, strict=True)) % 10 == 0


def iban_ok(iban: str) -> bool:
    """ISO 13616 / ISO 7064 mod 97-10 check, plus the country length when known."""
    if not _IBAN.match(iban):
        return False
    want = IBAN_LENGTHS.get(iban[:2])
    if want is not None and len(iban) != want:
        return False
    if want is None and not 15 <= len(iban) <= 34:
        return False
    moved = iban[4:] + iban[:4]
    digits = "".join(str(int(ch, 36)) for ch in moved)
    return int(digits) % 97 == 1


def eip55(address: str) -> str:
    """EIP-55 mixed-case checksum form of a 20-byte hex address."""
    hexpart = address[2:].lower()
    h = keccak256(hexpart.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(hexpart))


def evm_ok(address: str) -> bool:
    """Well-formed, and if mixed case, the EIP-55 checksum matches.

    All-lower and all-upper addresses carry no checksum; they pass here and the
    guard reports them as unchecked so a person can compare them by eye.
    """
    if not _EVM.match(address):
        return False
    body = address[2:]
    if body == body.lower() or body == body.upper():
        return True
    return eip55(address) == address


def _squash(v: str) -> str:
    return re.sub(r"[\s\-./]", "", v).upper()


@dataclass(frozen=True)
class Instrument:
    """A normalized payment destination.

    ``us_bank`` uses ``routing`` and ``account``. ``iban`` uses ``iban`` and
    optionally ``bic``. ``evm`` uses ``address`` and ``chain_id``.
    """

    kind: Kind
    routing: str = ""
    account: str = ""
    iban: str = ""
    bic: str = ""
    address: str = ""
    chain_id: int = 0

    @property
    def country(self) -> str:
        """Two-letter country of the account where the format carries one, else ''."""
        if self.kind == "us_bank":
            return "US"
        if self.kind == "iban":
            return self.iban[:2]
        return ""

    @property
    def checksummed(self) -> bool:
        """False for an EVM address given in a single case (no EIP-55 checksum to test)."""
        if self.kind != "evm":
            return True
        body = self.address[2:]
        return not (body == body.lower() or body == body.upper())

    def fingerprint(self) -> str:
        """Stable identifier for equality across systems. Hex SHA-256 of the normalized fields.

        Hashing keeps full account numbers out of audit logs while still letting
        two logs be joined on the same destination.
        """
        if self.kind == "us_bank":
            key = f"us_bank|{self.routing}|{self.account}"
        elif self.kind == "iban":
            key = f"iban|{self.iban}"
        else:
            key = f"evm|{self.chain_id}|{self.address.lower()}"
        return hashlib.sha256(key.encode()).hexdigest()

    def masked(self) -> str:
        """Display form that shows only enough to read back on a call-back."""
        if self.kind == "us_bank":
            return f"ABA {self.routing} acct ...{self.account[-4:]}"
        if self.kind == "iban":
            return f"IBAN {self.iban[:4]}...{self.iban[-4:]}"
        a = self.address
        return f"chain {self.chain_id} {a[:6]}...{a[-4:]}"


def parse(raw: dict[str, object]) -> Instrument:
    """Build and validate an instrument from a plain mapping.

    Raises :class:`InvalidInstrument` with a reason a person can act on.
    """
    kind = str(raw.get("kind", ""))
    if kind == "us_bank":
        routing = _squash(str(raw.get("routing", "")))
        account = _squash(str(raw.get("account", "")))
        if not aba_ok(routing):
            raise InvalidInstrument(f"routing number {routing!r} fails the ABA check digit")
        if not _ACCOUNT.match(account):
            raise InvalidInstrument("account number must be 4 to 17 letters or digits")
        return Instrument("us_bank", routing=routing, account=account)
    if kind == "iban":
        iban = _squash(str(raw.get("iban", "")))
        bic = _squash(str(raw.get("bic", "") or ""))
        if not iban_ok(iban):
            raise InvalidInstrument("IBAN fails the ISO 13616 length or mod-97 check")
        if bic and not _BIC.match(bic):
            raise InvalidInstrument(f"BIC {bic!r} is not 8 or 11 characters of ISO 9362 form")
        if bic and bic[4:6] != iban[:2]:
            raise InvalidInstrument(f"BIC country {bic[4:6]} differs from IBAN country {iban[:2]}")
        return Instrument("iban", iban=iban, bic=bic)
    if kind == "evm":
        address = str(raw.get("address", "")).strip()
        chain = raw.get("chain_id", 1)
        if not isinstance(chain, int) or isinstance(chain, bool) or chain <= 0:
            raise InvalidInstrument("chain_id must be a positive integer (EIP-155)")
        if not evm_ok(address):
            raise InvalidInstrument("address is not 0x plus 40 hex digits with a valid EIP-55 checksum")
        return Instrument("evm", address=address, chain_id=chain)
    raise InvalidInstrument(f"unknown instrument kind {kind!r}; use one of {', '.join(KINDS)}")
