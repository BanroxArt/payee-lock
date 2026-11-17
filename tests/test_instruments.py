import pytest
from hypothesis import given
from hypothesis import strategies as st

from payeelock.instruments import InvalidInstrument, aba_ok, eip55, evm_ok, iban_ok, parse

# Test vectors from EIP-55.
EIP55 = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]


def test_aba_check_digit() -> None:
    assert aba_ok("011000015")
    assert aba_ok("021000021")
    assert not aba_ok("011000016")
    assert not aba_ok("01100001")
    assert not aba_ok("01100001a")


@given(st.text("0123456789", min_size=8, max_size=8), st.integers(0, 8), st.integers(1, 9))
def test_aba_catches_every_single_digit_error(prefix: str, pos: int, delta: int) -> None:
    weights = (3, 7, 1) * 3
    partial = sum(int(d) * w for d, w in zip(prefix, weights[:8], strict=True))
    good = prefix + str((-partial) % 10)
    assert aba_ok(good)
    digits = list(good)
    digits[pos] = str((int(digits[pos]) + delta) % 10)
    assert not aba_ok("".join(digits))


def test_iban() -> None:
    assert iban_ok("GB82WEST12345698765432")
    assert iban_ok("DE89370400440532013000")
    assert not iban_ok("GB82WEST12345698765433")
    assert not iban_ok("DE8937040044053201300")  # one short for DE
    assert not iban_ok("gb82west12345698765432")  # parse() upper-cases first


def test_iban_parse_normalizes_and_checks_bic_country() -> None:
    a = parse({"kind": "iban", "iban": "gb82 west 1234 5698 7654 32"})
    b = parse({"kind": "iban", "iban": "GB82WEST12345698765432", "bic": "WESTGB2L"})
    assert a.fingerprint() == b.fingerprint()
    with pytest.raises(InvalidInstrument, match="BIC country"):
        parse({"kind": "iban", "iban": "GB82WEST12345698765432", "bic": "DEUTDEFF"})


@pytest.mark.parametrize("addr", EIP55)
def test_eip55_vectors(addr: str) -> None:
    assert eip55(addr.lower()) == addr
    assert evm_ok(addr)


def test_evm_bad_checksum_and_single_case() -> None:
    bad = EIP55[0][:-1] + ("d" if EIP55[0][-1] == "D" else "D")
    assert not evm_ok(bad)
    lower = parse({"kind": "evm", "address": EIP55[0].lower()})
    assert not lower.checksummed
    assert parse({"kind": "evm", "address": EIP55[0]}).checksummed
    assert lower.fingerprint() == parse({"kind": "evm", "address": EIP55[0]}).fingerprint()
    assert lower.fingerprint() != parse({"kind": "evm", "address": EIP55[0], "chain_id": 8453}).fingerprint()


def test_one_digit_change_is_a_different_destination() -> None:
    a = parse({"kind": "us_bank", "routing": "011000015", "account": "4402187731"})
    b = parse({"kind": "us_bank", "routing": "011000015", "account": "4402187732"})
    assert a.fingerprint() != b.fingerprint()
    assert a.masked() == "ABA 011000015 acct ...7731"
    assert "4402187731" not in a.fingerprint()


@pytest.mark.parametrize(
    "raw",
    [
        {"kind": "us_bank", "routing": "011000016", "account": "1234"},
        {"kind": "us_bank", "routing": "011000015", "account": "12"},
        {"kind": "evm", "address": "0x1234"},
        {"kind": "evm", "address": EIP55[0], "chain_id": 0},
        {"kind": "evm", "address": EIP55[0], "chain_id": True},
        {"kind": "paypal", "handle": "x"},
    ],
)
def test_rejects(raw: dict[str, object]) -> None:
    with pytest.raises(InvalidInstrument):
        parse(raw)
