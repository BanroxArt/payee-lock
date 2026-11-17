from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import EX, request

from payeelock import Policy, PolicyError, audit, check, load, request_from, vendors_from
from payeelock.__main__ import main
from payeelock.model import RecordError
from payeelock.policy import from_dict


def test_example_policy_equals_defaults() -> None:
    p = load(EX / "policy.toml")
    d = Policy()
    assert p.irreversible_rails == d.irreversible_rails
    assert p.cooling_tiers == d.cooling_tiers
    assert p.dual_threshold_cents == d.dual_threshold_cents
    assert len(p.digest) == 64


@pytest.mark.parametrize(
    "doc",
    [
        {"callback": {"max_age_hour": 5}},
        {"callbacks": {}},
        {"irreversible_rail": ["wire"]},
        {"dual_approval": {"approvers": 0}},
        {"checks": {"country_change": "warn"}},
        {"callback": {"require_read_back": "yes"}},
        {"irreversible_rails": "wire"},
    ],
)
def test_policy_rejects_typos_and_bad_values(doc: dict[str, object]) -> None:
    with pytest.raises(PolicyError):
        from_dict(doc)


def test_cooling_hours_takes_the_highest_tier() -> None:
    p = Policy()
    assert p.cooling_hours(1) == 24
    assert p.cooling_hours(2_500_000) == 48
    assert p.cooling_hours(50_000_000) == 72


def test_naive_times_are_rejected() -> None:
    with pytest.raises(RecordError, match="UTC offset"):
        request_from(request(requested_at="2026-11-19T10:00:00"))


def _decision(vendors_doc: dict[str, object]):  # type: ignore[no-untyped-def]
    return check(Policy(), vendors_from(vendors_doc), request_from(request()))


def test_audit_chain_and_tamper_detection(tmp_path: Path, vendors_doc: dict[str, object]) -> None:
    log = tmp_path / "a.jsonl"
    for _ in range(3):
        audit.append(log, _decision(vendors_doc), "tester")
    ok, n, _ = audit.verify(log)
    assert ok and n == 3
    text = log.read_text()
    assert "9917730045" not in text  # full account number never logged
    lines = text.splitlines()

    edited = json.loads(lines[1])
    edited["decision"]["outcome"] = "allow"
    log.write_text("\n".join([lines[0], json.dumps(edited), lines[2]]) + "\n")
    ok, n, msg = audit.verify(log)
    assert not ok and n == 1 and "modified" in msg

    log.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, _, msg = audit.verify(log)
    assert not ok and "sequence" in msg

    swapped = json.loads(lines[1])
    swapped["seq"] = 1
    log.write_text("\n".join([json.dumps(swapped)]) + "\n")
    assert not audit.verify(log)[0]


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "log.jsonl"
    args = ["check", "--policy", str(EX / "policy.toml"), "--vendors", str(EX / "vendors.json")]
    reqs = json.loads((EX / "requests.json").read_text())
    expected = {"pay-001": 0, "pay-002": 2, "pay-003": 3}
    for r in reqs:
        f = tmp_path / f"{r['id']}.json"
        f.write_text(json.dumps(r))
        assert main([*args, "--request", str(f), "--log", str(log)]) == expected[r["id"]]
    assert main([*args, "--request", str(EX / "requests.json")]) == 3
    assert main(["verify-log", str(log)]) == 0
    out = capsys.readouterr().out
    assert "PL-CALLBACK-SUPPLIED-CONTACT" in out and "chain intact" in out
    assert main([*args, "--request", str(tmp_path / "pay-001.json"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "allow"


def test_cli_validate_and_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["validate", '{"kind": "iban", "iban": "GB82 WEST 1234 5698 7654 32"}']) == 0
    assert "GB82...5432" in capsys.readouterr().out
    assert main(["validate", '{"kind": "us_bank", "routing": "123456789", "account": "1234"}']) == 1
    bad = tmp_path / "bad.toml"
    bad.write_text("[nope]\n")
    rc = main(
        [
            "check",
            "--policy",
            str(bad),
            "--vendors",
            str(EX / "vendors.json"),
            "--request",
            str(EX / "requests.json"),
        ]
    )
    assert rc == 1
