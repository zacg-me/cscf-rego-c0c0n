"""The exception mechanism end to end through gate.main(), with OPA.

The plan comes from test_trust_boundary._plan: a Swift-zone bucket whose policy
grants the partner account 444455556666, outside the declared boundary, so
1.1-A15 fires on aws_s3_bucket_policy.exchange. Running only ctrl_1_1 on an
incremental plan turns the other 1.1 finding (an absence, 1.1-A9) into an
undetermined check, leaving 1.1-A15 as the only violation.
"""
import datetime as dt
import hashlib
import json
import sys

import pytest

import gate
from test_trust_boundary import PARTNER, _plan

TODAY = dt.datetime.now(dt.timezone.utc).date()


def _exceptions_file(tmp_path, resource="aws_s3_bucket_policy.exchange", name="exceptions.toml"):
    path = tmp_path / name
    path.write_text(
        f"""[[exception]]
id          = "EXC-TEST-001"
assertion   = "1.1-A15"
resource    = "{resource}"
reason      = "Test."
risk_owner  = "Head of Payments Operations"
approved_by = "CISO"
ticket      = "RISK-1"
approved_on = {TODAY.isoformat()}
expires_on  = {(TODAY + dt.timedelta(days=30)).isoformat()}
""",
        encoding="utf-8",
    )
    return path


def _run(monkeypatch, opa, plan, *extra):
    argv = ["gate.py", "--plan", str(plan), "--controls", "ctrl_1_1",
            "--plan-scope", "incremental", "--opa", opa, *extra]
    monkeypatch.setattr(sys, "argv", argv)
    return gate.main()


@pytest.fixture
def plan(tmp_path):
    return _plan(tmp_path, {"AWS": f"arn:aws:iam::{PARTNER}:root"})


@pytest.fixture(autouse=True)
def no_default_file(monkeypatch, tmp_path):
    # Never pick up a real exceptions/exceptions.toml from the working tree.
    monkeypatch.setattr(gate, "DEFAULT_EXCEPTIONS", tmp_path / "absent" / "exceptions.toml")


def test_without_exceptions_the_finding_blocks_and_evidence_is_unchanged(monkeypatch, opa, plan, tmp_path):
    evidence = tmp_path / "evidence.json"
    assert _run(monkeypatch, opa, plan, "--evidence", str(evidence)) == 1
    doc = json.loads(evidence.read_text(encoding="utf-8"))
    assert "exceptions" not in doc
    assert "excepted_instances" not in doc["summary"]
    assert all("excepted" not in c for c in doc["controls"])


def test_exception_turns_the_run_into_a_pass_and_is_in_the_evidence(monkeypatch, opa, plan, tmp_path, capsys):
    path = _exceptions_file(tmp_path)
    evidence = tmp_path / "evidence.json"
    assert _run(monkeypatch, opa, plan, "--exceptions", str(path), "--evidence", str(evidence)) == 0
    doc = json.loads(evidence.read_text(encoding="utf-8"))
    (c11,) = doc["controls"]
    assert c11["violations"] == []
    assert len(c11["excepted"]) == 1
    assert "[1.1-A15]" in c11["excepted"][0]["finding"]
    assert c11["excepted"][0]["exception"]["id"] == "EXC-TEST-001"
    assert doc["summary"]["result"] == "PASS"
    assert doc["summary"]["excepted_instances"] == 1
    assert doc["exceptions"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert doc["exceptions"]["applied"] == ["EXC-TEST-001"]
    assert doc["schema"] == "swift-cscf-evidence/v1"
    out = capsys.readouterr().out
    assert "EXCEPTED (1) -- accepted risk, not passed:" in out
    assert "~ CSCF 1.1 [1.1-A15] aws_s3_bucket_policy.exchange" in out
    assert "EXC-TEST-001, owner Head of Payments Operations" in out
    assert ", 1 excepted" in out


def test_unused_exception_is_reported_on_the_console(monkeypatch, opa, plan, tmp_path, capsys):
    path = _exceptions_file(tmp_path, resource="aws_s3_bucket_policy.elsewhere")
    assert _run(monkeypatch, opa, plan, "--exceptions", str(path)) == 1
    assert "UNUSED EXCEPTION:  EXC-TEST-001 matched no finding" in capsys.readouterr().out


def test_default_file_is_picked_up(monkeypatch, opa, plan, tmp_path):
    monkeypatch.setattr(gate, "DEFAULT_EXCEPTIONS", _exceptions_file(tmp_path))
    assert _run(monkeypatch, opa, plan) == 0


def test_explicit_missing_file_is_a_configuration_error(monkeypatch, opa, plan, tmp_path, capsys):
    assert _run(monkeypatch, opa, plan, "--exceptions", str(tmp_path / "nope.toml")) == 2
    assert "exceptions file not found" in capsys.readouterr().err


def test_invalid_file_is_a_configuration_error(monkeypatch, opa, plan, tmp_path, capsys):
    path = tmp_path / "bad.toml"
    path.write_text('[[exception]]\nid = "EXC-1"\n', encoding="utf-8")
    assert _run(monkeypatch, opa, plan, "--exceptions", str(path)) == 2
    assert "missing field(s)" in capsys.readouterr().err


def test_file_outside_repo_is_recorded_as_given(monkeypatch, opa, plan, tmp_path):
    path = _exceptions_file(tmp_path)
    evidence = tmp_path / "evidence.json"
    _run(monkeypatch, opa, plan, "--exceptions", str(path), "--evidence", str(evidence))
    assert json.loads(evidence.read_text(encoding="utf-8"))["exceptions"]["file"] == str(path)


def test_signed_evidence_with_exceptions_verifies_and_detects_an_edit(monkeypatch, opa, plan, tmp_path):
    pytest.importorskip("cryptography")
    import evidence_signing
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    evidence = tmp_path / "evidence.json"
    path = _exceptions_file(tmp_path)
    assert _run(monkeypatch, opa, plan, "--exceptions", str(path), "--evidence", str(evidence),
                "--signing-key", str(key_path)) == 0

    doc = json.loads(evidence.read_text(encoding="utf-8"))
    assert evidence_signing.verify(doc, key.public_key())[0] == "valid"
    doc["controls"][0]["excepted"][0]["exception"]["expires_on"] = "2099-01-01"
    assert evidence_signing.verify(doc, key.public_key())[0] == "invalid"


def test_console_control_line_marks_an_excepted_control(monkeypatch, opa, plan, tmp_path, capsys):
    path = _exceptions_file(tmp_path)
    _run(monkeypatch, opa, plan, "--exceptions", str(path))
    out = capsys.readouterr().out
    assert "[EXCEPTED] Control 1.1" in out
    assert "[PASS] Control 1.1" not in out
