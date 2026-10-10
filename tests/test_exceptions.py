"""exceptions.py: loading, validation and application of risk acceptances."""
import datetime as dt
import hashlib
import re

import pytest

import exceptions

TODAY = dt.date(2026, 10, 5)

VALID = """
[[exception]]
id          = "EXC-2026-001"
assertion   = "1.1-A15"
resource    = "aws_s3_bucket_policy.exchange"
reason      = "Partner reconciliation feed until DR account onboarding completes."
risk_owner  = "Head of Payments Operations"
approved_by = "CISO"
ticket      = "RISK-1432"
approved_on = 2026-10-05
expires_on  = 2027-04-05
"""


def _write(tmp_path, text, name="exceptions.toml", encoding="utf-8"):
    path = tmp_path / name
    path.write_text(text, encoding=encoding)
    return path


def _load(tmp_path, text, today=TODAY):
    return exceptions.load(_write(tmp_path, text), today)


def _with(**changes):
    """VALID with fields replaced (value None removes the field)."""
    lines = []
    for line in VALID.strip().splitlines():
        key = line.split("=")[0].strip()
        if key in changes:
            if changes[key] is None:
                continue
            line = f"{key} = {changes[key]}"
        lines.append(line)
    return "\n".join(lines) + "\n"


# loading

def test_valid_file_loads_one_record_and_its_hash(tmp_path):
    path = _write(tmp_path, VALID)
    records, digest = exceptions.load(path, TODAY)
    assert len(records) == 1
    r = records[0]
    assert (r.id, r.assertion, r.resource) == ("EXC-2026-001", "1.1-A15", "aws_s3_bucket_policy.exchange")
    assert r.approved_on == dt.date(2026, 10, 5) and r.expires_on == dt.date(2027, 4, 5)
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()


def test_record_as_json_uses_iso_dates(tmp_path):
    (r,), _ = _load(tmp_path, VALID)
    assert r.as_json()["approved_on"] == "2026-10-05"
    assert r.as_json()["expires_on"] == "2027-04-05"
    assert set(r.as_json()) == set(exceptions.FIELDS)


def test_empty_file_means_no_records(tmp_path):
    records, _ = _load(tmp_path, "")
    assert records == []


def test_bom_is_accepted(tmp_path):
    path = _write(tmp_path, VALID, encoding="utf-8-sig")
    records, _ = exceptions.load(path, TODAY)
    assert len(records) == 1


def test_text_fields_are_trimmed(tmp_path):
    (r,), _ = _load(tmp_path, _with(resource='"  aws_s3_bucket_policy.exchange  "'))
    assert r.resource == "aws_s3_bucket_policy.exchange"


# validation: every case is a configuration error

@pytest.mark.parametrize("text, message", [
    ("this is = = not toml", "not valid TOML"),
    ('title = "x"\n' + VALID, "unexpected top-level key"),
    ('exception = "x"\n', "array of tables"),
    (_with(ticket=None), "missing field(s): ticket"),
    (_with(reason='""'), "reason must be a non-empty string"),
    (_with(reason='"   "'), "reason must be a non-empty string"),
    (_with(risk_owner="42"), "risk_owner must be a non-empty string"),
    (VALID.replace('ticket      = "RISK-1432"', 'ticket = "RISK-1432"\nexpires = 2027-01-01'), "unknown field(s): expires"),
    (_with(assertion='"1.1-15"'), "is not an assertion id"),
    (_with(assertion='"A15"'), "is not an assertion id"),
    (_with(resource='"aws_s3_bucket_policy.*"'), "wildcards"),
    (_with(resource='"aws_s3_bucket_policy.exchange?"'), "wildcards"),
    (_with(approved_on='"2026-10-05"'), "approved_on must be a TOML date"),
    (_with(expires_on="2027-04-05T00:00:00"), "expires_on must be a TOML date"),
    (_with(expires_on="2026-10-05"), "expires_on must be after approved_on"),
    (_with(expires_on="2026-10-01"), "expires_on must be after approved_on"),
    (_with(expires_on="2027-04-06"), "more than 6 months"),
    (_with(approved_on="2026-10-06", expires_on="2027-01-01"), "is in the future"),
])
def test_invalid_files_are_refused(tmp_path, text, message):
    with pytest.raises(exceptions.ExceptionFileError, match=re.escape(message)):
        _load(tmp_path, text)


def test_error_names_the_record(tmp_path):
    with pytest.raises(exceptions.ExceptionFileError, match="EXC-2026-001"):
        _load(tmp_path, _with(ticket=None))


def test_error_names_the_position_when_the_id_is_missing(tmp_path):
    with pytest.raises(exceptions.ExceptionFileError, match="exception #1"):
        _load(tmp_path, _with(id=None))


def test_duplicate_id_is_refused(tmp_path):
    second = VALID.replace("aws_s3_bucket_policy.exchange", "aws_s3_bucket_policy.other")
    with pytest.raises(exceptions.ExceptionFileError, match="used more than once"):
        _load(tmp_path, VALID + second)


def test_duplicate_assertion_and_resource_is_refused(tmp_path):
    second = VALID.replace("EXC-2026-001", "EXC-2026-002")
    with pytest.raises(exceptions.ExceptionFileError, match="already covers 1.1-A15"):
        _load(tmp_path, VALID + second)


# the six-month limit

def test_exactly_six_months_is_accepted(tmp_path):
    records, _ = _load(tmp_path, _with(expires_on="2027-04-05"))
    assert records[0].expires_on == dt.date(2027, 4, 5)


def test_one_day_over_six_months_is_refused(tmp_path):
    with pytest.raises(exceptions.ExceptionFileError, match="latest allowed: 2027-04-05"):
        _load(tmp_path, _with(expires_on="2027-04-06"))


@pytest.mark.parametrize("start, expected", [
    (dt.date(2026, 8, 31), dt.date(2027, 2, 28)),   # clamped to the month's end
    (dt.date(2027, 8, 31), dt.date(2028, 2, 29)),   # leap year
    (dt.date(2026, 10, 5), dt.date(2027, 4, 5)),
    (dt.date(2026, 7, 15), dt.date(2027, 1, 15)),   # across the year end
])
def test_add_months_clamps_to_the_last_day_of_the_month(start, expected):
    assert exceptions.add_months(start, 6) == expected


def test_month_end_record_is_limited_to_the_clamped_date(tmp_path):
    text = _with(approved_on="2026-08-31", expires_on="2027-02-28")
    assert len(_load(tmp_path, text)[0]) == 1
    with pytest.raises(exceptions.ExceptionFileError, match="more than 6 months"):
        _load(tmp_path, _with(approved_on="2026-08-31", expires_on="2027-03-01"))


def test_approved_today_is_accepted(tmp_path):
    assert len(_load(tmp_path, VALID, today=dt.date(2026, 10, 5))[0]) == 1


# apply

A15 = ("CSCF 1.1 [1.1-A15]: S3 bucket policy grants account 444455556666, outside the "
       "declared Swift trust boundary (§ Boundary Protection). (resource: aws_s3_bucket_policy.exchange)")
A15_CANONICAL = ("CSCF 1.1 [1.1-A15]: S3 bucket policy grants a canonical user, which cannot be "
                 "placed inside the declared Swift trust boundary (§ Boundary Protection). "
                 "(resource: aws_s3_bucket_policy.exchange)")
A16 = ("CSCF 2.1 [2.1-A16]: S3 bucket policy does not enforce TLS-only access (§ Impl. Guidelines). "
       "(resource: aws_s3_bucket_policy.exchange)")
A9 = "CSCF 1.1 [1.1-A9]: No VPC Flow Log capturing ALL traffic is configured (§ c)."


def _report(violations_by_control, undetermined=None):
    import findings
    report = {
        "controls": [
            {"control": c, "module": f"ctrl_{c.replace('.', '_')}", "violations": list(v),
             "assertions": [], "rules_fired": 0, "violation_instances": 0}
            for c, v in violations_by_control.items()
        ],
        "summary": {},
    }
    findings.recount(report)
    if undetermined is not None:
        report["undetermined"] = undetermined
    return report


def _record(**changes):
    base = dict(
        id="EXC-2026-001", assertion="1.1-A15", resource="aws_s3_bucket_policy.exchange",
        reason="Partner feed.", risk_owner="Head of Payments Operations", approved_by="CISO",
        ticket="RISK-1432", approved_on=dt.date(2026, 10, 5), expires_on=dt.date(2027, 4, 5),
    )
    base.update(changes)
    return exceptions.Record(**base)


def _apply(report, records, today=TODAY):
    exceptions.apply(report, records, today, "exceptions/exceptions.toml", "abc123")
    return report


def test_active_exception_moves_the_finding_and_the_run_passes():
    report = _apply(_report({"1.1": [A15]}), [_record()])
    c = report["controls"][0]
    assert c["violations"] == []
    assert c["excepted"] == [{"finding": A15, "exception": _record().as_json()}]
    assert report["summary"]["result"] == "PASS"
    assert report["summary"]["excepted_instances"] == 1
    assert report["exceptions"] == {
        "file": "exceptions/exceptions.toml", "sha256": "abc123", "evaluated_on": "2026-10-05",
        "applied": ["EXC-2026-001"], "expired": [], "unused": [],
    }


def test_one_of_two_violations_excepted_still_fails():
    report = _apply(_report({"1.1": [A15], "2.1": [A16]}), [_record()])
    assert report["summary"]["result"] == "FAIL"
    assert report["summary"]["total_violation_instances"] == 1
    assert report["summary"]["controls_with_violations"] == 1
    assert report["summary"]["distinct_assertions_fired"] == 1
    assert report["controls"][0]["rules_fired"] == 0
    assert report["controls"][1]["violations"] == [A16]


def test_expired_exception_keeps_the_violation_and_is_listed():
    record = _record(approved_on=dt.date(2026, 4, 1), expires_on=dt.date(2026, 10, 1))
    report = _apply(_report({"1.1": [A15]}), [record])
    assert report["controls"][0]["violations"] == [A15]
    assert report["controls"][0]["excepted"] == []
    assert report["summary"]["result"] == "FAIL"
    assert report["exceptions"]["expired"] == [
        {"id": "EXC-2026-001", "expired_on": "2026-10-01", "findings": 1}
    ]
    assert report["exceptions"]["applied"] == [] and report["exceptions"]["unused"] == []


def test_unused_exception_is_listed_and_does_not_fail_the_run():
    record = _record(id="EXC-2026-004", resource="aws_s3_bucket_policy.elsewhere")
    report = _apply(_report({"1.1": []}), [record])
    assert report["summary"]["result"] == "PASS"
    assert report["exceptions"]["unused"] == ["EXC-2026-004"]


@pytest.mark.parametrize("today, active", [
    (dt.date(2026, 10, 5), True),   # approved_on
    (dt.date(2027, 4, 5), True),    # expires_on: still active
    (dt.date(2027, 4, 6), False),   # the day after: expired
])
def test_dates_are_inclusive(today, active):
    report = _apply(_report({"1.1": [A15]}), [_record()], today=today)
    assert (report["summary"]["result"] == "PASS") is active


@pytest.mark.parametrize("resource", [
    "aws_s3_bucket_policy.exchange2",
    "module.x.aws_s3_bucket_policy.exchange",
    "aws_s3_bucket_policy.exchang",
])
def test_address_match_is_exact(resource):
    report = _apply(_report({"1.1": [A15]}), [_record(resource=resource)])
    assert report["summary"]["result"] == "FAIL"


def test_indexed_address_matches_exactly():
    finding = A15.replace("aws_s3_bucket_policy.exchange)", 'module.zone.aws_s3_bucket_policy.x["a"])')
    record = _record(resource='module.zone.aws_s3_bucket_policy.x["a"]')
    report = _apply(_report({"1.1": [finding]}), [record])
    assert report["summary"]["result"] == "PASS"


def test_one_record_covers_every_finding_with_its_pair():
    report = _apply(_report({"1.1": [A15, A15_CANONICAL]}), [_record()])
    assert len(report["controls"][0]["excepted"]) == 2
    assert report["summary"]["excepted_instances"] == 2
    assert report["summary"]["result"] == "PASS"


def test_trimmed_record_matches(tmp_path):
    (record,), _ = _load(tmp_path, _with(resource='"  aws_s3_bucket_policy.exchange  "'))
    report = _apply(_report({"1.1": [A15]}), [record])
    assert report["summary"]["result"] == "PASS"


def test_absence_finding_is_never_excepted():
    # A record cannot have an empty resource, so an address-less finding never matches.
    report = _apply(_report({"1.1": [A9]}), [_record(assertion="1.1-A9")])
    assert report["controls"][0]["violations"] == [A9]
    assert report["exceptions"]["unused"] == ["EXC-2026-001"]


def test_undetermined_entries_are_untouched():
    undetermined = [{"control": "1.1", "assertion": "1.1-A15", "resource": "aws_s3_bucket_policy.exchange",
                     "attribute": "policy", "kind": "unbound-environment", "reason": "x"}]
    report = _apply(_report({"1.1": []}, undetermined=list(undetermined)), [_record()])
    assert report["undetermined"] == undetermined
    assert report["exceptions"]["unused"] == ["EXC-2026-001"]


def test_no_records_still_records_the_file():
    report = _apply(_report({"1.1": [A15]}), [])
    assert report["summary"]["result"] == "FAIL"
    assert report["summary"]["excepted_instances"] == 0
    assert report["controls"][0]["excepted"] == []
    assert report["exceptions"]["applied"] == []


def test_shipped_example_is_valid_and_is_never_the_default():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    example = root / "exceptions" / "exceptions.example.toml"
    records, _ = exceptions.load(example, dt.date(2026, 10, 5))
    assert [r.id for r in records] == ["EXC-2026-001"]
    assert records[0].resource == "aws_s3_bucket_policy.reporting_partner"
    assert example.name != "exceptions.toml"  # the gate's default name: never loaded


def test_suite_never_reads_the_repository_exceptions_file():
    # An institution that follows the adoption guide adds exceptions/exceptions.toml;
    # the conformance suite must not pick it up, or its fixtures' verdicts would change.
    import gate
    from pathlib import Path
    real = Path(__file__).resolve().parents[1] / "exceptions" / "exceptions.toml"
    assert gate.DEFAULT_EXCEPTIONS != real
