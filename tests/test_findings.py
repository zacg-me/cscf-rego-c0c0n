"""findings.py: the message parsing and recount shared by the gate and exceptions."""
import findings

A15 = ("CSCF 1.1 [1.1-A15]: S3 bucket policy grants account 444455556666, outside the "
       "declared Swift trust boundary (§ Boundary Protection). (resource: aws_s3_bucket_policy.exchange)")
A9 = "CSCF 1.1 [1.1-A9]: No VPC Flow Log capturing ALL traffic is configured (§ c)."


def test_instance_extracts_assertion_and_resource():
    assert findings.instance(A15) == ("1.1-A15", "aws_s3_bucket_policy.exchange")


def test_absence_finding_has_an_empty_resource():
    assert findings.instance(A9) == ("1.1-A9", "")


def test_message_without_an_assertion_id_is_not_an_instance():
    assert findings.instance("something else entirely") is None


def _report(*controls):
    return {
        "controls": [
            {"control": c, "violations": list(v), "assertions": [], "rules_fired": 0,
             "violation_instances": 0}
            for c, v in controls
        ],
        "summary": {},
    }


def test_recount_recomputes_every_figure():
    report = _report(("1.1", [A15, A9, A15]), ("6.4", []))
    findings.recount(report)
    c11, c64 = report["controls"]
    assert c11["assertions"] == ["1.1-A15", "1.1-A9"]
    assert c11["rules_fired"] == 2
    assert c11["violation_instances"] == 3
    assert c64["violation_instances"] == 0
    assert report["summary"] == {
        "total_violation_instances": 3,
        "distinct_assertions_fired": 2,
        "controls_with_violations": 1,
        "result": "FAIL",
    }


def test_recount_of_an_empty_report_passes():
    report = _report(("1.1", []))
    findings.recount(report)
    assert report["summary"]["result"] == "PASS"
    assert report["summary"]["total_violation_instances"] == 0
