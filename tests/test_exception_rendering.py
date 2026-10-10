"""The attestation and the step summary show accepted risks, never as a clean pass."""
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evidence"))

import report  # noqa: E402
import step_summary  # noqa: E402

FINDING = ("CSCF 1.1 [1.1-A15]: S3 bucket policy grants account 444455556666, outside the "
           "declared Swift trust boundary (§ Boundary Protection). (resource: aws_s3_bucket_policy.exchange)")
RECORD = {
    "id": "EXC-2026-001", "assertion": "1.1-A15", "resource": "aws_s3_bucket_policy.exchange",
    "reason": "Partner feed.", "risk_owner": "Head of Payments Operations", "approved_by": "CISO",
    "ticket": "RISK-1432", "approved_on": "2026-10-05", "expires_on": "2027-04-05",
}
BASE = {
    "schema": "swift-cscf-evidence/v1", "cscf_version": "v2026", "plan_file": "plan.json",
    "plan_sha256": "0" * 64, "opa_version": "1.17.0", "generated_at": "2026-10-05T00:00:00+00:00",
    "library": {"version": "2.1.1", "digest": "sha256:abc"},
    "controls": [{"control": "1.1", "module": "ctrl_1_1", "violations": [], "assertions": [],
                  "rules_fired": 0, "violation_instances": 0}],
    "summary": {"total_violation_instances": 0, "distinct_assertions_fired": 0,
                "controls_with_violations": 0, "result": "PASS"},
}


def _with_exception(expired=(), unused=()):
    ev = copy.deepcopy(BASE)
    ev["controls"][0]["excepted"] = [{"finding": FINDING, "exception": RECORD}]
    ev["summary"]["excepted_instances"] = 1
    ev["exceptions"] = {"file": "exceptions/exceptions.toml", "sha256": "f" * 64,
                        "evaluated_on": "2026-10-05", "applied": ["EXC-2026-001"],
                        "expired": list(expired), "unused": list(unused)}
    return ev


def test_html_headline_never_reads_as_a_clean_pass():
    html = report.render_html(_with_exception(), None)
    assert '<div class="tag">PASS WITH 1 ACCEPTED RISK</div>' in html
    assert '<div class="tag">COMPLIANT</div>' not in html
    assert "COMPLIANT WITH" not in html  # the banner says "not attested as compliant"


def test_html_headline_keeps_undetermined_when_both_apply():
    ev = _with_exception()
    ev["undetermined"] = [{"control": "1.1", "assertion": "1.1-A9", "resource": "",
                           "attribute": "(whole plan)", "kind": "incomplete-plan", "reason": "x"}]
    html = report.render_html(ev, None)
    assert "PASS WITH 1 ACCEPTED RISK, WITH UNDETERMINED CHECKS" in html


def test_html_lists_the_accepted_risk_with_its_approval_trail():
    html = report.render_html(_with_exception(), None)
    assert "Accepted Risks (Exceptions)" in html
    for value in ("EXC-2026-001", "Head of Payments Operations", "CISO", "RISK-1432",
                  "2027-04-05", "aws_s3_bucket_policy.exchange"):
        assert value in html
    assert "<th class=\"num\">Excepted</th>" in html


def test_html_lists_expired_and_unused_exceptions():
    ev = _with_exception(expired=[{"id": "EXC-2025-007", "expired_on": "2026-09-30", "findings": 1}],
                         unused=["EXC-2026-004"])
    html = report.render_html(ev, None)
    assert "EXC-2025-007" in html and "2026-09-30" in html
    assert "EXC-2026-004" in html


def test_html_without_exceptions_is_unchanged():
    html = report.render_html(copy.deepcopy(BASE), None)
    assert "Accepted Risks" not in html
    assert "Excepted" not in html
    assert '<div class="tag">COMPLIANT</div>' in html


def test_step_summary_says_pass_with_accepted_risk_and_lists_it():
    md = step_summary.render(_with_exception(), "CSCF compliance gate", None)
    assert "### PASS with 1 accepted risk(s): the change may proceed" in md
    assert "#### Excepted: 1 finding(s), accepted risk, not passed" in md
    assert "`EXC-2026-001`" in md and "Head of Payments Operations" in md and "2027-04-05" in md


def test_step_summary_without_exceptions_is_unchanged():
    md = step_summary.render(copy.deepcopy(BASE), "CSCF compliance gate", None)
    assert "### PASS: the change may proceed" in md
    assert "Excepted" not in md


def test_html_detail_section_does_not_claim_everything_compliant():
    html = report.render_html(_with_exception(), None)
    assert "evaluated to compliant" not in html
    assert "accepted risks" in html.split("Detailed Findings")[1].split("</section>")[0]
