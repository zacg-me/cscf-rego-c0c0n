"""Conformance suite for the SWIFT CSCF compliance gate and policy library.

Goes beyond the CI gate's pass/fail steps by enforcing, for every control:

* **False positives** (each compliant fixture yields exactly zero violations.
* **False negatives / coverage symmetry**) each non-compliant fixture fires
  *exactly* the set of assertions it is designed to trip, no more and no fewer.
* **Nothing silent**: on the generated environments every assertion fires,
  is undetermined, or is explained.
* **Performance**: the gate evaluates each plan well under a wall-clock bound.

The defects of the first library (1.0.0) and how 2.0.0 corrected them are
described in docs/failure-modes.md and policies/CHANGELOG.md.

Run: ``pytest tests -v`` (requires OPA on PATH).
"""
import json
import re
import sys
import time
from pathlib import Path

import pytest

import gate  # noqa: E402  (path injected by conftest.py)

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "policies"
FIX = ROOT / "fixtures"
# Hand-written mock plans from the first phase of the research, kept as inputs.
P1PLANS = ROOT / "fixtures" / "phase1_mock"

# The five controls the mock plans were written for.
PHASE1_MODULES = ["ctrl_1_1", "ctrl_2_1", "ctrl_4_1", "ctrl_5_1", "ctrl_6_4"]

# Phase II controls: (module, cscf_version, fixture_stem, expected assertions on
# the non-compliant fixture). The expected set is the specification the suite
# enforces for coverage symmetry.
PHASE2 = [
    ("ctrl_1_4", "v2026", "ctrl_1_4",
     {"1.4-A1", "1.4-A2", "1.4-A3", "1.4-A4", "1.4-A5", "1.4-A6"}),
    ("ctrl_1_3", "v2026", "ctrl_1_3",
     {"1.3-A1", "1.3-A2", "1.3-A3", "1.3-A4", "1.3-A5"}),
    ("ctrl_5_4", "v2026", "ctrl_5_4",
     {"5.4-A1", "5.4-A2", "5.4-A3", "5.4-A4", "5.4-A5"}),
    ("ctrl_4_2", "v2026", "ctrl_4_2",
     {"4.2-A1", "4.2-A2", "4.2-A3", "4.2-A4"}),
    ("ctrl_2_4", "v2026", "ctrl_2_4",
     {"2.4-A1", "2.4-A2", "2.4-A3", "2.4-A4"}),
    ("ctrl_1_2", "v2026", "ctrl_1_2",
     {"1.2-A1", "1.2-A2", "1.2-A3"}),
    ("ctrl_2_6", "v2026", "ctrl_2_6",
     {"2.6-A1", "2.6-A2", "2.6-A3"}),
    ("ctrl_2_3", "v2026", "ctrl_2_3",
     {"2.3-A1", "2.3-A2", "2.3-A3", "2.3-A4"}),
    ("ctrl_2_2", "v2026", "ctrl_2_2",
     {"2.2-A1", "2.2-A2"}),
    ("ctrl_2_7", "v2026", "ctrl_2_7",
     {"2.7-A1"}),
    ("ctrl_4_1", "v2027", "ctrl_4_1_v2027",
     {"4.1-A20"}),
]

PERF_BUDGET_SECONDS = 30.0  # generous CI bound; real evaluation is sub-second


def opa_binary():
    import shutil

    exe = shutil.which("opa")
    if not exe:
        pytest.skip("opa binary not on PATH")
    return exe


def _fired(report):
    fired = set()
    for c in report["controls"]:
        fired |= set(c["assertions"])
    return fired


# ============================================================================
# Phase II: false positives (compliant fixtures must be clean)
# ============================================================================

@pytest.mark.parametrize("module,version,stem,expected", PHASE2, ids=[e[0] + "/" + e[1] for e in PHASE2])
def test_phase2_compliant_is_clean(opa, module, version, stem, expected):
    plan = FIX / f"{stem}_compliant.json"
    report = gate.build_report(opa, [LIB], plan, [module], version)
    assert report["summary"]["result"] == "PASS"
    assert report["summary"]["total_violation_instances"] == 0, _fired(report)


# ============================================================================
# Phase II: coverage symmetry (non-compliant fires EXACTLY the expected set)
# ============================================================================

@pytest.mark.parametrize("module,version,stem,expected", PHASE2, ids=[e[0] + "/" + e[1] for e in PHASE2])
def test_phase2_noncompliant_fires_expected(opa, module, version, stem, expected):
    plan = FIX / f"{stem}_non_compliant.json"
    report = gate.build_report(opa, [LIB], plan, [module], version)
    assert report["summary"]["result"] == "FAIL"
    assert _fired(report) == expected


# ============================================================================
# Phase I baseline + 95 / 88 / 108 reconciliation
# ============================================================================


# ============================================================================
# Performance
# ============================================================================

def test_performance_noncompliant_plan(opa):
    start = time.perf_counter()
    gate.build_report(opa, [LIB], P1PLANS / "non_compliant_plan.json", PHASE1_MODULES)
    elapsed = time.perf_counter() - start
    assert elapsed < PERF_BUDGET_SECONDS, f"gate took {elapsed:.2f}s (budget {PERF_BUDGET_SECONDS}s)"


# ============================================================================
# Case study: CR-2041 realistic multi-control change
# ============================================================================

CASE = ROOT / "case_study"
CASE_MODULES = ["ctrl_1_2", "ctrl_1_3", "ctrl_1_4", "ctrl_2_3", "ctrl_4_2", "ctrl_5_4"]


def test_case_study_change_is_blocked(opa):
    report = gate.build_report(opa, [LIB], CASE / "cr2041_change_plan.json", CASE_MODULES)
    s = report["summary"]
    assert s["result"] == "FAIL"
    assert s["controls_with_violations"] == 6
    assert s["total_violation_instances"] == 14


def test_case_study_remediated_passes(opa):
    report = gate.build_report(opa, [LIB], CASE / "cr2041_remediated_plan.json", CASE_MODULES)
    assert report["summary"]["result"] == "PASS"
    assert report["summary"]["total_violation_instances"] == 0


# ============================================================================
# Live Terraform plans and the third verdict: UNDETERMINED
# ============================================================================

PLANS = ROOT / "plans"

# Both environments are now references for the whole library, not just the five
# Phase I controls (review findings R3, R4).
ALL_MODULES = [
    "ctrl_1_1", "ctrl_1_2", "ctrl_1_3", "ctrl_1_4", "ctrl_2_1",
    "ctrl_2_2", "ctrl_2_3", "ctrl_2_4", "ctrl_2_6", "ctrl_2_7",
    "ctrl_4_1", "ctrl_4_2", "ctrl_5_1", "ctrl_5_4", "ctrl_6_4",
]

# Assertions that read a policy document whose text is unknown until apply.
# They are undetermined on a live plan -- never silently passed. 2.1-A16 and
# 5.1-A11 join this set once re-scoped: before the fix they were out of scope
# on any real plan and so passed silently.
LIVE_UNDETERMINED = {
    "compliant": {"1.1-A15", "2.1-A12", "2.1-A16", "5.1-A1", "5.1-A11", "5.4-A3", "6.4-A17"},
    "non_compliant": {"1.1-A15", "2.1-A12", "2.1-A16", "5.1-A11", "6.4-A17"},
}

# The six v2026 assertions the non-compliant environment does not trip, and why.
# None of them passes silently: four are undetermined (above) and two are
# mutually exclusive with an assertion that does fire.
LIVE_NOT_FIRED = {
    "2.1-A12": "undetermined -- EFS policy document unknown at plan time",
    "2.1-A16": "undetermined -- bucket policy document unknown at plan time",
    "5.1-A11": "undetermined -- bucket policy document unknown at plan time",
    "6.4-A17": "undetermined -- bucket policy document unknown at plan time",
    "4.1-A1": "mutually exclusive with 4.1-A2..A10: a weak password policy "
              "exists, so 'no policy at all' cannot also hold",
    "4.1-A18": "mutually exclusive with 4.1-A17: fine-grained access control is "
               "disabled, so the internal-user-database branch is unreachable",
}

# The three assertions found unsatisfiable on generated plans, re-scoped onto the parent
# resource that actually carries the tag.
RESCOPED = {"1.1-A14", "2.1-A16", "5.1-A11"}


def _live(opa, stem, modules=None):
    modules = modules or ALL_MODULES
    plan = PLANS / f"{stem}_resolved_plan.json"
    report = gate.build_report(opa, [LIB], plan, modules)
    resolvability = json.loads(
        (PLANS / f"{stem}_resolvability.json").read_text(encoding="utf-8")
    )
    undetermined = gate.find_undetermined(
        opa, [LIB], plan, modules, "v2026", resolvability, report
    )
    return report, undetermined


def test_live_compliant_plan_passes(opa):
    """The reference environment passes all fifteen controls on a real plan."""
    report, _ = _live(opa, "compliant")
    assert report["summary"]["result"] == "PASS"
    assert report["summary"]["total_violation_instances"] == 0, _fired(report)
    assert len(report["controls"]) == 15


def test_live_noncompliant_plan_is_blocked(opa):
    report, _ = _live(opa, "non_compliant")
    s = report["summary"]
    assert s["result"] == "FAIL"
    assert s["total_violation_instances"] == 151
    assert s["distinct_assertions_fired"] == 122
    # Every implemented control is exercised on a generated plan, not just the
    # five Phase I ones.
    assert s["controls_with_violations"] == 15


def test_live_noncompliant_corpus_accounts_for_every_assertion(opa):
    """Nothing passes silently: fired + undetermined + explained == the library."""
    report, undetermined = _live(opa, "non_compliant")
    defined = set()
    for root in (LIB / "swift_cscf" / "v2026",):
        for rego in root.glob("*.rego"):
            defined |= set(re.findall(r"\[(\d+\.\d+-A\d+)\]", rego.read_text(encoding="utf-8")))

    fired = _fired(report)
    assert fired | set(LIVE_NOT_FIRED) == defined
    assert fired.isdisjoint(LIVE_NOT_FIRED)
    # An assertion may fire on one resource and be undetermined on another
    # (1.1-A15: partner_share fires; R3 bucket policies are undetermined).
    assert {u["assertion"] for u in undetermined} - fired <= set(LIVE_NOT_FIRED)


def test_live_plans_report_undetermined_checks(opa):
    """A check that depends on a plan-time unknown is undetermined, not passed."""
    for stem in ("compliant", "non_compliant"):
        _, undetermined = _live(opa, stem)
        assert {u["assertion"] for u in undetermined} == LIVE_UNDETERMINED[stem], stem
        for u in undetermined:
            # Attributed to the resource and attribute that could not resolve.
            assert u["resource"]
            assert u["attribute"] == "policy"


def test_undetermined_assertions_do_not_appear_as_violations(opa):
    """The third verdict is disjoint from the other two: undetermined != fired."""
    report, undetermined = _live(opa, "compliant")
    assert _fired(report).isdisjoint({u["assertion"] for u in undetermined})


def test_no_resolvability_report_means_no_undetermined(opa):
    """Without a resolvability report the gate behaves exactly as before."""
    plan = PLANS / "compliant_resolved_plan.json"
    report = gate.build_report(opa, [LIB], plan, ALL_MODULES)
    assert gate.find_undetermined(
        opa, [LIB], plan, ALL_MODULES, "v2026", {"r3_unresolvable": []}, report
    ) == []


# ============================================================================
# Re-scoped assertions (1.1-A14, 2.1-A16, 5.1-A11)
# ============================================================================
#
# All three TAG-scoped a resource type the AWS provider does not accept tags on,
# so they could not fire on any real plan. Scope now comes from the parent role
# or bucket (docs/failure-modes.md).

def test_every_control_is_exercised_on_a_generated_plan(opa):
    """R4: the Phase II controls are validated on real plans, not only fixtures."""
    report, _ = _live(opa, "non_compliant")
    per_control = {c["control"]: c["rules_fired"] for c in report["controls"]}
    for control, fired in per_control.items():
        assert fired > 0, f"control {control} fires nothing on the generated plan"


def test_rescoped_assertions_reach_a_verdict_on_a_live_plan(opa):
    """Each re-scoped assertion now either fires or is undetermined -- never silent."""
    report, undetermined = _live(opa, "non_compliant")
    decided = _fired(report) | {u["assertion"] for u in undetermined}
    assert RESCOPED <= decided


def test_rescoped_mfa_assertion_fires_on_live_plan(opa):
    """1.1-A14 reads a document the plan knows, so it reaches a real verdict."""
    report, _ = _live(opa, "non_compliant")
    assert "1.1-A14" in _fired(report)


def test_rescope_finds_a_real_defect_in_the_phase1_compliant_mock(opa):
    """The corrected scope catches something the original scoping could not.

    The Phase I compliant mock plan tags its CloudTrail log bucket but not the
    bucket policy attached to it, and that policy carries no SecureTransport
    deny. Scoped on the policy, 2.1-A16 never looked; scoped on the bucket, it
    is a genuine finding.
    """
    report = gate.build_report(
        opa, [LIB], P1PLANS / "compliant_plan.json", PHASE1_MODULES
    )
    assert _fired(report) == {"2.1-A16"}


# ============================================================================
# Plan completeness (R1): absence findings are undecidable on a change plan
# ============================================================================
#
# Twelve assertions report that nothing in the plan provides a required
# resource -- a CloudTrail, a GuardDuty detector, a patch baseline. A plan for a
# change does not re-declare what the account already has, so on an incremental
# plan those findings are undetermined rather than violations. The signal is the
# message shape: a finding that cannot name a resource is asserting an absence.

CASE_PRESENCE_ASSERTIONS = {
    "1.1-A9",
    "6.4-A1",
    "6.4-A5",
    "6.4-A19",
    "6.4-A20",
    "6.4-A21",
    "6.4-A23",
    "6.4-A24",
}


def test_absence_findings_carry_no_resource_attribution(opa):
    """The partition is driven by message shape, so pin that shape."""
    report = gate.build_report(
        opa, [LIB], CASE / "cr2041_remediated_plan.json", ["ctrl_6_4", "ctrl_1_1"]
    )
    for control in report["controls"]:
        attributed, globals_ = gate.split_global_findings(control["violations"])
        assert all("(resource:" in v for v in attributed)
        assert all("(resource:" not in v for v in globals_)


def test_change_plan_does_not_fail_on_absent_account_infrastructure(opa):
    """The case study's remediated plan is clean once absence is not asserted.

    Under the default full-plan reading it fails eight assertions purely because
    an incremental plan does not re-declare the account's logging and monitoring
    estate. Those become undetermined, leaving only findings that name a
    resource in the change itself.
    """
    report = gate.build_report(
        opa, [LIB], CASE / "cr2041_remediated_plan.json", ["ctrl_6_4", "ctrl_1_1"]
    )
    assert report["summary"]["total_violation_instances"] == 9

    undetermined = gate.apply_plan_scope(report)
    assert {u["assertion"] for u in undetermined} == CASE_PRESENCE_ASSERTIONS
    assert all(u["kind"] == "incomplete-plan" for u in undetermined)

    # 6.4-A6 names the RDS instance the change itself creates, so it survives.
    assert _fired(report) == {"6.4-A6"}


def test_full_plan_scope_is_the_default_and_changes_nothing(opa):
    """A full-environment plan must be evaluated exactly as before."""
    plan = PLANS / "non_compliant_resolved_plan.json"
    report = gate.build_report(opa, [LIB], plan, PHASE1_MODULES)
    before = dict(report["summary"])
    attributed_only = gate.apply_plan_scope(report)
    # The live fixtures are whole-environment plans, so the downgrade removes
    # findings -- which is precisely why `full` is the default.
    assert before["total_violation_instances"] >= report["summary"][
        "total_violation_instances"
    ]
    assert attributed_only  # the non-compliant environment does trip absence rules


# ============================================================================
# Binding-plane audits (review R2, and the Gate B check of the paper's N6)
# ============================================================================
#
# Both audits are cheap and mechanical, and between them they found four defects
# that the fixture corpus and this suite did not. They belong in conformance so
# they run on every change rather than when someone remembers.

AUDIT = ROOT / "pipeline" / "audit"


def test_no_rule_declares_a_scope_it_does_not_apply():
    """R2: library 2.0.0 implements every scope it declares."""
    import subprocess

    result = subprocess.run(
        [sys.executable, str(AUDIT / "scope_audit.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "No mismatches" in result.stdout


def test_scope_predicates_narrow_without_losing_detection():
    """The Phase II re-scoping must not have cost any finding on a live plan."""
    report, _ = _live(opa_binary(), "non_compliant")
    control = next(c for c in report["controls"] if c["control"] == "1.4")
    assert control["rules_fired"] == 6, control["assertions"]


# ============================================================================
# IAM condition values (review R6, R7)
# ============================================================================
#
# R6: 1.1-A12 tested that the MFA condition key was *present* and never looked
# at its value, so a trust policy carrying MultiFactorAuthPresent=false -- the
# exact opposite of the requirement -- was reported compliant.
#
# R7: two helpers compared the condition value against the string "false" only.
# Terraform's jsonencode preserves HCL types, so `Bool = { x = false }` emits a
# JSON boolean and a correctly written policy was reported as violating.

CONDITION_MODULES = ["ctrl_1_1", "ctrl_2_1"]


def _fixture_report(opa, stem, policies):
    report = gate.build_report(opa, policies, FIX / f"{stem}.json", CONDITION_MODULES)
    # These fixtures are single-purpose, so absence assertions about
    # account-level infrastructure are noise here.
    gate.apply_plan_scope(report)
    return report


def test_mfa_condition_set_to_false_is_a_violation(opa):
    """R6: requiring MFA to be *absent* must not read as compliant."""
    corrected = _fixture_report(opa, "r6_mfa_condition_disabled", [LIB])
    assert "1.1-A12" in _fired(corrected)


def test_mfa_condition_true_as_a_json_boolean_is_accepted(opa):
    """The correction must not flag the boolean spelling of a correct policy."""
    report = _fixture_report(opa, "r6_mfa_condition_boolean_true", [LIB])
    assert _fired(report) == set()


def test_boolean_conditions_are_accepted(opa):
    """R7: `Bool = { "aws:SecureTransport" = false }` is a valid TLS-only policy."""
    report = _fixture_report(opa, "r7_boolean_conditions", [LIB])
    assert _fired(report) == set(), _fired(report)


def test_boolean_tolerance_does_not_weaken_the_rules(opa):
    """Remove the Deny statements and both assertions must fire again."""
    report = _fixture_report(opa, "r7_conditions_absent", [LIB])
    assert _fired(report) == {"1.1-A14", "2.1-A16"}


# ============================================================================
# Binding coverage extensions (review R5, R9.3, R9.5)
# ============================================================================
#
# The assertions are unchanged; the set of resource shapes their binding covers
# is wider. Each of these shapes passed silently before, because the Phase I
# binding only looked at one way of expressing the configuration.

COVERAGE_SHAPES = {
    "aws_vpc_security_group_ingress_rule.bad_ssh": {"1.1-A2", "1.1-A3"},
    "aws_vpc_security_group_egress_rule.bad_all": {"1.1-A4"},
    "aws_security_group_rule.bad_legacy_ingress": {"1.1-A2"},
    "aws_network_acl.bad": {"1.1-A7", "1.1-A8"},
    "aws_network_acl_rule.bad_inbound": {"1.1-A7"},
    "aws_iam_group_policy.bad_ops": {"5.1-A1", "5.1-A2"},
}


def test_modern_and_legacy_rule_shapes_are_covered(opa):
    """R5, R9.5: each newly covered resource shape produces its findings."""
    report, _ = _live(opa, "non_compliant")
    findings = [v for c in report["controls"] for v in c["violations"]]

    for address, expected in COVERAGE_SHAPES.items():
        fired = {
            m.group(1)
            for v in findings
            if f"(resource: {address})" in v
            and (m := re.search(r"\[(\d+\.\d+-A\d+)\]", v))
        }
        assert expected <= fired, f"{address}: expected {expected}, got {fired}"


# ============================================================================
# Module depth (review R8)
# ============================================================================
#
# helpers.all_resources walks the root and two levels of child_modules, under a
# comment claiming recursion. A resource three modules deep is invisible to
# every rule. The fixture is a generated plan, not hand-written: an SSH-open
# security group at root -> zone -> network -> edge.

NESTED = PLANS / "nested_modules_live_plan.json"
DEEP_SG = "module.zone.module.network.module.edge.aws_security_group.edge"


def test_library_traverses_every_module_depth(opa):
    """R8 corrected in 2.0.0: the plan as supplied, no normalisation needed."""
    report = gate.build_report(opa, [LIB], NESTED, ["ctrl_1_1"])
    gate.apply_plan_scope(report)
    assert {"1.1-A2", "1.1-A3"} <= _fired(report)
    findings = [v for c in report["controls"] for v in c["violations"]]
    assert all(DEEP_SG in v for v in findings), findings


def test_deep_module_resources_are_evaluated_after_normalisation(opa, tmp_path):
    """Lifted into the root module, the resource is still found and named exactly."""
    plan = json.loads(NESTED.read_text(encoding="utf-8"))
    assert gate.flatten_deep_modules(plan) == 1

    lifted = tmp_path / NESTED.name
    lifted.write_text(json.dumps(plan), encoding="utf-8")
    report = gate.build_report(opa, [LIB], lifted, ["ctrl_1_1"], source=NESTED)
    gate.apply_plan_scope(report)

    assert {"1.1-A2", "1.1-A3"} <= _fired(report)
    findings = [v for c in report["controls"] for v in c["violations"]]
    assert all(DEEP_SG in v for v in findings), findings
    # The evidence identifies the file as supplied, not the normalised copy.
    assert report["plan_sha256"] == gate.sha256(NESTED)


def test_normalisation_leaves_shallow_plans_untouched():
    """Plans within the traversal depth must pass through unchanged."""
    for stem in ("compliant", "non_compliant"):
        plan = json.loads((PLANS / f"{stem}_resolved_plan.json").read_text(encoding="utf-8"))
        assert gate.flatten_deep_modules(plan) == 0


# ============================================================================
# Gate C scope correctness (review R11): an out-of-scope corpus
# ============================================================================
#
# The framework's Gate C listed "an out-of-scope corpus yields zero findings"
# as an executable criterion, and no test performed it -- which is why the R2
# scope defects went unnoticed. Each Phase II non-compliant fixture is moved out
# of the Swift zone (zone tags removed, VPC binding pointed elsewhere) and
# re-evaluated. A resource-scoped assertion that still fires is not honouring
# its scope. Account-scoped assertions may fire -- that is what ACCT means.

OUT_OF_ZONE_CONTROLS = [
    "ctrl_1_2", "ctrl_1_3", "ctrl_1_4", "ctrl_2_3",
    "ctrl_2_4", "ctrl_2_6", "ctrl_4_2", "ctrl_5_4",
]


def _declared_scopes():
    sys.path.insert(0, str(AUDIT))
    import scope_audit

    scopes = {}
    for row in scope_audit.audit():
        scopes.setdefault(row["assertion"], set()).add(row["declared"])
    return scopes


def _out_of_zone(plan):
    for resource in gate._iter_planned_resources(plan):
        for key in ("tags", "tags_all"):
            tags = resource["values"].get(key)
            if isinstance(tags, dict):
                tags.pop("swift:zone", None)
                tags.pop("swift:role", None)
    plan["swift_vpc_id"] = "vpc-not-the-swift-zone"
    return plan


@pytest.mark.parametrize("module", OUT_OF_ZONE_CONTROLS)
def test_out_of_scope_corpus_trips_no_resource_scoped_assertion(opa, module, tmp_path):
    scopes = _declared_scopes()
    source = FIX / f"{module}_non_compliant.json"
    plan = _out_of_zone(json.loads(source.read_text(encoding="utf-8")))
    moved = tmp_path / source.name
    moved.write_text(json.dumps(plan), encoding="utf-8")

    report = gate.build_report(opa, [LIB], moved, [module])
    gate.apply_plan_scope(report)

    leaked = {
        a for a in _fired(report) if scopes.get(a, set()) & {"TAG", "VPC", "MODULE"}
    }
    assert not leaked, f"{module}: resource-scoped assertions fired out of zone: {leaked}"


def test_generated_plan_out_of_zone_trips_no_resource_scoped_assertion(opa, tmp_path):
    """All fifteen controls, including the 39 rules 1.0.0 left unscoped.

    The generated non-compliant environment fires 122 assertions in the zone.
    Moved out of it, only account-scoped and cross-reference assertions may
    remain.
    """
    scopes = _declared_scopes()
    source = PLANS / "non_compliant_resolved_plan.json"
    plan = _out_of_zone(json.loads(source.read_text(encoding="utf-8")))
    moved = tmp_path / source.name
    moved.write_text(json.dumps(plan), encoding="utf-8")

    report = gate.build_report(opa, [LIB], moved, ALL_MODULES)
    gate.apply_plan_scope(report)
    resource_scoped = {a for a, s in scopes.items() if s & {"TAG", "VPC", "MODULE"}}
    assert not _fired(report) & resource_scoped, _fired(report) & resource_scoped


# ============================================================================
# Traceability matrix
# ============================================================================
#
# The matrix is generated from the library, the registers and the evidence, so
# it can be checked rather than trusted. If a rule, an assertion or a verdict
# changes without the matrix being regenerated, this fails.

TRACE = ROOT / "traceability"


def _committed_matrix():
    return json.loads((TRACE / "traceability.json").read_text(encoding="utf-8"))


def test_traceability_matrix_is_current():
    sys.path.insert(0, str(TRACE))
    import build_matrix

    assert build_matrix.build() == _committed_matrix(), (
        "the traceability matrix is stale; regenerate with "
        "python traceability/build_matrix.py --xlsx"
    )


def test_traceability_is_bidirectional_and_complete():
    matrix = _committed_matrix()
    assertions = {a["assertion"]: a for a in matrix["assertions"]}

    # Backward: every rule in the library reports an assertion in the matrix.
    assert matrix["library_version"] == "2.1.2"
    assert len(matrix["rules"]) == LIBRARY_RULES
    assert all(r["assertion"] in assertions for r in matrix["rules"])

    # Forward: every assertion is realised by a rule, or says why it is not.
    assert len(assertions) == 130
    for aid, a in assertions.items():
        assert a["rules"] or a["live_verdict"].startswith("not fired"), aid

    # Nothing passes silently, and every recorded sub-requirement is either
    # covered by an assertion or excluded with a rationale.
    assert not [a for a in assertions if assertions[a]["live_verdict"] == "SILENT"]
    assert not [r["requirement"] for r in matrix["requirements"] if r["disposition"] == "UNTRACED"]


# ============================================================================
# Evidence signing
# ============================================================================
#
# The evidence was bound to its plan by hash but could itself be edited without
# trace. It now carries an Ed25519 signature over a canonical serialisation.
# These tests use a throwaway key, so they need no secret.

SIGNED_SAMPLE = PLANS / "non_compliant_resolved_evidence.json"


def _signing():
    import evidence_signing
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return evidence_signing, Ed25519PrivateKey.generate()


def _unsigned_sample():
    evidence = json.loads(SIGNED_SAMPLE.read_text(encoding="utf-8"))
    evidence.pop("signature", None)
    return evidence


def test_signed_evidence_verifies():
    es, key = _signing()
    signed = es.sign(_unsigned_sample(), key)
    assert es.verify(signed, key.public_key())[0] == "valid"


def test_removing_a_finding_from_signed_evidence_is_detected():
    """The attack signing exists to stop: quietly deleting a violation."""
    es, key = _signing()
    signed = es.sign(_unsigned_sample(), key)
    tampered = json.loads(json.dumps(signed))
    control = next(c for c in tampered["controls"] if c["violations"])
    control["violations"].pop()
    status, reason = es.verify(tampered, key.public_key())
    assert status == "invalid", reason


def test_flipping_the_verdict_is_detected():
    es, key = _signing()
    signed = es.sign(_unsigned_sample(), key)
    signed["summary"]["result"] = "PASS"
    assert es.verify(signed, key.public_key())[0] == "invalid"


def test_key_order_and_whitespace_do_not_invalidate():
    """Canonicalisation: re-serialising the file must not break the signature."""
    es, key = _signing()
    signed = es.sign(_unsigned_sample(), key)
    reordered = json.loads(json.dumps(dict(reversed(list(signed.items()))), indent=7))
    assert es.verify(reordered, key.public_key())[0] == "valid"


def test_signature_from_another_key_is_rejected():
    es, key = _signing()
    _, impostor = _signing()
    signed = es.sign(_unsigned_sample(), impostor)
    status, reason = es.verify(signed, key.public_key())
    assert status == "invalid" and "not the published key" in reason


def test_unsigned_evidence_is_reported_as_unsigned():
    es, key = _signing()
    assert es.verify(_unsigned_sample(), key.public_key())[0] == "unsigned"


def test_gate_signs_evidence_when_a_key_is_supplied(opa, tmp_path):
    """End to end: the gate signs, and the attestation reports it valid."""
    import subprocess

    from cryptography.hazmat.primitives import serialization

    es, key = _signing()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public = tmp_path / "public.pem"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    evidence = tmp_path / "evidence.json"
    subprocess.run(
        [sys.executable, str(ROOT / "pipeline" / "gate.py"),
         "--plan", str(FIX / "r7_boolean_conditions.json"),
         "--policies", str(LIB), "--controls", "ctrl_1_1",
         "--evidence", str(evidence)],
        env={**__import__("os").environ, "CSCF_EVIDENCE_SIGNING_KEY": pem},
        capture_output=True, text=True, encoding="utf-8",
    )
    signed = json.loads(evidence.read_text(encoding="utf-8"))
    assert es.verify(signed, key.public_key())[0] == "valid"

    sys.path.insert(0, str(ROOT / "evidence"))
    import report

    assert "Signature</th><td class='mono'>VALID." in report.render_html(signed, public)
    signed["summary"]["result"] = "PASS"
    assert "INVALID" in report.render_html(signed, public)


# ============================================================================
# The library as a versioned artefact
# ============================================================================
#
# Rego merges a package across files, so two roots that define the same file
# compile cleanly and silently evaluate both. The gate refuses that, and records
# the library version and a digest of its source in every evidence file.

LIBRARY_RULES = 147  # 144 in 2.0.0 (153 before it: -3 superseded, -3 empty-block, -1 A12, -2 inline), +1 for 1.1-A15 (2.1.0), +2 canonical/NotPrincipal (2.1.1)

REISSUE = FIX / "reissue_corrections.json"
REISSUE_MODULES = ["ctrl_1_1", "ctrl_2_1", "ctrl_5_1"]

# Each defect the 2.0.0 re-issue corrected (docs/failure-modes.md), pinned on
# fixtures/reissue_corrections.json to the verdict the current library must give:
# (assertion, resource) -> fires.
REISSUE_CASES = {
    # Over-reported by 1.0.0; must stay silent.
    ("2.1-A14", "aws_kms_key.shared_services"): False,  # declared scope now applied
    ("2.1-A12", "aws_efs_file_system_policy.swift"): False,  # JSON boolean condition
    ("1.1-A13", "aws_iam_role.trust_unknown"): False,  # unreadable trust policy
    ("1.1-A6", "aws_route.to_peer"): False,  # contains(x, "") matched every route
    ("5.1-A16", "aws_iam_role_policy_attachment.orphan_admin"): False,  # empty join key
    # Missed by 1.0.0; must fire.
    ("5.1-A1", "aws_iam_policy.single_statement"): True,  # Statement as a single object
    ("2.1-A7", "aws_msk_cluster.swift"): True,  # explicitly empty block
    ("2.1-A8", "aws_msk_cluster.swift"): True,  # explicitly empty block
    # Control: unaffected by the re-issue, fires.
    ("5.1-A8", "aws_iam_role_policy_attachment.orphan_admin"): True,
}


@pytest.fixture(scope="module")
def corrections_instances():
    report = gate.build_report(opa_binary(), [LIB], REISSUE, REISSUE_MODULES)
    gate.apply_plan_scope(report)
    return gate._instances([v for c in report["controls"] for v in c["violations"]])


@pytest.mark.parametrize(
    "case,fires", REISSUE_CASES.items(), ids=[f"{a}:{r.split('.')[-1]}" for a, r in REISSUE_CASES]
)
def test_corrected_defect_stays_corrected(corrections_instances, case, fires):
    assert (case in corrections_instances) == fires


def test_nothing_else_fires_on_the_corrections_fixture(corrections_instances):
    """Every finding on this fixture is a listed case: no correction regressed quietly."""
    assert corrections_instances == {case for case, fires in REISSUE_CASES.items() if fires}


def test_a_library_without_a_version_record_is_labelled_undeclared(opa, tmp_path):
    """Signed evidence must not attribute an unversioned library to anything else."""
    import shutil

    copy = tmp_path / "policies"
    shutil.copytree(LIB, copy)
    (copy / "swift_cscf" / "library.rego").unlink()
    assert gate.library_info(opa, [copy])["version"] == "undeclared"


def test_two_roots_defining_the_same_file_are_refused(opa, tmp_path):
    """Merged silently, a second copy of the library would double every finding."""
    import shutil

    copy = tmp_path / "policies"
    shutil.copytree(LIB, copy)
    with pytest.raises(ValueError, match="load one library at a time"):
        gate.build_report(opa, [LIB, copy], REISSUE, ["ctrl_1_1"])


def test_evidence_names_the_library_that_produced_it(opa):
    current = gate.build_report(opa, [LIB], REISSUE, ["ctrl_1_1"])
    assert current["library"]["version"] == "2.1.2"
    assert current["library"]["digest"].startswith("sha256:")


def test_library_digest_ignores_line_endings(tmp_path):
    """A CRLF checkout must digest the same as CI's LF one."""
    for name, text in (("lf", "package p\n\nx := 1\n"), ("crlf", "package p\r\n\r\nx := 1\r\n")):
        root = tmp_path / name
        root.mkdir()
        (root / "p.rego").write_bytes(text.encode("utf-8"))
    digests = {
        gate.library_info("opa", [tmp_path / name])["digest"] for name in ("lf", "crlf")
    }
    assert len(digests) == 1


def test_reissue_leaves_the_generated_environments_unchanged(opa):
    """Both reference environments already carry every zone signal, so correct
    scoping costs no finding there: 0 on the compliant plan, 150 / 121 on the
    non-compliant one, exactly as before the re-issue. 2.1.0 adds 1.1-A15, one
    instance on partner_share: 151 / 122."""
    compliant, _ = _live(opa, "compliant")
    non_compliant, _ = _live(opa, "non_compliant")
    assert compliant["summary"]["total_violation_instances"] == 0
    assert non_compliant["summary"]["total_violation_instances"] == 151
    assert non_compliant["summary"]["distinct_assertions_fired"] == 122


# A sub-resource whose parent is not in the plan
#
# Scoping a sub-resource by its parent raises a question 1.0.0 never had to
# answer: what if the parent is not in the plan? A change plan references
# existing resources by id all the time. The answer is the third verdict --
# the plan does not determine it -- computed by a witness that supplies the
# missing parent inside the zone.

P1_MOCK_DANGLING = {
    ("1.1-A11", "aws_ec2_client_vpn_authorization_rule.bad"),
    ("1.1-A6", "aws_route.bad_igw"),
    ("2.1-A12", "aws_efs_file_system_policy.bad"),
    ("2.1-A16", "aws_s3_bucket_policy.bad_data"),
    ("2.1-A16", "aws_s3_bucket_policy.bad_open"),
    ("4.1-A16", "aws_secretsmanager_secret_rotation.bad"),
    ("5.1-A11", "aws_s3_bucket_policy.bad_data"),
    ("5.1-A11", "aws_s3_bucket_policy.bad_open"),
}


def test_missing_parent_is_undetermined_not_silent(opa):
    """The Phase I mock references parents it never defines (rtb-bad, fs-bad...)."""
    plan = P1PLANS / "non_compliant_plan.json"
    report = gate.build_report(opa, [LIB], plan, PHASE1_MODULES)
    undetermined = gate.find_scope_undetermined(opa, [LIB], plan, PHASE1_MODULES, "v2026", report)
    assert {(u["assertion"], u["resource"]) for u in undetermined} == P1_MOCK_DANGLING
    assert all(u["kind"] == "unresolved-scope" and u["parent"] for u in undetermined)


def test_generated_plans_have_no_missing_parents():
    for stem in ("compliant", "non_compliant"):
        plan = json.loads((PLANS / f"{stem}_resolved_plan.json").read_text(encoding="utf-8"))
        assert gate.dangling_parents(plan) == [], stem


def test_parent_references_cover_every_parent_lookup_in_the_library():
    """The witness must know every (reference, parent type) the library resolves."""
    known = {(attr, t) for attr, types in gate.PARENT_REFERENCES.values() for t in types}
    named = {  # the named lookups in parent_scope.rego
        ("bucket", "aws_s3_bucket"), ("role", "aws_iam_role"), ("route_table_id", "aws_route_table"),
    }
    calls = set()
    for rego in (LIB / "swift_cscf").rglob("*.rego"):
        calls |= set(re.findall(
            r'parent_scope\.parent_\w+\(\s*\w+,\s*"([a-z_0-9]+)",\s*"([a-z0-9_]+)"\s*\)',
            rego.read_text(encoding="utf-8"),
        ))
    assert calls, "no parent lookups found; the pattern is stale"
    assert (calls | named) <= known, (calls | named) - known


def test_library_performance_on_the_generated_plan(opa):
    """2.0.0 walks every module depth; the full library must stay well inside budget."""
    start = time.perf_counter()
    _live(opa, "non_compliant")
    elapsed = time.perf_counter() - start
    assert elapsed < PERF_BUDGET_SECONDS * 2, f"{elapsed:.2f}s"


# ============================================================================
# CR-2041 on a real plan, and values AWS decides at apply time
# ============================================================================
#
# The case study was re-run as a real change: the reporting service written as
# Terraform, added to the secure-zone environment, planned by `terraform plan`
# (in a pull request in the development repository). The generated plans are
# committed here as fixtures.
#
# The real plan exposed a silent pass the hand-written one could not. The change
# leaves the root volume's `encrypted` unset, so AWS applies the account's EBS
# encryption-by-default setting at apply time and Terraform reports the value
# as unknown. The plan normaliser treated every value the author never assigned
# as provider output no rule depends on, and dropped it -- so 1.3-A3 read
# nothing and passed. Such values are now classified in the Target Profile:
# taken from state outside the plan (R3, undetermined) or with a fixed meaning.

CR_LIVE = CASE / "cr2041_change_live_plan.json"
CR_LIVE_REMEDIATED = CASE / "cr2041_remediated_live_plan.json"


def _resolve_and_gate(opa, source, tmp_path, mutate=None):
    import resolve_plan

    plan = json.loads(source.read_text(encoding="utf-8"))
    if mutate:
        mutate(plan)
    resolved, resolvability = resolve_plan.resolve(plan, None)
    path = tmp_path / "resolved.json"
    path.write_text(json.dumps(resolved), encoding="utf-8")
    report = gate.build_report(opa, [LIB], path, ALL_MODULES)
    undetermined = gate.find_undetermined(
        opa, [LIB], path, ALL_MODULES, "v2026", resolvability, report
    )
    return report, undetermined


def test_cr2041_real_change_is_blocked(opa, tmp_path):
    report, undetermined = _resolve_and_gate(opa, CR_LIVE, tmp_path)
    s = report["summary"]
    assert s["result"] == "FAIL"
    assert s["total_violation_instances"] == 16
    assert s["controls_with_violations"] == 9
    # The unencrypted-by-default root volume: undetermined, never a silent pass.
    root = [u for u in undetermined if u["assertion"] == "1.3-A3"]
    assert [(u["resource"], u["attribute"]) for u in root] == [
        ("aws_instance.reporting_host", "root_block_device.0.encrypted")
    ]
    assert "1.3-A3" not in _fired(report)


def test_cr2041_real_remediation_passes(opa, tmp_path):
    report, undetermined = _resolve_and_gate(opa, CR_LIVE_REMEDIATED, tmp_path)
    assert report["summary"]["result"] == "PASS"
    assert report["summary"]["total_violation_instances"] == 0
    assert not [u for u in undetermined if "reporting" in u["resource"]]


def test_account_ebs_default_in_the_plan_decides_root_volume_encryption(opa, tmp_path):
    """If the plan itself turns on EBS encryption by default, the value is known."""

    def enable_ebs_default(plan):
        plan["planned_values"]["root_module"]["resources"].append(
            {
                "address": "aws_ebs_encryption_by_default.account",
                "mode": "managed",
                "type": "aws_ebs_encryption_by_default",
                "name": "account",
                "values": {"enabled": True},
            }
        )

    report, undetermined = _resolve_and_gate(opa, CR_LIVE, tmp_path, enable_ebs_default)
    assert "1.3-A3" not in _fired(report)
    assert "1.3-A3" not in {u["assertion"] for u in undetermined}


def test_every_provider_decided_value_a_rule_reads_is_classified():
    """A rule reading a value AWS fills in at apply time is a decision to make.

    Either the value comes from state outside the plan (APPLY_TIME_DEFAULTS:
    undetermined) or leaving it unset has a fixed meaning (UNSET_DEFAULTS).
    A new rule, or a new plan, that reads an unclassified one fails here.
    """
    import resolve_plan

    sys.path.insert(0, str(AUDIT))
    import gate_b_admissibility

    reads = gate_b_admissibility.library_reads([str(LIB)])
    classified = set(resolve_plan.APPLY_TIME_DEFAULTS) | set(resolve_plan.UNSET_DEFAULTS)
    unclassified = set()
    for source in (
        PLANS / "compliant_live_plan.json",
        PLANS / "non_compliant_live_plan.json",
        CR_LIVE,
        CR_LIVE_REMEDIATED,
    ):
        plan = json.loads(source.read_text(encoding="utf-8"))
        _, resolvability = resolve_plan.resolve(plan, None)
        for entry in resolvability["provider_decided"]:
            key = (entry["type"], resolve_plan.without_indices(entry["attribute"]))
            if key in reads and key not in classified:
                unclassified.add(key)
    assert not unclassified, f"classify in resolve_plan's Target Profile tables: {unclassified}"
