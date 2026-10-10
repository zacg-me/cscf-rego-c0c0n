"""1.1-A15: a Swift-zone bucket may grant access only inside the trust boundary.

The boundary is an environment binding, like the Swift account and VPC: the
plan does not carry it, resolve_plan.py supplies it, and a rule that needs it
reports undetermined -- never a pass -- when it is missing.
"""
import json
from pathlib import Path

import pytest

import gate
import resolve_plan

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "policies"
FIX = ROOT / "fixtures"

ACCOUNT = "111122223333"   # the Swift account
DR = "210987654321"        # a second account inside the declared boundary
PARTNER = "444455556666"   # outside the boundary


def _variables(**values):
    return {"variables": {k: {"value": v} for k, v in values.items()}}


# ============================================================================
# The binding (resolve_plan.trust_boundary)
# ============================================================================

def test_declared_boundary_is_sorted_unique_and_includes_the_swift_account():
    plan = _variables(swift_trust_boundary_accounts=[DR, DR])
    assert resolve_plan.trust_boundary(plan, ACCOUNT) == sorted({ACCOUNT, DR})


def test_undeclared_boundary_is_the_swift_account_alone():
    assert resolve_plan.trust_boundary(_variables(), ACCOUNT) == [ACCOUNT]


def test_no_account_and_no_declaration_leaves_the_boundary_unbound():
    assert resolve_plan.trust_boundary(_variables(), None) is None


def test_explicit_empty_boundary_still_contains_the_swift_account():
    """Review focus 5: [] means 'no further accounts', never 'trust nobody'."""
    plan = _variables(swift_trust_boundary_accounts=[])
    assert resolve_plan.trust_boundary(plan, ACCOUNT) == [ACCOUNT]


def test_declared_boundary_without_a_known_account_is_used_as_declared():
    plan = _variables(swift_trust_boundary_accounts=[DR])
    assert resolve_plan.trust_boundary(plan, None) == [DR]


# ============================================================================
# The rule (ctrl_1_1, 1.1-A15)
# ============================================================================

def _plan(tmp_path, principal=None, *, boundary=(ACCOUNT,), tagged=True,
          effect="Allow", statement=None, policy=True):
    tags = {"swift:zone": "secure"} if tagged else {}
    stmt = statement or {
        "Sid": "Share", "Effect": effect, "Principal": principal,
        "Action": "s3:GetObject", "Resource": "arn:aws:s3:::swift-exchange/*",
    }
    policy_values = {"bucket": "swift-exchange"}
    if policy:
        policy_values["policy"] = json.dumps({"Version": "2012-10-17", "Statement": [stmt]})
    doc = {
        "format_version": "1.2",
        "swift_account_id": ACCOUNT,
        "planned_values": {"root_module": {"child_modules": [], "resources": [
            {"address": "aws_s3_bucket.exchange", "mode": "managed",
             "type": "aws_s3_bucket", "name": "exchange",
             "values": {"bucket": "swift-exchange", "tags": tags, "tags_all": tags}},
            {"address": "aws_s3_bucket_policy.exchange", "mode": "managed",
             "type": "aws_s3_bucket_policy", "name": "exchange", "values": policy_values},
        ]}},
    }
    if boundary is not None:
        doc["swift_trust_boundary_accounts"] = list(boundary)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _a15(opa, plan):
    return [v for v in gate.eval_control(opa, [LIB], plan, "ctrl_1_1") if "[1.1-A15]" in v]


def test_partner_account_root_arn_fires(opa, tmp_path):
    found = _a15(opa, _plan(tmp_path, {"AWS": f"arn:aws:iam::{PARTNER}:root"}))
    assert len(found) == 1
    assert PARTNER in found[0] and "(resource: aws_s3_bucket_policy.exchange)" in found[0]


def test_bare_account_id_fires(opa, tmp_path):
    assert len(_a15(opa, _plan(tmp_path, {"AWS": PARTNER}))) == 1


def test_numeric_account_id_fires(opa, tmp_path):
    """Review focus 1: a number must not slip past a string-only check."""
    assert len(_a15(opa, _plan(tmp_path, {"AWS": int(PARTNER)}))) == 1


def test_role_and_sts_arns_of_one_account_are_one_finding(opa, tmp_path):
    principal = {"AWS": [f"arn:aws:iam::{PARTNER}:role/reader",
                         f"arn:aws:sts::{PARTNER}:assumed-role/reader/s1"]}
    assert len(_a15(opa, _plan(tmp_path, principal))) == 1


@pytest.mark.parametrize("partition", ["aws-us-gov", "aws-cn"])
def test_other_partitions_yield_their_account(opa, tmp_path, partition):
    """Review focus 2."""
    principal = {"AWS": f"arn:{partition}:iam::{PARTNER}:root"}
    assert len(_a15(opa, _plan(tmp_path, principal))) == 1


def test_single_object_statement_and_string_principal_are_evaluated(opa, tmp_path):
    """Review focus 3: Statement as an object, not a list."""
    plan = _plan(tmp_path, {"AWS": f"arn:aws:iam::{PARTNER}:root"})
    doc = json.loads(plan.read_text(encoding="utf-8"))
    policy_resource = doc["planned_values"]["root_module"]["resources"][1]
    body = json.loads(policy_resource["values"]["policy"])
    body["Statement"] = body["Statement"][0]
    policy_resource["values"]["policy"] = json.dumps(body)
    plan.write_text(json.dumps(doc), encoding="utf-8")
    assert len(_a15(opa, plan)) == 1


def test_conditioned_grant_outside_the_boundary_still_fires(opa, tmp_path):
    """Review focus 4: a condition narrows a grant; it does not move the boundary."""
    stmt = {"Effect": "Allow", "Principal": {"AWS": PARTNER}, "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::swift-exchange/*",
            "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-0abc"}}}
    assert len(_a15(opa, _plan(tmp_path, statement=stmt))) == 1


def test_mixed_principals_flag_only_the_outside_account(opa, tmp_path):
    principal = {"AWS": [f"arn:aws:iam::{ACCOUNT}:role/app", f"arn:aws:iam::{PARTNER}:root"]}
    found = _a15(opa, _plan(tmp_path, principal))
    assert len(found) == 1 and PARTNER in found[0] and ACCOUNT not in found[0].split("(resource")[0]


def test_swift_account_principal_is_silent(opa, tmp_path):
    assert _a15(opa, _plan(tmp_path, {"AWS": f"arn:aws:iam::{ACCOUNT}:role/app"})) == []


def test_declared_boundary_admits_its_accounts(opa, tmp_path):
    plan = _plan(tmp_path, {"AWS": f"arn:aws:iam::{DR}:root"}, boundary=(ACCOUNT, DR))
    assert _a15(opa, plan) == []


def test_wildcard_is_left_to_5_1_a11(opa, tmp_path):
    assert _a15(opa, _plan(tmp_path, "*")) == []
    assert _a15(opa, _plan(tmp_path, {"AWS": "*"})) == []


def test_service_principal_names_no_account(opa, tmp_path):
    assert _a15(opa, _plan(tmp_path, {"Service": "logging.s3.amazonaws.com"})) == []


def test_deny_statement_is_not_a_grant(opa, tmp_path):
    assert _a15(opa, _plan(tmp_path, {"AWS": PARTNER}, effect="Deny")) == []


def test_bucket_outside_the_zone_is_out_of_scope(opa, tmp_path):
    assert _a15(opa, _plan(tmp_path, {"AWS": PARTNER}, tagged=False)) == []


def test_unbound_boundary_is_silent_in_the_rule(opa, tmp_path):
    """The rule cannot decide without the binding; the gate reports it (Task 4)."""
    assert _a15(opa, _plan(tmp_path, {"AWS": PARTNER}, boundary=None)) == []


def test_committed_fixture_pair(opa):
    compliant = gate.build_report(opa, [LIB], FIX / "ctrl_1_1_a15_compliant.json", ["ctrl_1_1"])
    non_compliant = gate.build_report(opa, [LIB], FIX / "ctrl_1_1_a15_non_compliant.json", ["ctrl_1_1"])
    assert compliant["summary"]["result"] == "PASS"
    assert compliant["summary"]["total_violation_instances"] == 0
    assert non_compliant["summary"]["result"] == "FAIL"
    assert non_compliant["controls"][0]["assertions"] == ["1.1-A15"]


# ============================================================================
# The gate: undecidable is undetermined, never passed
# ============================================================================

def test_unbound_boundary_is_reported_undetermined(opa, tmp_path):
    plan = _plan(tmp_path, {"AWS": PARTNER}, boundary=None)
    baseline = gate.build_report(opa, [LIB], plan, ["ctrl_1_1"])
    found = gate.find_binding_undetermined(opa, [LIB], plan, ["ctrl_1_1"], "v2026", baseline)
    assert [(u["assertion"], u["resource"], u["kind"]) for u in found] == [
        ("1.1-A15", "aws_s3_bucket_policy.exchange", "unbound-environment")
    ]
    assert found[0]["attribute"] == "input.swift_trust_boundary_accounts"


def test_bound_plan_has_no_binding_undetermined(opa, tmp_path):
    plan = _plan(tmp_path, {"AWS": PARTNER})
    baseline = gate.build_report(opa, [LIB], plan, ["ctrl_1_1"])
    assert gate.find_binding_undetermined(opa, [LIB], plan, ["ctrl_1_1"], "v2026", baseline) == []


def test_unknown_policy_document_makes_a15_undetermined(opa, tmp_path):
    """An R3 bucket policy could name any account: the witness must expose 1.1-A15."""
    plan = _plan(tmp_path, {"AWS": PARTNER}, policy=False)
    baseline = gate.build_report(opa, [LIB], plan, ["ctrl_1_1"])
    resolvability = {"r3_unresolvable": [{
        "resource": "aws_s3_bucket_policy.exchange", "attribute": "policy",
        "reason": "document body unknown at plan time; JSON-parsing assertions cannot decide",
    }]}
    found = gate.find_undetermined(opa, [LIB], plan, ["ctrl_1_1"], "v2026", resolvability, baseline)
    assert "1.1-A15" in {u["assertion"] for u in found}


def test_attestation_names_the_unbound_cause():
    import sys
    sys.path.insert(0, str(ROOT / "evidence"))
    import report
    assert report.UNDETERMINED_CAUSES["unbound-environment"] == "environment binding not supplied"


# ============================================================================
# The generated environments
# ============================================================================

PLANS = ROOT / "plans"


def _resolved(stem):
    return json.loads((PLANS / f"{stem}_resolved_plan.json").read_text(encoding="utf-8"))


def test_generated_plans_carry_the_declared_boundary():
    assert _resolved("compliant")["swift_trust_boundary_accounts"] == ["123456789012", "210987654321"]
    assert _resolved("non_compliant")["swift_trust_boundary_accounts"] == ["123456789012"]


def test_partner_share_is_the_one_seeded_boundary_violation(opa):
    report = gate.build_report(opa, [LIB], PLANS / "non_compliant_resolved_plan.json", ["ctrl_1_1"])
    a15 = [v for v in report["controls"][0]["violations"] if "[1.1-A15]" in v]
    assert a15 == [
        "CSCF 1.1 [1.1-A15]: S3 bucket policy grants account 444455556666, outside the "
        "declared Swift trust boundary (§ Boundary Protection). (resource: aws_s3_bucket_policy.partner_share)"
    ]


# ============================================================================
# Final-review fixes (2.1.1)
# ============================================================================

def _raw_plan(variables, policy_principal):
    """A plan as Terraform emits it: no bindings, the policy the only literal ARN."""
    policy = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": policy_principal,
        "Action": "s3:GetObject", "Resource": "arn:aws:s3:::swift-exchange/*"}]})
    return {
        "variables": {k: {"value": v} for k, v in variables.items()},
        "planned_values": {"root_module": {"resources": [
            {"address": "aws_s3_bucket.exchange", "mode": "managed", "type": "aws_s3_bucket",
             "name": "exchange", "values": {"bucket": "swift-exchange",
                                            "tags": {"swift:zone": "secure"}}},
            {"address": "aws_s3_bucket_policy.exchange", "mode": "managed",
             "type": "aws_s3_bucket_policy", "name": "exchange",
             "values": {"bucket": "swift-exchange", "policy": policy}},
        ]}},
        "resource_changes": [],
        "configuration": {"root_module": {"resources": []}},
    }


def test_an_account_scraped_from_an_arn_never_widens_the_boundary(opa, tmp_path):
    """Review C1: with no account_id variable, the first ARN in the plan may be the
    partner's own. It may name the Swift account for other rules, but it must never
    be placed inside the trust boundary."""
    plan = _raw_plan({"swift_trust_boundary_accounts": [ACCOUNT]},
                     {"AWS": f"arn:aws:iam::{PARTNER}:root"})
    resolved, _ = resolve_plan.resolve(plan, None)
    assert resolved["swift_trust_boundary_accounts"] == [ACCOUNT]
    path = tmp_path / "resolved.json"
    path.write_text(json.dumps(resolved), encoding="utf-8")
    assert len(_a15(opa, path)) == 1


def test_a_scraped_account_alone_leaves_the_boundary_unbound():
    """No declaration and no explicit account: undetermined, not a guessed boundary."""
    plan = _raw_plan({}, {"AWS": f"arn:aws:iam::{PARTNER}:root"})
    resolved, report = resolve_plan.resolve(plan, None)
    assert "swift_trust_boundary_accounts" not in resolved
    assert report["trust_boundary_accounts"] is None


def test_an_explicit_account_joins_the_boundary():
    plan = _raw_plan({"account_id": ACCOUNT}, {"AWS": f"arn:aws:iam::{PARTNER}:root"})
    resolved, _ = resolve_plan.resolve(plan, None)
    assert resolved["swift_trust_boundary_accounts"] == [ACCOUNT]
    resolved, _ = resolve_plan.resolve(_raw_plan({}, {"AWS": PARTNER}), ACCOUNT)
    assert resolved["swift_trust_boundary_accounts"] == [ACCOUNT]


def test_hand_written_plan_own_account_grant_is_not_undetermined(opa):
    """Review I3: a hand-written plan names its Swift account; a grant to that
    account alone is inside any boundary and must not be reported undetermined."""
    plan = FIX / "r7_conditions_absent.json"
    baseline = gate.build_report(opa, [LIB], plan, ["ctrl_1_1"])
    found = gate.find_binding_undetermined(opa, [LIB], plan, ["ctrl_1_1"], "v2026", baseline)
    assert "1.1-A15" not in {u["assertion"] for u in found}


def test_missing_parent_and_unbound_boundary_is_undetermined(opa, tmp_path):
    """Review I2: a change plan attaching a policy to an existing bucket, resolved
    without a boundary. Two inputs missing at once must not add up to a pass."""
    doc = json.loads(_plan(tmp_path, {"AWS": PARTNER}, boundary=None).read_text(encoding="utf-8"))
    resources = doc["planned_values"]["root_module"]["resources"]
    doc["planned_values"]["root_module"]["resources"] = [
        r for r in resources if r["type"] == "aws_s3_bucket_policy"
    ]
    plan = tmp_path / "change.json"
    plan.write_text(json.dumps(doc), encoding="utf-8")
    baseline = gate.build_report(opa, [LIB], plan, ["ctrl_1_1"])
    found = gate.find_scope_undetermined(opa, [LIB], plan, ["ctrl_1_1"], "v2026", baseline)
    found += gate.find_binding_undetermined(opa, [LIB], plan, ["ctrl_1_1"], "v2026", baseline)
    assert ("1.1-A15", "aws_s3_bucket_policy.exchange") in {
        (u["assertion"], u["resource"]) for u in found
    }


def test_unknown_document_and_unbound_boundary_is_undetermined(opa, tmp_path):
    """Review I2: an R3 policy document on a plan with no boundary bound."""
    plan = _plan(tmp_path, {"AWS": PARTNER}, boundary=None, policy=False)
    baseline = gate.build_report(opa, [LIB], plan, ["ctrl_1_1"])
    resolvability = {"r3_unresolvable": [{
        "resource": "aws_s3_bucket_policy.exchange", "attribute": "policy",
        "reason": "document body unknown at plan time; JSON-parsing assertions cannot decide",
    }]}
    found = gate.find_undetermined(opa, [LIB], plan, ["ctrl_1_1"], "v2026", resolvability, baseline)
    found += gate.find_binding_undetermined(opa, [LIB], plan, ["ctrl_1_1"], "v2026", baseline)
    assert "1.1-A15" in {u["assertion"] for u in found}


def test_federated_provider_of_a_partner_account_fires(opa, tmp_path):
    """Review I6: a partner's SAML provider is the partner's account."""
    principal = {"Federated": f"arn:aws:iam::{PARTNER}:saml-provider/partner-idp"}
    assert len(_a15(opa, _plan(tmp_path, principal))) == 1


def test_federated_web_identity_service_names_no_account(opa, tmp_path):
    assert _a15(opa, _plan(tmp_path, {"Federated": "cognito-identity.amazonaws.com"})) == []


def test_canonical_user_grant_fires(opa, tmp_path):
    """Review I6: a canonical id cannot be placed inside the boundary from the plan."""
    principal = {"CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}
    found = _a15(opa, _plan(tmp_path, principal))
    assert len(found) == 1 and "canonical user" in found[0]


def test_allow_with_not_principal_fires(opa, tmp_path):
    """Review I6: Allow + NotPrincipal grants everyone except those listed."""
    stmt = {"Effect": "Allow", "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::swift-exchange/*"}
    found = _a15(opa, _plan(tmp_path, statement=stmt))
    assert len(found) == 1 and "NotPrincipal" in found[0]


def test_deny_with_not_principal_is_a_restriction(opa, tmp_path):
    stmt = {"Effect": "Deny", "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
            "Action": "s3:*", "Resource": "arn:aws:s3:::swift-exchange/*"}
    assert _a15(opa, _plan(tmp_path, statement=stmt)) == []
