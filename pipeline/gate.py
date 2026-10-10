#!/usr/bin/env python3
"""
SWIFT CSCF v2026, Pre-Deployment Compliance Gate

Evaluates a Terraform plan JSON against the CSCF OPA/Rego policy library and
acts as a CI/CD gate: exit code 0 when the plan is compliant (no deny rules
fire), exit code 1 when any control is violated. Optionally emits a timestamped,
structured, signed evidence artefact that names the library
version it was produced by.

Usage:
    python gate.py --plan <plan.json> [--policies <dir>] [--evidence <out.json>]

    # The current library, all fifteen controls -- the defaults
    python gate.py --plan plans/compliant_resolved_plan.json \
                   --evidence evidence_compliant.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LIBRARY = REPO / "policies"
# Risk acceptances. A missing default file means none; see exceptions.py.
DEFAULT_EXCEPTIONS = REPO / "exceptions" / "exceptions.toml"

# Control module -> CSCF control number.  Module names follow ctrl_<a>_<b>.
CONTROLS = [
    "ctrl_1_1", "ctrl_1_2", "ctrl_1_3", "ctrl_1_4", "ctrl_2_1",
    "ctrl_2_2", "ctrl_2_3", "ctrl_2_4", "ctrl_2_6", "ctrl_2_7",
    "ctrl_4_1", "ctrl_4_2", "ctrl_5_1", "ctrl_5_4", "ctrl_6_4",
]
# The message parsing and the recount are shared with exceptions.py.
from findings import ASSERTION_RE, RESOURCE_RE, instance, recount  # noqa: E402
import exceptions  # noqa: E402  (risk acceptances: pipeline/exceptions.py)

# Witness documents for an R3 attribute: if substituting an admissible value
# changes an assertion's verdict, that verdict was never determined by the plan.
# Two are needed because a single witness only exposes rules it happens to move.
# An assertion demanding a restriction ("the policy must deny non-TLS access")
# is exposed by the empty document; one forbidding a permission ("the policy
# must not allow any principal") is exposed by the permissive one.
WITNESS_DOCUMENTS = {
    "empty": json.dumps({"Version": "2012-10-17", "Statement": []}),
    "permissive": json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
                # A named account outside any declared boundary, so a rule over
                # named principals (1.1-A15) is exposed as well as one over "*".
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "*",
                    "Resource": "*",
                },
            ],
        }
    ),
}


# Each witness pass gives every unresolved attribute one stand-in value: a policy
# document for a document attribute, a scalar for anything else. One scalar is
# not enough -- `encrypted != true` moves only for a value other than true,
# `encrypted == false` only for false, a threshold only for a number -- so the
# passes between them try false, true, an arbitrary string and zero.
WITNESS_VARIANTS = [
    ("empty", "empty", False),
    ("permissive", "permissive", True),
    ("opaque", "empty", None),  # None: a string naming the attribute
    ("zero", "permissive", 0),
]


def control_number(module: str) -> str:
    return module.replace("ctrl_", "").replace("_", ".")


def opa_version(opa: str) -> str:
    try:
        out = subprocess.run(
            [opa, "version"], capture_output=True, text=True, encoding="utf-8", timeout=15
        )
        for line in out.stdout.splitlines():
            if line.lower().startswith("version:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _rego_files(policy_dirs: list[Path]) -> list[tuple[Path, Path]]:
    """(root, file) for every .rego file under the given roots, in a stable order."""
    return [
        (Path(root), path)
        for root in policy_dirs
        for path in sorted(Path(root).rglob("*.rego"))
    ]


def check_policy_roots(policy_dirs: list[Path]) -> None:
    """Refuse two roots that define the same policy file.

    Rego merges a package across files, so two roots defining the same file
    compile cleanly and silently evaluate both: every rule fires twice, and a
    corrected rule fires next to the version it replaced. Each library is
    loaded on its own.
    """
    seen: dict[str, Path] = {}
    for root, path in _rego_files(policy_dirs):
        relative = path.relative_to(root).as_posix()
        if relative in seen and seen[relative] != root:
            raise ValueError(
                f"{relative} is defined under both {seen[relative]} and {root}; "
                "load one library at a time (Rego merges packages across roots, "
                "so both would be evaluated silently)"
            )
        seen[relative] = root


def library_info(opa: str, policy_dirs: list[Path]) -> dict:
    """The library version the policies declare, and a digest of their source.

    The digest is over each file's path and content with line endings
    normalised, so a checkout with CRLF endings digests the same as CI's.
    """
    digest = hashlib.sha256()
    files = _rego_files(policy_dirs)
    for root, path in files:
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")

    cmd = [opa, "eval", "-f", "json"]
    for policy_dir in policy_dirs:
        cmd += ["-d", str(policy_dir)]
    cmd.append("data.swift_cscf.library.version")
    version = None
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=60)
    if result.returncode == 0:
        try:
            version = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, ValueError):
            version = None  # a library without a version record
    return {
        "version": version or "undeclared",
        "digest": f"sha256:{digest.hexdigest()}",
        "files": len(files),
    }


def eval_control(
    opa: str, policy_dirs: list[Path], plan: Path, module: str, cscf_version: str = "v2026"
) -> list[str]:
    """Return the list of violation messages for one control module.

    ``policy_dirs`` is normally the one library root; more than one is accepted
    for a library split across directories, provided no file is defined twice
    (``check_policy_roots``). ``cscf_version`` selects the package namespace
    (``swift_cscf.<version>.<module>``) so a v2027 delta control can be gated
    alongside the v2026 library.
    """
    query = f"data.swift_cscf.{cscf_version}.{module}.deny"
    cmd = [opa, "eval"]
    for policy_dir in policy_dirs:
        cmd += ["-d", str(policy_dir)]
    cmd += ["-i", str(plan), query, "-f", "json"]
    # Force UTF-8 decoding of OPA output: violation messages contain the section
    # sign (U+00A7); relying on the host's default (cp1252 on Windows) corrupts
    # the evidence artefact.
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"OPA error evaluating {module}: {result.stderr.strip()}")
    payload = json.loads(result.stdout or "{}")
    try:
        value = payload["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError):
        value = []  # undefined query -> no violations
    return sorted(str(v) for v in (value or []))


# The first library's resource traversal walked the root module and two levels
# of child_modules only (docs/failure-modes.md, section 7). The current library
# traverses every depth, so for it the lifting below changes nothing; it keeps
# the gate safe for a policy set with a shallow traversal.
HELPER_TRAVERSAL_DEPTH = 2


def flatten_deep_modules(plan: dict) -> int:
    """Lift resources nested deeper than a shallow traversal can see into the root module.

    A resource three modules deep was invisible to every rule in the first
    library: the traversal never reached it, so it could violate anything and
    the plan still passed. Real estates nest that deeply routinely (root ->
    zone -> network -> edge). The current library corrects the traversal
    itself; the plan is still normalised, which changes nothing for it.

    Each resource keeps its full `address` (module.zone.module.network...), so
    findings still name it exactly and the module-path scope predicate still
    works. Returns how many resources were moved.
    """
    root = plan.get("planned_values", {}).get("root_module", {})
    lifted = []

    def walk(module, depth):
        for child in module.get("child_modules", []) or []:
            if depth + 1 > HELPER_TRAVERSAL_DEPTH:
                lifted.extend(child.get("resources", []) or [])
                child["resources"] = []
            walk(child, depth + 1)

    walk(root, 0)
    if lifted:
        root.setdefault("resources", []).extend(lifted)
    return len(lifted)


def split_global_findings(violations: list[str]) -> tuple[list[str], list[str]]:
    """Separate findings that name a resource from findings that cannot.

    A rule reports either "this resource is wrong" or "nothing in this plan
    provides X". Only the first kind can name a resource, so the message shape
    is itself the signal: **a finding with no resource attribution is asserting
    a global absence.** An absence cannot be concluded from a plan that
    describes only part of an environment -- a plan that adds one server does
    not re-declare the account's CloudTrail -- so on an incremental plan those
    findings are undetermined rather than violations.

    Note this is not the same as "the resource must not exist" (5.1-A3, a
    direct policy attachment): that finding names the offending resource, is
    present in the change itself, and stays a violation.
    """
    attributed = [v for v in violations if "(resource:" in v]
    globals_ = [v for v in violations if "(resource:" not in v]
    return attributed, globals_


def apply_plan_scope(report: dict) -> list[dict]:
    """Downgrade absence findings to undetermined for an incremental plan."""
    downgraded = []
    for control in report["controls"]:
        attributed, globals_ = split_global_findings(control["violations"])
        for finding in globals_:
            match = ASSERTION_RE.search(finding)
            downgraded.append(
                {
                    "control": control["control"],
                    "assertion": match.group(1) if match else "",
                    "resource": "",
                    "attribute": "(whole plan)",
                    "kind": "incomplete-plan",
                    "reason": (
                        "this assertion reports the absence of a resource, and an "
                        "incremental plan does not describe the whole environment; "
                        "verify it against a full-environment plan"
                    ),
                }
            )
        control["violations"] = attributed
    recount(report)
    return downgraded


def _iter_planned_resources(plan: dict):
    def walk(module):
        yield from module.get("resources", []) or []
        for child in module.get("child_modules", []) or []:
            yield from walk(child)

    yield from walk(plan.get("planned_values", {}).get("root_module", {}))


def _set_path(values: dict, dotted: str, value) -> bool:
    """Set `values` at a dotted path such as root_block_device.0.encrypted."""
    node = values
    parts = dotted.split(".")
    for part in parts[:-1]:
        if isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        elif isinstance(node, dict) and isinstance(node.get(part), (dict, list)):
            node = node[part]
        else:
            return False
    if not isinstance(node, dict):
        return False
    node[parts[-1]] = value
    return True


def _is_document(entry: dict) -> bool:
    return "document body unknown" in entry.get("reason", "")


def build_witness_plan(
    plan_path: Path, entries: list[dict], out_path: Path, document: str, scalar=None
) -> set[str]:
    """Write a copy of the plan with every R3 attribute given a witness value.

    An R3 attribute is unknown at plan time, so a rule that reads it cannot
    decide. Filling it with *some* admissible value and re-evaluating shows
    which assertions actually depend on it: any assertion whose verdict moves
    between the two runs was undetermined, not passed.

    `entries` is a resolvability report, or its R3 list. Returns the set of
    resource addresses carrying an R3 attribute.
    """
    if isinstance(entries, dict):
        entries = entries.get("r3_unresolvable", []) or []
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    resources = {r["address"]: r for r in _iter_planned_resources(plan)}
    affected: set[str] = set()

    for entry in entries:
        resource = resources.get(entry["resource"])
        if resource is None:
            continue
        attribute = entry["attribute"]
        if _is_document(entry):
            witness = document
        elif scalar is None:
            witness = f"{entry['resource']}-{attribute}-witness"
        else:
            witness = scalar
        if _set_path(resource.setdefault("values", {}), attribute, witness):
            affected.add(entry["resource"])

    out_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return affected


def _instances(violations: list[str]) -> set[tuple[str, str]]:
    """(assertion id, resource address) pairs from a list of deny messages."""
    return {i for v in violations if (i := instance(v))}


def find_undetermined(
    opa: str,
    policy_dirs: list[Path],
    plan: Path,
    modules: list[str],
    cscf_version: str,
    resolvability: dict,
    baseline: dict,
) -> list[dict]:
    """Assertions whose verdict depends on a value unknown at plan time."""
    entries = resolvability.get("r3_unresolvable", []) or []
    if not entries:
        return []

    by_resource: dict[str, list[dict]] = {}
    for entry in entries:
        by_resource.setdefault(entry["resource"], []).append(entry)

    # Each witness exposes a different family of rules, so the moved sets are
    # unioned: an assertion is undetermined if *any* admissible value changes it.
    # Documents need two passes; scalars need all four.
    variants = WITNESS_VARIANTS
    if all(_is_document(e) for e in entries):
        variants = WITNESS_VARIANTS[:2]
    moved_by_module: dict[str, set[tuple[str, str]]] = {m: set() for m in modules}
    with tempfile.TemporaryDirectory() as tmp:
        plan, baseline_by_module = _with_missing_bindings(
            opa, policy_dirs, plan, modules, cscf_version, baseline, tmp
        )
        for name, document, scalar in variants:
            witness_path = Path(tmp) / f"witness_{name}.json"
            affected = build_witness_plan(
                plan, entries, witness_path, WITNESS_DOCUMENTS[document], scalar
            )
            if not affected:
                return []
            for module in modules:
                instances = _instances(
                    eval_control(opa, policy_dirs, witness_path, module, cscf_version)
                )
                moved_by_module[module] |= instances.symmetric_difference(
                    baseline_by_module.get(module, set())
                )

    undetermined = []
    for module, moved in moved_by_module.items():
        for assertion, resource in sorted(moved):
            unresolved = by_resource.get(resource, [])
            causes = sorted(
                {e["reason"] for e in unresolved if e.get("reason") and not _is_document(e)}
            )
            undetermined.append(
                {
                    "control": control_number(module),
                    "assertion": assertion,
                    "resource": resource,
                    "attribute": ", ".join(sorted({e["attribute"] for e in unresolved}))
                    or "(indirect)",
                    "kind": "unresolved-value",
                    "reason": (
                        "the attribute this assertion reads is unknown at plan time; "
                        "the verdict changes when it is given a value, so the plan "
                        "does not determine it"
                        + (f" ({'; '.join(causes)})" if causes else "")
                    ),
                }
            )
    return undetermined


# Sub-resources that take their Swift-zone scope from a parent they reference:
# child type -> (reference attribute, parent types). This mirrors the
# parent_scope calls in the library, and a conformance test keeps the two in
# step. The identifying attributes mirror parent_scope._identifies.
PARENT_REFERENCES = {
    "aws_s3_bucket_policy": ("bucket", ("aws_s3_bucket",)),
    "aws_iam_role_policy": ("role", ("aws_iam_role",)),
    "aws_route": ("route_table_id", ("aws_route_table",)),
    "aws_security_group_rule": ("security_group_id", ("aws_security_group",)),
    "aws_vpc_security_group_ingress_rule": ("security_group_id", ("aws_security_group",)),
    "aws_vpc_security_group_egress_rule": ("security_group_id", ("aws_security_group",)),
    "aws_network_acl_rule": ("network_acl_id", ("aws_network_acl", "aws_default_network_acl")),
    "aws_ec2_client_vpn_authorization_rule": (
        "client_vpn_endpoint_id", ("aws_ec2_client_vpn_endpoint",)
    ),
    "aws_efs_file_system_policy": ("file_system_id", ("aws_efs_file_system",)),
    "aws_secretsmanager_secret_rotation": ("secret_id", ("aws_secretsmanager_secret",)),
}
IDENTIFYING_ATTRIBUTES = ("name", "bucket", "id", "arn")


def dangling_parents(plan: dict) -> list[dict]:
    """Sub-resources whose parent is not in the plan.

    A change plan routinely references an existing resource by id -- a policy
    for a bucket created long ago -- and a hand-written plan may simply omit it.
    Either way the sub-resource's zone cannot be read from the plan, and a
    scoped rule over it would otherwise pass silently.
    """
    resources = list(_iter_planned_resources(plan))
    keys_by_type: dict[str, set[str]] = {}
    for resource in resources:
        values = resource.get("values") or {}
        keys_by_type.setdefault(resource.get("type", ""), set()).update(
            value
            for attribute in IDENTIFYING_ATTRIBUTES
            if isinstance(value := values.get(attribute), str) and value
        )

    dangling = []
    for resource in resources:
        reference = PARENT_REFERENCES.get(resource.get("type", ""))
        if not reference:
            continue
        attribute, parent_types = reference
        key = (resource.get("values") or {}).get(attribute)
        if not isinstance(key, str) or not key:
            continue
        if any(key in keys_by_type.get(t, set()) for t in parent_types):
            continue
        dangling.append(
            {
                "resource": resource["address"],
                "attribute": attribute,
                "parent_type": parent_types[0],
                "key": key,
            }
        )
    return dangling


def build_scope_witness(plan: dict, dangling: list[dict], out_path: Path) -> None:
    """Write a copy of the plan with each missing parent supplied, in the Swift zone.

    One synthetic parent per (type, key): two sub-resources of the same missing
    parent must resolve to the same resource, as they would in reality.
    """
    plan = json.loads(json.dumps(plan))
    root = plan.setdefault("planned_values", {}).setdefault("root_module", {})
    zone = {"swift:zone": "secure"}
    supplied = set()
    for entry in dangling:
        if (entry["parent_type"], entry["key"]) in supplied:
            continue
        supplied.add((entry["parent_type"], entry["key"]))
        values = {attribute: entry["key"] for attribute in IDENTIFYING_ATTRIBUTES}
        values.update({"tags": dict(zone), "tags_all": dict(zone)})
        if plan.get("swift_vpc_id"):
            values["vpc_id"] = plan["swift_vpc_id"]
        root.setdefault("resources", []).append(
            {
                "address": f"{entry['parent_type']}.scope_witness_{len(supplied)}",
                "mode": "managed",
                "type": entry["parent_type"],
                "name": f"scope_witness_{len(supplied)}",
                "values": values,
            }
        )
    out_path.write_text(json.dumps(plan), encoding="utf-8")


def find_scope_undetermined(
    opa: str,
    policy_dirs: list[Path],
    plan: Path,
    modules: list[str],
    cscf_version: str,
    baseline: dict,
) -> list[dict]:
    """Assertions over a sub-resource whose verdict depends on a parent outside the plan.

    The witness supplies every missing parent inside the Swift zone. A finding
    on the sub-resource that appears only then was not a pass: the plan could
    not say whether the resource is in scope.
    """
    document = json.loads(plan.read_text(encoding="utf-8"))
    dangling = dangling_parents(document)
    if not dangling:
        return []
    children = {entry["resource"]: entry for entry in dangling}

    undetermined = []
    with tempfile.TemporaryDirectory() as tmp:
        bound, baseline_by_module = _with_missing_bindings(
            opa, policy_dirs, plan, modules, cscf_version, baseline, tmp
        )
        document = json.loads(bound.read_text(encoding="utf-8"))
        witness = Path(tmp) / "scope_witness.json"
        build_scope_witness(document, dangling, witness)
        for module in modules:
            instances = _instances(
                eval_control(opa, policy_dirs, witness, module, cscf_version)
            )
            moved = instances.symmetric_difference(baseline_by_module.get(module, set()))
            for assertion, resource in sorted(moved):
                entry = children.get(resource)
                if entry is None:
                    continue
                undetermined.append(
                    {
                        "control": control_number(module),
                        "assertion": assertion,
                        "resource": resource,
                        "attribute": entry["attribute"],
                        "kind": "unresolved-scope",
                        "parent": f"{entry['parent_type']} '{entry['key']}'",
                        "reason": (
                            "this resource takes its scope from the "
                            f"{entry['parent_type']} it references ('{entry['key']}'), "
                            "which is not in the plan; the assertion fires when that "
                            "parent is in the Swift zone, so the plan does not "
                            "determine it"
                        ),
                    }
                )
    return undetermined


# Environment bindings a rule compares against and a plan may not carry. With a
# binding absent the rule cannot fire, so the gate supplies its most restrictive
# admissible value -- here, a boundary holding no account -- and reports every
# finding that appears only then as undetermined.
BINDING_WITNESSES = {"swift_trust_boundary_accounts": []}


def missing_bindings(document: dict) -> dict:
    """The environment bindings a plan lacks, each at its most restrictive value.

    A boundary holds no account -- except that a hand-written plan (one never
    passed through resolve_plan.py) states its Swift account deliberately, and
    the Swift account is inside any boundary. A resolved plan without a
    boundary had no explicitly known account, so its swift_account_id may be a
    guess and is not trusted here.
    """
    missing = {k: list(v) for k, v in BINDING_WITNESSES.items() if k not in document}
    if (
        "swift_trust_boundary_accounts" in missing
        and document.get("swift_account_id")
        and "lct_resolvability" not in document
    ):
        missing["swift_trust_boundary_accounts"] = [str(document["swift_account_id"])]
    return missing


def _with_missing_bindings(
    opa: str,
    policy_dirs: list[Path],
    plan: Path,
    modules: list[str],
    cscf_version: str,
    baseline: dict,
    tmp: str,
) -> tuple[Path, dict]:
    """The plan other witnesses should start from, and the baseline to compare with.

    A witness varies one missing input. When a binding is missing too, it is
    supplied to both the witness and its baseline, so the witness still isolates
    its own input -- and two missing inputs cannot add up to a silent pass.
    """
    document = json.loads(plan.read_text(encoding="utf-8"))
    missing = missing_bindings(document)
    if not missing:
        return plan, {c["module"]: _instances(c["violations"]) for c in baseline["controls"]}
    document.update(missing)
    bound = Path(tmp) / "bound_plan.json"
    bound.write_text(json.dumps(document), encoding="utf-8")
    return bound, {
        module: _instances(eval_control(opa, policy_dirs, bound, module, cscf_version))
        for module in modules
    }


def find_binding_undetermined(
    opa: str,
    policy_dirs: list[Path],
    plan: Path,
    modules: list[str],
    cscf_version: str,
    baseline: dict,
) -> list[dict]:
    """Assertions that depend on an environment binding the plan does not carry."""
    document = json.loads(plan.read_text(encoding="utf-8"))
    missing = missing_bindings(document)
    if not missing:
        return []
    document.update(missing)
    baseline_by_module = {
        c["module"]: _instances(c["violations"]) for c in baseline["controls"]
    }

    undetermined = []
    with tempfile.TemporaryDirectory() as tmp:
        witness = Path(tmp) / "binding_witness.json"
        witness.write_text(json.dumps(document), encoding="utf-8")
        for module in modules:
            instances = _instances(
                eval_control(opa, policy_dirs, witness, module, cscf_version)
            )
            for assertion, resource in sorted(instances - baseline_by_module.get(module, set())):
                undetermined.append(
                    {
                        "control": control_number(module),
                        "assertion": assertion,
                        "resource": resource,
                        "attribute": ", ".join(f"input.{k}" for k in sorted(missing)),
                        "kind": "unbound-environment",
                        "reason": (
                            "this assertion compares the resource with the Swift trust "
                            "boundary, which the plan does not carry; resolve the plan "
                            "with resolve_plan.py or declare swift_trust_boundary_accounts"
                        ),
                    }
                )
    return undetermined


def build_report(
    opa: str,
    policy_dirs: list[Path],
    plan: Path,
    modules: list[str],
    cscf_version: str = "v2026",
    source: Path | None = None,
) -> dict:
    """Evaluate `plan`. `source` is the file as supplied, when `plan` is a
    normalised copy of it: the evidence must identify what the assessor holds,
    not a temporary file."""
    source = source or plan
    check_policy_roots(policy_dirs)
    controls = []
    total_instances = 0
    for module in modules:
        violations = eval_control(opa, policy_dirs, plan, module, cscf_version)
        assertions = sorted({m.group(1) for v in violations if (m := ASSERTION_RE.search(v))})
        total_instances += len(violations)
        controls.append(
            {
                "control": control_number(module),
                "module": module,
                "rules_fired": len(assertions),          # distinct assertion IDs
                "violation_instances": len(violations),  # individual deny messages
                "assertions": assertions,
                "violations": violations,
            }
        )
    failing = [c for c in controls if c["violation_instances"] > 0]
    return {
        "schema": "swift-cscf-evidence/v1",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "cscf_version": cscf_version,
        "plan_file": source.name,
        "plan_sha256": sha256(source),
        "opa_version": opa_version(opa),
        "library": library_info(opa, policy_dirs),
        "controls": controls,
        "summary": {
            "total_violation_instances": total_instances,
            "distinct_assertions_fired": sum(c["rules_fired"] for c in controls),
            "controls_with_violations": len(failing),
            "result": "FAIL" if failing else "PASS",
        },
    }


def _display_path(path: Path) -> str:
    """The path relative to the repository when it is inside it, else as given."""
    try:
        return path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return str(path)


def print_summary(report: dict) -> None:
    line = "=" * 70
    print(line)
    print(f"  SWIFT CSCF {report['cscf_version']} Compliance Gate  --  plan: {report['plan_file']}")
    scope = report.get("plan_scope", "full")
    print(
        f"  OPA {report['opa_version']}  |  plan sha256: {report['plan_sha256'][:16]}..."
        f"  |  plan scope: {scope}"
    )
    library = report.get("library")
    if library:
        print(f"  Policy library {library['version']}  |  {library['digest'][:23]}...")
    print(line)
    for c in report["controls"]:
        if c["violation_instances"]:
            mark = "FAIL"
        elif c.get("excepted"):
            mark = "EXCEPTED"
        else:
            mark = "PASS"
        print(
            f"  [{mark}] Control {c['control']:<4} "
            f"{c['violation_instances']:>3} violation instance(s), "
            f"{c['rules_fired']:>2} rule(s) fired"
        )
        for v in c["violations"]:
            print(f"         - {v[:110]}{'...' if len(v) > 110 else ''}")
    undetermined = report.get("undetermined", [])
    if undetermined:
        print("-" * 70)
        print(f"  UNDETERMINED ({len(undetermined)}) -- not evaluated, not passed:")
        for u in undetermined:
            if u.get("kind") == "incomplete-plan":
                print(
                    f"         ? CSCF {u['control']} [{u['assertion']}] "
                    f"absence not decidable from an incremental plan"
                )
            elif u.get("kind") == "unresolved-scope":
                print(
                    f"         ? CSCF {u['control']} [{u['assertion']}] "
                    f"{u['resource']}: parent {u['parent']} not in the plan"
                )
            else:
                print(
                    f"         ? CSCF {u['control']} [{u['assertion']}] "
                    f"{u['resource']}.{u['attribute']} unknown at plan time"
                )
    block = report.get("exceptions")
    if block:
        excepted = [
            (c["control"], e) for c in report["controls"] for e in c.get("excepted", [])
        ]
        if excepted or block["expired"] or block["unused"]:
            print("-" * 70)
        if excepted:
            print(f"  EXCEPTED ({len(excepted)}) -- accepted risk, not passed:")
            for control, e in excepted:
                x = e["exception"]
                print(f"         ~ CSCF {control} [{x['assertion']}] {x['resource']}")
                print(
                    f"             {x['id']}, owner {x['risk_owner']}, "
                    f"expires {x['expires_on']}"
                )
        for x in block["expired"]:
            print(
                f"  EXPIRED EXCEPTION: {x['id']} expired {x['expired_on']} "
                "-- finding counted as a violation"
            )
        for rid in block["unused"]:
            print(f"  UNUSED EXCEPTION:  {rid} matched no finding")
    s = report["summary"]
    print("-" * 70)
    excepted_suffix = (
        f", {s['excepted_instances']} excepted" if s.get("excepted_instances") else ""
    )
    print(
        f"  TOTAL: {s['total_violation_instances']} violation instance(s), "
        f"{s['distinct_assertions_fired']} distinct assertion(s) across "
        f"{s['controls_with_violations']} control(s){excepted_suffix}"
    )
    if s.get("undetermined_instances"):
        print(
            f"  UNDETERMINED: {s['undetermined_instances']} check(s) over "
            f"{s['undetermined_assertions']} assertion(s) could not be evaluated"
        )
    print(f"  RESULT: {s['result']}")
    print(line)


def main() -> int:
    parser = argparse.ArgumentParser(description="SWIFT CSCF pre-deployment compliance gate")
    parser.add_argument("--plan", required=True, type=Path, help="Terraform plan JSON")
    parser.add_argument(
        "--policies",
        type=Path,
        nargs="+",
        default=[LIBRARY],
        help=(
            "OPA policy root (default: the current library, policies/). "
            "Two roots that define the same file are refused."
        ),
    )
    parser.add_argument(
        "--controls",
        help=(
            "Comma-separated control modules to evaluate "
            f"(default: {','.join(CONTROLS)}). e.g. --controls ctrl_1_4"
        ),
    )
    parser.add_argument(
        "--cscf-version",
        default="v2026",
        help="CSCF package namespace to evaluate (default: v2026). Use v2027 for the v2027 delta.",
    )
    parser.add_argument(
        "--plan-scope",
        choices=("full", "incremental"),
        default="full",
        help=(
            "Whether the plan describes the whole environment (default) or only a "
            "change to it. On an incremental plan, assertions that report the "
            "absence of a resource -- no CloudTrail, no GuardDuty detector -- cannot "
            "be decided, because the plan does not re-declare what already exists; "
            "they are reported as UNDETERMINED instead of violated."
        ),
    )
    parser.add_argument(
        "--resolvability",
        type=Path,
        help=(
            "Resolvability report from resolve_plan.py. Enables the third verdict: "
            "assertions that depend on a value unknown at plan time are reported as "
            "UNDETERMINED rather than counted as passes."
        ),
    )
    parser.add_argument(
        "--fail-on-undetermined",
        action="store_true",
        help=(
            "Exit non-zero when any check is undetermined. The conservative posture "
            "for a production SWIFT zone: what the gate could not evaluate must not "
            "silently ship."
        ),
    )
    parser.add_argument(
        "--exceptions",
        type=Path,
        default=None,
        help=(
            "Risk acceptances (TOML; see pipeline/exceptions.py). Default: "
            "exceptions/exceptions.toml if it exists, otherwise none. A finding covered "
            "by an active exception is reported as EXCEPTED -- accepted risk, not passed -- "
            "and recorded in the evidence; an expired exception no longer applies."
        ),
    )
    parser.add_argument("--evidence", type=Path, help="Write evidence JSON artefact to this path")
    parser.add_argument(
        "--signing-key",
        help=(
            "Ed25519 private key (PEM) to sign the evidence with. Defaults to the "
            "CSCF_EVIDENCE_SIGNING_KEY environment variable, which is how CI supplies it; "
            "evidence is written unsigned when neither is present."
        ),
    )
    parser.add_argument("--opa", default="opa", help="Path to the OPA binary (default: opa on PATH)")
    args = parser.parse_args()

    opa = shutil.which(args.opa) or args.opa
    if shutil.which(args.opa) is None and not Path(args.opa).exists():
        print(f"ERROR: OPA binary not found: {args.opa}", file=sys.stderr)
        return 2
    if not args.plan.exists():
        print(f"ERROR: plan file not found: {args.plan}", file=sys.stderr)
        return 2
    for policy_dir in args.policies:
        if not policy_dir.exists():
            print(f"ERROR: policies dir not found: {policy_dir}", file=sys.stderr)
            return 2
    try:
        check_policy_roots(args.policies)
    except ValueError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 2

    # Load exceptions before any OPA evaluation, so a bad file fails fast.
    today = _dt.datetime.now(_dt.timezone.utc).date()
    if args.exceptions is not None and not args.exceptions.exists():
        print(f"ERROR: exceptions file not found: {args.exceptions}", file=sys.stderr)
        return 2
    exceptions_path = args.exceptions if args.exceptions is not None else DEFAULT_EXCEPTIONS
    records = None
    exceptions_sha = ""
    if exceptions_path.exists():
        try:
            records, exceptions_sha = exceptions.load(exceptions_path, today)
        except exceptions.ExceptionFileError as err:
            print(f"ERROR: {err}", file=sys.stderr)
            return 2

    modules = (
        [c.strip() for c in args.controls.split(",") if c.strip()]
        if args.controls
        else CONTROLS
    )
    # Normalise module depth before anything is evaluated, so the witness plans
    # built for undetermined detection see the same document the report does.
    workdir = tempfile.TemporaryDirectory()
    eval_plan = args.plan
    plan_doc = json.loads(args.plan.read_text(encoding="utf-8"))
    lifted = flatten_deep_modules(plan_doc)
    if lifted:
        eval_plan = Path(workdir.name) / args.plan.name
        eval_plan.write_text(json.dumps(plan_doc), encoding="utf-8")

    report = build_report(
        opa, args.policies, eval_plan, modules, args.cscf_version, source=args.plan
    )
    if lifted:
        report["module_normalisation"] = {
            "resources_lifted": lifted,
            "reason": (
                f"resources nested deeper than {HELPER_TRAVERSAL_DEPTH} module levels are "
                "invisible to the library's resource traversal; they were lifted into "
                "the root module, keeping their full addresses, before evaluation"
            ),
        }

    undetermined = []
    if args.plan_scope == "incremental":
        undetermined += apply_plan_scope(report)
    report["plan_scope"] = args.plan_scope

    if args.resolvability:
        if not args.resolvability.exists():
            print(
                f"ERROR: resolvability report not found: {args.resolvability}",
                file=sys.stderr,
            )
            return 2
        resolvability = json.loads(args.resolvability.read_text(encoding="utf-8"))
        undetermined += find_undetermined(
            opa,
            args.policies,
            eval_plan,
            modules,
            args.cscf_version,
            resolvability,
            report,
        )

    # Needs no report: a sub-resource whose parent is absent is visible in the plan.
    undetermined += find_scope_undetermined(
        opa, args.policies, eval_plan, modules, args.cscf_version, report
    )

    # Needs no report either: a missing binding is visible in the plan itself.
    undetermined += find_binding_undetermined(
        opa, args.policies, eval_plan, modules, args.cscf_version, report
    )

    if undetermined:
        report["undetermined"] = undetermined
        report["summary"]["undetermined_instances"] = len(undetermined)
        report["summary"]["undetermined_assertions"] = len(
            {u["assertion"] for u in undetermined}
        )

    # Last, after every undetermined check: those compare witness runs with the
    # report's violations and must see what the gate actually found.
    if records is not None:
        exceptions.apply(
            report, records, today, _display_path(exceptions_path), exceptions_sha
        )

    print_summary(report)
    if lifted:
        print(
            f"  NOTE: {lifted} resource(s) nested deeper than {HELPER_TRAVERSAL_DEPTH} "
            "module levels were lifted so the library could see them."
        )
    workdir.cleanup()

    if args.evidence:
        signed_by = None
        if args.signing_key or os.environ.get("CSCF_EVIDENCE_SIGNING_KEY"):
            # Imported only when signing, so unsigned runs need no crypto package.
            import evidence_signing

            key = evidence_signing.private_key_from(args.signing_key)
            report = evidence_signing.sign(report, key)
            signed_by = report["signature"]["key_id"]
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"  Evidence written: {args.evidence}")
        if signed_by:
            print(f"  Evidence signed: Ed25519, key {signed_by}")

    if report["summary"]["result"] == "FAIL":
        return 1
    if args.fail_on_undetermined and report["summary"].get("undetermined_instances"):
        print(
            "  BLOCKED: undetermined checks present and --fail-on-undetermined is set",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
