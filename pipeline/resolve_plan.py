#!/usr/bin/env python3
"""
Plan-time resolvability resolver.

A real ``terraform show -json`` plan differs from the hand-written mock plans
Phase I was validated against in two ways that break the policy library:

1. **Unknown values.** An attribute assigned from another resource -- say
   ``kms_key_id = aws_kms_key.swift_logs.arn`` -- is not yet computed at plan
   time. Terraform emits ``null`` in ``change.after`` and records the attribute
   in ``change.after_unknown``. A policy that reads only ``after`` therefore
   sees an *absent* attribute and denies a plan that is in fact configured
   correctly (a false positive), or, for a scope filter such as
   ``vpc_id == input.swift_vpc_id``, matches nothing at all and lets every
   VPC-scoped rule pass silently (a false negative -- the fail-open case).

2. **Environment bindings.** The library reads ``input.swift_account_id`` and
   ``input.swift_vpc_id``. Terraform's plan JSON carries neither: they were
   fields the hand-written mock plans supplied out of band.

This resolver closes both gaps before the gate runs, and -- the point of the
exercise -- *reports what it had to assume*. Each unknown attribute is
classified:

    R1  resolved in the plan            -- the value is literally present
    R2  resolvable by reference         -- unknown, but the configuration shows
                                           it is assigned from another resource
                                           created by this same plan, so its
                                           presence (not its value) is verified
    R3  unresolvable at plan time       -- the configuration assigns it, but not
                                           from anything this plan creates (a
                                           data source, a module output, an
                                           unknown variable); no static check
                                           can decide it
    C   computed by the provider        -- unknown because nobody assigned it;
                                           an output such as `arn` or `id` that
                                           only exists after apply. Counted, not
                                           listed: these are not policy inputs.

R2 attributes are filled with a deterministic synthetic value derived from the
reference, so a presence check evaluates correctly and every consumer of the
same reference agrees. R3 attributes are left unknown and listed in the report:
any rule that depends on one cannot decide, and the attestation must say so
rather than record a pass.

Usage:
    python resolve_plan.py --plan live_plan.json --out resolved_plan.json \
                           [--report resolvability.json] [--account-id 123456789012]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Target Profile: attributes whose Terraform value is a collection. A resolved
# reference is wrapped in a list for these and written as a scalar otherwise.
COLLECTION_ATTRIBUTES = {
    "alarm_actions",
    "cidr_blocks",
    "client_subnets",
    "insufficient_data_actions",
    "log_group_names",
    "ok_actions",
    "security_group_ids",
    "security_groups",
    "subnet_ids",
    "subnets",
    "vpc_security_group_ids",
}

# Target Profile: attributes carrying an embedded JSON document. When one of
# these is unknown at plan time there is nothing useful to substitute -- see
# the R3 branch in resolve().
DOCUMENT_ATTRIBUTES = {
    "assume_role_policy",
    "container_definitions",
    "policy",
    "policy_document",
}

# Target Profile: attributes the author may leave unset, that Terraform reports
# as "known after apply", and whose value AWS then takes from state *outside*
# the plan. A rule reading one cannot be decided from the plan, so it is R3.
# (Block indices are not part of the key: root_block_device.0.encrypted matches
# root_block_device.encrypted.)
APPLY_TIME_DEFAULTS = {
    ("aws_instance", "root_block_device.encrypted"): "ebs-default",
    ("aws_instance", "ebs_block_device.encrypted"): "ebs-default",
    ("aws_ebs_volume", "encrypted"): "ebs-default",
}
APPLY_TIME_REASONS = {
    "ebs-default": (
        "left unset, so AWS applies the account's EBS encryption-by-default "
        "setting at apply time, which this plan does not declare"
    ),
}

# Target Profile: provider-computed attributes a rule reads whose unset value is
# fixed -- the rule's reading of "absent" is the value AWS will apply. Recorded
# so every such attribute is a decision, not an oversight: the conformance suite
# fails if a rule reads a provider-computed attribute listed in neither table.
UNSET_DEFAULTS = {
    ("aws_instance", "key_name"): "no key pair",
    ("aws_instance", "iam_instance_profile"): "no instance profile",
    ("aws_instance", "tenancy"): "default tenancy, or the VPC's instance_tenancy (in the plan)",
    ("aws_instance", "associate_public_ip_address"): (
        "the subnet's map_public_ip_on_launch (in the plan; checked by 1.1-A5)"
    ),
    ("aws_default_security_group", "ingress"): "all rules removed when Terraform adopts it",
    ("aws_default_security_group", "egress"): "all rules removed when Terraform adopts it",
    ("aws_security_group", "ingress"): "rules declared as separate resources (in the plan)",
    ("aws_security_group", "egress"): "rules declared as separate resources (in the plan)",
    ("aws_s3_bucket", "object_lock_enabled"): "false",
    ("aws_lb_listener", "ssl_policy"): "AWS's default policy, which is not an approved TLS 1.2+ policy",
    ("aws_dx_connection", "encryption_mode"): "no MACsec encryption",
}

ACCOUNT_IN_ARN = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):")


def without_indices(attribute: str) -> str:
    return ".".join(p for p in attribute.split(".") if not p.isdigit())


def ebs_encrypted_by_default(resources: dict) -> bool:
    """The plan itself turns on EBS encryption by default for the account."""
    return any(
        r.get("type") == "aws_ebs_encryption_by_default"
        and (r.get("values") or {}).get("enabled") is not False
        for r in resources.values()
    )


def walk_modules(module: dict):
    """Yield every module in a planned_values / configuration module tree."""
    yield module
    for child in module.get("child_modules", []) or []:
        yield from walk_modules(child)
    for child in (module.get("module_calls") or {}).values():
        if "module" in child:
            yield from walk_modules(child["module"])


def planned_resources(plan: dict) -> dict:
    root = plan.get("planned_values", {}).get("root_module", {})
    return {
        r["address"]: r
        for module in walk_modules(root)
        for r in module.get("resources", []) or []
    }


def configured_resources(plan: dict) -> dict:
    root = plan.get("configuration", {}).get("root_module", {})
    return {
        r["address"]: r
        for module in walk_modules(root)
        for r in module.get("resources", []) or []
    }


def identifying_name(target: dict | None) -> str | None:
    """The target's own identifying attribute, when the plan already knows it.

    An IAM role's ARN ends with its `name`, an S3 bucket's id *is* its
    `bucket`. Those attributes are usually literals, so the plan knows them
    even while the ARN itself is unknown. Building the stand-in around the real
    name keeps cross-resource joins working: a rule that asks whether a
    Lambda's role ARN contains an attachment's role name still matches.
    """
    values = (target or {}).get("values", {}) or {}
    for attribute in ("name", "bucket", "domain_name", "cluster_name", "function_name"):
        value = values.get(attribute)
        if isinstance(value, str) and value:
            return value
    return None


def synthetic_value(
    ref: str, account_id: str, region: str, target: dict | None = None
) -> str:
    """A deterministic stand-in for a reference that resolves only at apply.

    Derived purely from the reference and the target's own known name, so every
    attribute assigned from the same reference receives the identical value --
    which is what makes a scope filter such as
    ``vpc_id == input.swift_vpc_id`` work again.
    """
    parts = ref.split(".")
    resource_type, resource_name = parts[0], parts[1]
    attribute = parts[2] if len(parts) > 2 else "id"

    segments = resource_type.split("_")
    service = segments[1] if len(segments) > 1 else resource_type
    kind = "_".join(segments[2:]) or service
    label = identifying_name(target) or resource_name

    if attribute == "arn":
        return f"arn:aws:{service}:{region}:{account_id}:{kind}/{label}"
    if attribute == "id" and identifying_name(target):
        return label
    return f"{resource_type}-{resource_name}-{attribute}-known-after-apply"


def unknown_attributes(after_unknown: dict) -> list[str]:
    """Top-level attributes Terraform reports as wholly unknown."""
    return sorted(k for k, v in (after_unknown or {}).items() if v is True)


def nested_unknowns(after_unknown, expressions, values, path=()):
    """Yield unknown attributes that sit *inside* a block, not at the top level.

    `vpc_options { subnet_ids = aws_subnet.swift[*].id }` puts the unknown one
    level down: after_unknown is `{"vpc_options": [{"subnet_ids": true}]}`. A
    rule reading `values.vpc_options[_].subnet_ids` sees nothing unless these
    are resolved too, so every nested read would otherwise produce the same
    false positive the top-level pass exists to prevent.

    Yields (path, attribute, expression, container) where `container` is the
    dict to write the resolved value into.
    """
    if isinstance(after_unknown, dict):
        for key, unknown in after_unknown.items():
            if unknown is True:
                continue  # handled by the top-level pass
            expression = (expressions or {}).get(key) if isinstance(expressions, dict) else None
            value = (values or {}).get(key) if isinstance(values, dict) else None
            yield from nested_unknowns(unknown, expression, value, path + (key,))
        return

    if isinstance(after_unknown, list):
        for index, unknown in enumerate(after_unknown):
            expression = (
                expressions[index]
                if isinstance(expressions, list) and index < len(expressions)
                else None
            )
            value = values[index] if isinstance(values, list) and index < len(values) else None
            if isinstance(unknown, dict) and isinstance(value, dict):
                for key, sub_unknown in unknown.items():
                    if sub_unknown is not True:
                        yield from nested_unknowns(
                            sub_unknown,
                            (expression or {}).get(key) if isinstance(expression, dict) else None,
                            value.get(key),
                            path + (str(index), key),
                        )
                        continue
                    sub_expression = (
                        (expression or {}).get(key) if isinstance(expression, dict) else None
                    )
                    yield path + (str(index),), key, sub_expression, value
            else:
                yield from nested_unknowns(unknown, expression, value, path + (str(index),))


def first_resource_reference(expression: dict, known_addresses: set[str]) -> str | None:
    """The first reference in an expression that names a resource in this plan.

    Terraform lists both ``aws_kms_key.swift_logs.arn`` and its bare address;
    the attribute-qualified form comes first and is the one worth recording.
    """
    for ref in (expression or {}).get("references", []) or []:
        parts = ref.split(".")
        if len(parts) >= 2 and ".".join(parts[:2]) in known_addresses:
            return ref
    return None


def splat_instances(expression: dict, known_addresses: set[str]) -> list[str] | None:
    """Instance addresses behind a splat over a counted resource.

    ``subnet_ids = aws_subnet.swift[*].id`` records only the bare address
    ``aws_subnet.swift``, which matches no single planned resource -- the plan
    holds ``aws_subnet.swift[0]``, ``aws_subnet.swift[1]``. Every instance is
    still created by this plan, so the reference resolves.
    """
    for ref in (expression or {}).get("references", []) or []:
        instances = sorted(a for a in known_addresses if a.startswith(f"{ref}["))
        if instances:
            return instances
    return None


def declared_account_id(plan: dict) -> str | None:
    """The Swift account as the environment states it (the ``account_id`` variable)."""
    declared = plan.get("variables", {}).get("account_id", {}).get("value")
    return str(declared) if declared else None


def detect_account_id(plan: dict) -> str | None:
    """The Swift account: declared, or else the first account in any ARN.

    The fallback is a guess -- in a real plan the first literal ARN may well be
    a partner principal in a policy -- so it is good enough to make synthetic
    ARNs well-formed, and never good enough for the trust boundary.
    """
    declared = declared_account_id(plan)
    if declared:
        return declared
    match = ACCOUNT_IN_ARN.search(json.dumps(plan.get("planned_values", {})))
    return match.group(1) if match else None


def detect_region(plan: dict) -> str:
    declared = plan.get("variables", {}).get("region", {}).get("value")
    return str(declared) if declared else "eu-west-1"


def trust_boundary(plan: dict, account_id: str | None) -> list[str] | None:
    """The accounts a Swift-zone resource may grant access to (1.1-A15).

    The environment declares them in the ``swift_trust_boundary_accounts``
    Terraform variable -- the institution's scoping decision, which an assessor
    can challenge. The Swift account is always inside. With neither a
    declaration nor a known account the boundary is unbound: the gate then
    reports 1.1-A15 undetermined rather than guessing.
    """
    declared = plan.get("variables", {}).get("swift_trust_boundary_accounts", {}).get("value")
    accounts = {str(a) for a in declared} if declared is not None else set()
    if account_id:
        accounts.add(account_id)
    return sorted(accounts) if accounts or declared is not None else None


def swift_vpc_address(resources: dict) -> str | None:
    for address, resource in resources.items():
        if resource.get("type") != "aws_vpc":
            continue
        values = resource.get("values", {}) or {}
        tags = {**(values.get("tags") or {}), **(values.get("tags_all") or {})}
        if tags.get("swift:zone") == "secure":
            return address
    return None


def resolve(plan: dict, account_id: str | None) -> tuple[dict, dict]:
    resources = planned_resources(plan)
    configs = configured_resources(plan)
    addresses = set(resources)

    # Only an account stated explicitly (--account-id, or the account_id
    # variable) may join the trust boundary. One scraped from an ARN, and the
    # placeholder that keeps synthetic ARNs well-formed, never do: the first
    # ARN in a plan can be the very partner the boundary exists to exclude.
    explicit_account = account_id or declared_account_id(plan)
    account_id = explicit_account or detect_account_id(plan) or "000000000000"
    region = detect_region(plan)

    resolved, unresolvable, identities, computed = [], [], [], 0
    # Values the provider decides at apply time and the author never set. Most
    # are outputs no rule reads (owner_id, private_ip). Those a rule reads are
    # classified in the Target Profile: APPLY_TIME_DEFAULTS (taken from state
    # outside the plan -> R3) or UNSET_DEFAULTS (fixed meaning). The full list
    # goes into the report so the conformance suite can check every rule-read
    # one is classified.
    provider_decided = []
    ebs_default = ebs_encrypted_by_default(resources)

    def apply_time_default(address: str, rtype: str, where: str, container: dict, attribute: str):
        cause = APPLY_TIME_DEFAULTS.get((rtype, without_indices(where)))
        if cause is None:
            return
        if cause == "ebs-default" and ebs_default:
            # The account setting is in this plan, so the value is known.
            container[attribute] = True
            resolved.append(
                {
                    "resource": address,
                    "attribute": where,
                    "class": "R2",
                    "reference": "aws_ebs_encryption_by_default",
                    "substituted": True,
                }
            )
            return
        unresolvable.append(
            {
                "resource": address,
                "attribute": where,
                "class": "R3",
                "reason": APPLY_TIME_REASONS[cause],
            }
        )

    for change in plan.get("resource_changes", []) or []:
        address = change["address"]
        resource = resources.get(address)
        if resource is None:
            continue
        expressions = (configs.get(address, {}) or {}).get("expressions", {}) or {}

        for attribute in unknown_attributes(change.get("change", {}).get("after_unknown")):
            if attribute not in expressions:
                # Provider-computed: unknown because the author never assigned
                # it. Usually an output (owner_id, ...), but not always -- see
                # provider_decided above. id and arn are filled below.
                computed += 1
                if attribute not in ("id", "arn"):
                    provider_decided.append(
                        {"resource": address, "type": change.get("type", ""), "attribute": attribute}
                    )
                    apply_time_default(
                        address, change.get("type", ""), attribute,
                        resource.setdefault("values", {}), attribute,
                    )
                continue

            if attribute in DOCUMENT_ATTRIBUTES:
                # An embedded JSON document -- an IAM or bucket policy -- whose
                # text interpolates an unknown ARN is unknown *in its entirety*.
                # No stand-in can help: an assertion that parses the document
                # and looks for a statement inside it cannot be evaluated at
                # plan time, and silently returns no violation. Left unset and
                # reported, so the attestation cannot record a pass.
                unresolvable.append(
                    {
                        "resource": address,
                        "attribute": attribute,
                        "class": "R3",
                        "reason": "document body unknown at plan time; "
                        "JSON-parsing assertions over it cannot be evaluated",
                        "assigned_from": (expressions.get(attribute) or {}).get(
                            "references", []
                        ),
                    }
                )
                continue

            instances = splat_instances(expressions.get(attribute), addresses)
            if instances and attribute in COLLECTION_ATTRIBUTES:
                value = [
                    synthetic_value(
                        f"{instance}.id", account_id, region, resources.get(instance)
                    )
                    for instance in instances
                ]
                resource.setdefault("values", {})[attribute] = value
                resolved.append(
                    {
                        "resource": address,
                        "attribute": attribute,
                        "class": "R2",
                        "reference": f"{instances[0].split('[')[0]}[*]",
                        "substituted": value,
                    }
                )
                continue

            reference = first_resource_reference(expressions.get(attribute), addresses)
            if reference is None:
                unresolvable.append(
                    {
                        "resource": address,
                        "attribute": attribute,
                        "class": "R3",
                        "assigned_from": (expressions.get(attribute) or {}).get(
                            "references", []
                        ),
                    }
                )
                continue
            target = resources.get(".".join(reference.split(".")[:2]))
            value = synthetic_value(reference, account_id, region, target)
            if attribute in COLLECTION_ATTRIBUTES:
                value = [value]
            resource.setdefault("values", {})[attribute] = value
            resolved.append(
                {
                    "resource": address,
                    "attribute": attribute,
                    "class": "R2",
                    "reference": reference,
                    "substituted": value,
                }
            )

    # Nested unknowns: the same treatment, one or more levels inside a block.
    for change in plan.get("resource_changes", []) or []:
        address = change["address"]
        resource = resources.get(address)
        if resource is None:
            continue
        expressions = (configs.get(address, {}) or {}).get("expressions", {}) or {}
        after_unknown = change.get("change", {}).get("after_unknown") or {}

        for path, attribute, expression, container in nested_unknowns(
            after_unknown, expressions, resource.get("values", {})
        ):
            where = ".".join(path + (attribute,))
            if expression is None:
                computed += 1
                provider_decided.append(
                    {"resource": address, "type": change.get("type", ""), "attribute": where}
                )
                apply_time_default(address, change.get("type", ""), where, container, attribute)
                continue

            if attribute in DOCUMENT_ATTRIBUTES:
                unresolvable.append(
                    {
                        "resource": address,
                        "attribute": where,
                        "class": "R3",
                        "reason": "document body unknown at plan time; "
                        "JSON-parsing assertions over it cannot be evaluated",
                        "assigned_from": (expression or {}).get("references", []),
                    }
                )
                continue

            instances = splat_instances(expression, addresses)
            if instances and attribute in COLLECTION_ATTRIBUTES:
                value = [
                    synthetic_value(
                        f"{instance}.id", account_id, region, resources.get(instance)
                    )
                    for instance in instances
                ]
            else:
                reference = first_resource_reference(expression, addresses)
                if reference is None:
                    unresolvable.append(
                        {
                            "resource": address,
                            "attribute": where,
                            "class": "R3",
                            "assigned_from": (expression or {}).get("references", []),
                        }
                    )
                    continue
                target = resources.get(".".join(reference.split(".")[:2]))
                value = synthetic_value(reference, account_id, region, target)
                if attribute in COLLECTION_ATTRIBUTES:
                    value = [value]

            container[attribute] = value
            resolved.append(
                {
                    "resource": address,
                    "attribute": where,
                    "class": "R2",
                    "reference": (
                        f"{instances[0].split('[')[0]}[*]" if instances else reference
                    ),
                    "substituted": value,
                }
            )

    # Self-identity: a resource's own computed `id` / `arn` is unknown at plan
    # time, so a cross-resource rule that joins on it (does this route's
    # gateway_id name an internet gateway in this plan?) matches nothing and
    # passes silently. Filling each identity with the same deterministic value
    # that references to it received restores the join.
    for change in plan.get("resource_changes", []) or []:
        resource = resources.get(change["address"])
        if resource is None:
            continue
        after_unknown = change.get("change", {}).get("after_unknown") or {}
        for attribute in ("id", "arn"):
            if after_unknown.get(attribute) is not True:
                continue
            reference = f"{change['address']}.{attribute}"
            value = synthetic_value(reference, account_id, region, resource)
            resource.setdefault("values", {})[attribute] = value
            identities.append(
                {
                    "resource": change["address"],
                    "attribute": attribute,
                    "class": "R2",
                    "reference": reference,
                    "substituted": value,
                }
            )

    # Terraform writes `null` for an optional attribute the author left unset;
    # the hand-written mock plans simply omitted the key. Rules are written
    # against absence (`object.get(values, "x", "") == ""`), and `null` is not
    # `""`, so an unset attribute reads as present-and-fine. Dropping nulls
    # restores the intended semantics.
    nulls = 0
    for resource in resources.values():
        values = resource.get("values")
        if not isinstance(values, dict):
            continue
        for key in [k for k, v in values.items() if v is None]:
            del values[key]
            nulls += 1

    # Environment bindings the plan JSON does not carry.
    plan["swift_account_id"] = account_id
    boundary = trust_boundary(plan, explicit_account)
    if boundary is not None:
        plan["swift_trust_boundary_accounts"] = boundary
    vpc_address = swift_vpc_address(resources)
    if vpc_address:
        plan["swift_vpc_id"] = synthetic_value(
            f"{vpc_address}.id", account_id, region, resources.get(vpc_address)
        )

    report = {
        "schema": "swift-cscf-resolvability/v1",
        "account_id": account_id,
        "region": region,
        "swift_vpc": vpc_address,
        "swift_vpc_id": plan.get("swift_vpc_id"),
        "trust_boundary_accounts": boundary,
        "summary": {
            "r2_resolved_by_reference": len(resolved),
            "r2_self_identity": len(identities),
            "r3_unresolvable": len(unresolvable),
            "provider_computed": computed,
            "null_attributes_dropped": nulls,
        },
        "r2_resolved_by_reference": resolved,
        "r2_self_identity": identities,
        "r3_unresolvable": unresolvable,
        "provider_decided": provider_decided,
    }
    plan["lct_resolvability"] = report
    return plan, report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve plan-time unknowns and environment bindings before gating"
    )
    parser.add_argument("--plan", required=True, type=Path, help="terraform show -json output")
    parser.add_argument("--out", required=True, type=Path, help="Resolved plan JSON to write")
    parser.add_argument("--report", type=Path, help="Write the resolvability report here")
    parser.add_argument(
        "--account-id",
        help="Swift account id for input.swift_account_id (default: read from plan variables)",
    )
    args = parser.parse_args()

    if not args.plan.exists():
        print(f"ERROR: plan file not found: {args.plan}", file=sys.stderr)
        return 2

    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    plan, report = resolve(plan, args.account_id)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")

    summary = report["summary"]
    print(
        f"Resolved plan written: {args.out}\n"
        f"  account binding : {report['account_id']}\n"
        f"  swift VPC       : {report['swift_vpc'] or '(none tagged swift:zone=secure)'}\n"
        f"  trust boundary  : {', '.join(report['trust_boundary_accounts'] or []) or '(unbound)'}\n"
        f"  R2 resolved by reference : {summary['r2_resolved_by_reference']}\n"
        f"  R2 self-identity         : {summary['r2_self_identity']}\n"
        f"  R3 unresolvable          : {summary['r3_unresolvable']}\n"
        f"  provider-computed        : {summary['provider_computed']}\n"
        f"  null attributes dropped  : {summary['null_attributes_dropped']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
