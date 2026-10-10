"""Parsing and counting shared by the gate and the exception mechanism.

Every deny message the library emits has the shape
    CSCF {control} [{assertion}]: {description} (resource: {address})
and an absence finding has no "(resource: ...)" part. The gate and
exceptions.py both need the (assertion, resource) pair and both need to
recount a report after moving findings out of it, so the code lives here once.
"""
from __future__ import annotations

import re

ASSERTION_RE = re.compile(r"\[([0-9]+\.[0-9]+-A[0-9]+)\]")
RESOURCE_RE = re.compile(r"\(resource:\s*([^),]+)")


def instance(violation: str) -> tuple[str, str] | None:
    """(assertion id, resource address) of a deny message; "" for an absence finding."""
    assertion = ASSERTION_RE.search(violation)
    if not assertion:
        return None
    resource = RESOURCE_RE.search(violation)
    return assertion.group(1), resource.group(1).strip() if resource else ""


def recount(report: dict) -> None:
    """Recompute per-control and summary figures from each control's `violations`."""
    total = 0
    for control in report["controls"]:
        violations = control["violations"]
        control["assertions"] = sorted(
            {m.group(1) for v in violations if (m := ASSERTION_RE.search(v))}
        )
        control["rules_fired"] = len(control["assertions"])
        control["violation_instances"] = len(violations)
        total += len(violations)
    failing = [c for c in report["controls"] if c["violation_instances"] > 0]
    summary = report["summary"]
    summary["total_violation_instances"] = total
    summary["distinct_assertions_fired"] = sum(c["rules_fired"] for c in report["controls"])
    summary["controls_with_violations"] = len(failing)
    summary["result"] = "FAIL" if failing else "PASS"
