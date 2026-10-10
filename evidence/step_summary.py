#!/usr/bin/env python3
"""Render gate evidence as Markdown for a GitHub Actions job summary.

The attestation report (report.py) is the artefact for an assessor; this is the
same verdict at a glance on the workflow run page, so a reviewer sees what the
gate decided without downloading anything.

    python step_summary.py --evidence evidence.json [--title "..."] >> "$GITHUB_STEP_SUMMARY"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import report  # noqa: E402  (reuses its parsing, titles and signature check)


def _cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(evidence: dict, title: str, public_key: Path | None) -> str:
    summary = evidence["summary"]
    undetermined = evidence.get("undetermined", []) or []
    blocked = summary["result"] == "FAIL"
    library = evidence.get("library", {})
    status, detail = report.signature_status(evidence, public_key)

    lines = [f"## {title}", ""]
    if blocked:
        lines.append(
            f"### BLOCKED: {summary['total_violation_instances']} finding(s) across "
            f"{summary['controls_with_violations']} control(s)"
        )
    else:
        excepted_count = summary.get("excepted_instances", 0)
        if excepted_count:
            lines.append(
                f"### PASS with {excepted_count} accepted risk(s): the change may proceed"
            )
        else:
            lines.append("### PASS: the change may proceed")
    lines += [
        "",
        f"Plan `{evidence.get('plan_file', '')}`, SHA-256 `{evidence.get('plan_sha256', '')[:16]}...`, "
        f"policy library {library.get('version', 'n/a')}, OPA {evidence.get('opa_version', '')}",
        "",
        f"Evidence signature: **{status.upper()}** ({detail})",
        "",
        "| Control | Verdict | Findings |",
        "|---|---|---:|",
    ]
    for control in evidence["controls"]:
        number = control["control"]
        name = report.CONTROL_TITLES.get(number, "")
        if control["violation_instances"]:
            verdict = "FAIL"
        elif control.get("excepted"):
            verdict = "EXCEPTED"
        else:
            verdict = "PASS"
        lines.append(f"| {number} {_cell(name)} | {verdict} | {control['violation_instances']} |")

    findings = [
        (control["control"], report.parse_violation(raw))
        for control in evidence["controls"]
        for raw in control["violations"]
    ]
    if findings:
        lines += ["", "#### Findings", "", "| Assertion | Resource | Finding |", "|---|---|---|"]
        for _, f in findings:
            # An absence finding names no resource: the resource is what is missing.
            resource = f"`{_cell(f['resource'])}`" if f["resource"] else "(whole plan)"
            lines.append(f"| `{f['assertion']}` | {resource} | {_cell(f['message'])} |")

    excepted = [e for control in evidence["controls"] for e in control.get("excepted") or []]
    block = evidence.get("exceptions") or {}
    if excepted:
        lines += [
            "",
            f"#### Excepted: {len(excepted)} finding(s), accepted risk, not passed",
            "",
            "| Assertion | Resource | Exception | Risk owner | Expires |",
            "|---|---|---|---|---|",
        ]
        for e in excepted:
            x = e["exception"]
            lines.append(
                f"| `{x['assertion']}` | `{_cell(x['resource'])}` | `{x['id']}` | "
                f"{_cell(x['risk_owner'])} | {x['expires_on']} |"
            )
    for x in block.get("expired", []):
        lines += ["", f"Expired exception `{x['id']}` ({x['expired_on']}): finding counted as a violation."]
    for rid in block.get("unused", []):
        lines += ["", f"Unused exception `{rid}`: matched no finding."]

    if undetermined:
        lines += [
            "",
            f"#### Undetermined: {len(undetermined)} check(s), reported, never passed",
            "",
            "| Assertion | Resource | Cause |",
            "|---|---|---|",
        ]
        for u in undetermined:
            cause = report.UNDETERMINED_CAUSES.get(u.get("kind", ""), u.get("reason", ""))
            lines.append(f"| `{u['assertion']}` | `{_cell(u.get('resource', ''))}` | {_cell(cause)} |")

    lines += [
        "",
        "The signed evidence and the HTML attestation are attached to this run as an artefact.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--title", default="CSCF compliance gate")
    parser.add_argument("--public-key", type=Path, default=report.DEFAULT_PUBLIC_KEY)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    sys.stdout.write(render(evidence, args.title, args.public_key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
