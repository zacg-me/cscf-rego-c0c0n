#!/usr/bin/env python3
"""Build the consolidated CSCF traceability matrix (all 15 controls).

Phase I committed to "a bidirectional traceability matrix: every CSCF
sub-requirement linked to its assertion, deny rule, and (where applicable)
exclusion rationale". The Phase I spreadsheet covered its five controls only;
the ten Phase II controls recorded their traceability in separate translation
documents. This script joins them into one matrix and adds what only the
current library (2.1.2) knows: which rules realise each assertion, whether each
rule applies the scope it declares, what the 2.0.0 re-issue corrected, and what
each assertion does on the generated non-compliant plan.

It is generated rather than hand-maintained, so it cannot drift from the code:
the conformance suite rebuilds it and compares against the committed
traceability.json, failing if a rule, assertion or verdict changed without the
matrix being regenerated.

Sources, in order of authority:
  the Rego library          rules, and the assertion each rule reports
  translations/*.md         Phase II requirements, assertions, exclusions
  Phase I spreadsheet       Phase I assertions and exclusions
  plans/*_evidence.json     verdicts on the generated environments

Run from the repository root:

    python traceability/build_matrix.py          # JSON + CSV
    python traceability/build_matrix.py --xlsx   # + spreadsheet
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P2 = ROOT
OUT = P2 / "traceability"

PHASE1_SNAPSHOT = OUT / "phase1_register.json"

CONTROL_NAMES = {
    "1.1": "Swift Environment Protection",
    "1.2": "Operating System Privileged Account Control",
    "1.3": "Virtualisation or Cloud Platform Protection",
    "1.4": "Restriction of Internet Access",
    "2.1": "Internal Data Flow Security",
    "2.2": "Security Updates",
    "2.3": "System Hardening",
    "2.4": "Back Office Data Flow Security",
    "2.6": "Operator Session Confidentiality and Integrity",
    "2.7": "Vulnerability Scanning",
    "4.1": "Password Policy",
    "4.2": "Multi-Factor Authentication",
    "5.1": "Logical Access Control",
    "5.4": "Password Repository Protection",
    "6.4": "Logging and Monitoring",
}
PHASE1_CONTROLS = ("1.1", "2.1", "4.1", "5.1", "6.4")

ASSERTION_IN_MESSAGE = re.compile(r"\[(\d+\.\d+-A\d+)\]")
ASSERTION_HEADER = re.compile(r"#\s+(\d+\.\d+-A\d+)(?:\s*\([^)]*\))?:\s*(.+)")
SCOPE_HEADER = re.compile(r"#\s+Scope:\s*([^|\n]+)")

LIBRARY_VERSION = "2.1.2"
ADDED_IN_2_1_0 = {"1.1-A15"}

# Why an assertion that exists does not fire on the generated non-compliant
# plan. Everything not listed here must fire or be measured undetermined.
EXPLAINED = {
    "4.1-A1": "mutually exclusive with 4.1-A2..A10: a weak password policy exists, "
              "so 'no policy at all' cannot also hold",
    "4.1-A18": "mutually exclusive with 4.1-A17: fine-grained access control is off, "
               "so the internal-user-database branch is unreachable",
    "6.4-A9": "subsumed by 6.4-A8 (365-day retention discharges the 31-day floor); "
              "deliberately realised by no rule of its own",
    "4.1-A20": "CSCF v2027 delta; evaluated in the v2027 namespace, not in the v2026 run",
}

# Known defects open in the current library, by assertion. None as of 2.0.0:
# the three the library review could not fix by addition were corrected by the
# re-issue (policies/CHANGELOG.md).
OPEN_DEFECTS: dict = {}
FIXED_DEFECTS = {
    "1.1-A14": "unsatisfiable in 1.0.0 (tag on an untaggable type); corrected",
    "2.1-A16": "unsatisfiable in 1.0.0 (tag on an untaggable type); corrected",
    "5.1-A11": "unsatisfiable in 1.0.0 (tag on an untaggable type); corrected",
    "4.2-A4": "SAML branch read a block the provider does not define; corrected",
    "1.1-A12": "accepted a policy that disables MFA; corrected",
    "2.1-A12": "compared aws:SecureTransport to the string only, misreading a JSON "
               "boolean; corrected in 2.0.0",
    "1.1-A13": "flagged a service role whose trust policy was unreadable; corrected in 2.0.0",
    "1.1-A6": "contains(gateway_id, id) matched every route when an id was empty; "
              "corrected in 2.0.0",
}
SCOPE_CORRECTION = "declared scope not applied in 1.0.0 (evaluated account-wide); implemented in 2.0.0"


# ============================================================================
# Rules
# ============================================================================

def scan_rules() -> list[dict]:
    """Every deny rule, with the assertion it reports and where it lives."""
    rules = []
    sys.path.insert(0, str(P2 / "pipeline" / "audit"))
    import scope_audit  # noqa: E402  (reuse its definition of a scope predicate)

    for root in (P2 / "policies",):
        for path in sorted(root.rglob("*.rego")):
            text = path.read_text(encoding="utf-8")
            if "deny contains msg if" not in text:
                continue
            version = path.parent.name
            package = re.search(r"^package\s+(\S+)", text, re.M).group(1)
            local_predicates = scope_audit.tag_reading_helpers(text)
            lines = text.split("\n")
            ordinal = 0
            declared_scope = None
            for number, line in enumerate(lines, start=1):
                scope = SCOPE_HEADER.match(line)
                if scope:
                    declared_scope = scope.group(1).strip()
                if not line.startswith("deny contains msg if"):
                    continue
                ordinal += 1
                body = "\n".join(lines[number:number + 80]).split("\n}")[0]
                assertion = ASSERTION_IN_MESSAGE.search(body)
                assertion = assertion.group(1) if assertion else "?"
                control = assertion.split("-")[0]
                phase = "Phase I" if control in PHASE1_CONTROLS else "Phase II"
                role = "rule"
                if version == "v2027":
                    role = "v2027 delta"
                    phase = "Phase II"
                rules.append(
                    {
                        "rule_id": f"{path.name}#{ordinal}",
                        "file": str(path.relative_to(ROOT)).replace("\\", "/"),
                        "line": number,
                        "package": package,
                        "phase": phase,
                        "cscf_version": version,
                        "assertion": assertion,
                        "role": role,
                        "declared_scope": declared_scope or "",
                        "scope_applied": (
                            any(p in body for p in scope_audit.SHARED_PREDICATES)
                            or any(c in local_predicates for c in scope_audit.HELPER_CALL.findall(body))
                        ),
                    }
                )
    return rules


def assertion_titles() -> dict:
    """Assertion id -> short title, from the rule headers."""
    titles = {}
    for root in (P2 / "policies",):
        for path in root.rglob("*.rego"):
            for line in path.read_text(encoding="utf-8").split("\n"):
                m = ASSERTION_HEADER.match(line)
                if m and m.group(1) not in titles:
                    titles[m.group(1)] = m.group(2).strip()
    return titles


# ============================================================================
# Registers
# ============================================================================

def markdown_table(text: str, header_prefix: str) -> list[dict]:
    """Rows of the first markdown table whose header starts with header_prefix."""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.startswith(header_prefix):
            headers = [h.strip() for h in line.strip().strip("|").split("|")]
            rows = []
            for row in lines[i + 2:]:
                if not row.startswith("|"):
                    break
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                rows.append(dict(zip(headers, cells)))
            return rows
    return []


def expand_sources(text: str, control: str) -> list[str]:
    """Requirement references in a cell, normalised to full ids.

    'S1, S3' -> ['1.4-S1', '1.4-S3'];  '1.4-S10, S11' -> ['1.4-S10', '1.4-S11'].
    The registers also use non-numeric ids for optional enhancements and
    advisory items ('1.2-OE', '2.4-legacy') and lettered splits ('1.3-S5a');
    those are requirements too and must be traced like the rest.
    """
    out = []
    for full in re.findall(r"\d+\.\d+-(?:S\d+[a-z]?|OE|legacy)\b", text):
        if full not in out:
            out.append(full)
    for bare in re.findall(r"(?<![\w.\-])S(\d+[a-z]?)\b", text):
        ref = f"{control}-S{bare}"
        if ref not in out:
            out.append(ref)
    return out


def clean(cell: str) -> str:
    return re.sub(r"[*`]", "", cell or "").strip()


def phase2_registers() -> tuple[dict, list, list]:
    assertions, exclusions, requirements = {}, [], []
    for path in sorted((P2 / "translations").glob("ctrl_*_translation.md")):
        text = path.read_text(encoding="utf-8")
        control = re.search(r"ctrl_(\d)_(\d)_", path.name)
        control = f"{control.group(1)}.{control.group(2)}"

        statements = {
            r["ID"]: clean(r.get("Assertion (compliant state)", ""))
            for r in markdown_table(text, "| ID | Assertion")
        }
        for row in markdown_table(text, "| Assertion |"):
            aid = clean(row["Assertion"])
            if not re.match(r"\d+\.\d+-A\d+$", aid):
                continue
            src = row.get("Src ref(s)", row.get("Src", ""))
            assertions[aid] = {
                "control": control,
                "statement": statements.get(aid, ""),
                "sources": expand_sources(src, control),
                "cscf_section": clean(row.get("CSCF §", "")),
                "terraform_resource": clean(row.get("Terraform resource", "")),
                "scope_type": clean(row.get("Scope type", "")),
                "scope_level": clean(row.get("Scope level", "")),
                "variant": clean(row.get("Variant", "")),
                "coverage": clean(row.get("Coverage", "")),
                "register": str(path.relative_to(ROOT)).replace("\\", "/"),
            }

        for row in markdown_table(text, "| ID | Source"):
            rid = clean(row["ID"])
            source_col = next(k for k in row if k.startswith("Source"))
            requirements.append(
                {
                    "requirement": rid,
                    "control": control,
                    "text": clean(row[source_col]),
                    "cscf_section": clean(row.get("CSCF §", "")),
                }
            )

        for n, row in enumerate(markdown_table(text, "| Source | Category"), start=1):
            exclusions.append(
                {
                    "ref": f"{control}-X{n}",
                    "control": control,
                    "source": clean(row["Source"]),
                    "sources": expand_sources(row["Source"], control),
                    "category": clean(row["Category"]),
                    "rationale": clean(row["Rationale"]),
                    "partial_coverage": clean(row.get("Partial coverage", "")),
                }
            )
    return assertions, exclusions, requirements


def phase1_registers(write_snapshot: bool = False) -> tuple[dict, list]:
    """Phase I assertions and exclusions, from their JSON snapshot.

    The snapshot was taken from the Phase I research spreadsheet, which is not
    published; the snapshot is the source of record here. ``write_snapshot`` is
    accepted for compatibility and ignored.
    """
    data = json.loads(PHASE1_SNAPSHOT.read_text(encoding="utf-8"))
    return data["assertions"], data["exclusions"]


# ============================================================================
# Verdicts on the generated environments
# ============================================================================

def live_verdicts() -> dict:
    evidence = json.loads(
        (P2 / "plans" / "non_compliant_resolved_evidence.json").read_text(encoding="utf-8")
    )
    fired = {}
    for control in evidence["controls"]:
        for violation in control["violations"]:
            m = ASSERTION_IN_MESSAGE.search(violation)
            if m:
                fired[m.group(1)] = fired.get(m.group(1), 0) + 1
    undetermined = {u["assertion"] for u in evidence.get("undetermined", [])}
    return {"fired": fired, "undetermined": undetermined}


# ============================================================================
# Join
# ============================================================================

def build(write_snapshot: bool = False) -> dict:
    rules = scan_rules()
    titles = assertion_titles()
    p1_assertions, p1_exclusions = phase1_registers(write_snapshot)
    p2_assertions, p2_exclusions, p2_requirements = phase2_registers()
    verdicts = live_verdicts()

    register = {**p1_assertions, **p2_assertions}
    register.setdefault(
        "4.1-A20",
        {
            "control": "4.1",
            "statement": "Failed authentication attempts are logged and alarmed at a threshold of 5 or fewer.",
            "sources": [],
            "cscf_section": "v2027 lock-out / failed-authentication alerting",
            "terraform_resource": "aws_cloudwatch_log_metric_filter, aws_cloudwatch_metric_alarm",
            "scope_type": "PRESENCE",
            "scope_level": "ACCT",
            "variant": "B",
            "coverage": "Partial",
            "register": "v2026_to_v2027_delta.md",
        },
    )
    register.setdefault(
        "1.1-A15",
        {
            "control": "1.1",
            "statement": "A bucket in the secure zone grants access only to accounts "
                         "inside the declared Swift trust boundary.",
            # The same Boundary Protection sub-requirements as 1.1-A2.
            "sources": list(register.get("1.1-A2", {}).get("sources", [])),
            "cscf_section": "c) Boundary Protection",
            "terraform_resource": "aws_s3_bucket_policy (scope via aws_s3_bucket)",
            "scope_type": "RELATIONAL",
            "scope_level": "TAG",
            "variant": "E",
            "coverage": "Partial",
            "register": "translations/1_1_a15_trust_boundary.md",
        },
    )

    by_assertion = {}
    for rule in rules:
        by_assertion.setdefault(rule["assertion"], []).append(rule)

    sys.path.insert(0, str(P2 / "pipeline" / "audit"))
    import scope_audit  # noqa: E402

    scope_corrected = {aid for _, aid in scope_audit.PHASE1_MISMATCHES}
    rows = []
    for aid in sorted(register, key=lambda a: [int(x) for x in re.findall(r"\d+", a)]):
        entry = register[aid]
        realised = by_assertion.get(aid, [])
        scoped = [r["scope_applied"] for r in realised if r["scope_applied"] is not None]

        if aid in verdicts["fired"]:
            verdict = f"fires ({verdicts['fired'][aid]} instance(s))"
        elif aid in verdicts["undetermined"]:
            verdict = "undetermined (value unknown at plan time)"
        elif aid in EXPLAINED:
            verdict = "not fired: " + EXPLAINED[aid]
        else:
            verdict = "SILENT"  # must never occur; the suite asserts it

        declared = entry.get("scope_level", "")
        if declared in ("TAG", "VPC", "MODULE"):
            scope_status = (
                "implemented" if scoped and all(scoped)
                else "partly implemented" if any(scoped)
                else "not implemented"
            )
        else:
            scope_status = "n/a (account or cross-reference scope)"

        rows.append(
            {
                "assertion": aid,
                "control": entry["control"],
                "control_name": CONTROL_NAMES.get(entry["control"], ""),
                "phase": "2.1.0 addition" if aid in ADDED_IN_2_1_0 else (
                    "Phase I" if entry["control"] in PHASE1_CONTROLS and aid != "4.1-A20" else (
                        "v2027 delta" if aid == "4.1-A20" else "Phase II"
                    )
                ),
                "title": titles.get(aid, ""),
                "statement": entry.get("statement", ""),
                "sources": entry.get("sources", []),
                "cscf_section": entry.get("cscf_section", ""),
                "terraform_resource": entry.get("terraform_resource", ""),
                "scope_type": entry.get("scope_type", ""),
                "scope_level": declared,
                "scope_status": scope_status,
                "variant": entry.get("variant", ""),
                "coverage": entry.get("coverage", ""),
                "rules": [r["rule_id"] for r in realised],
                "live_verdict": verdict,
                "defect": "; ".join(
                    note for note in (
                        OPEN_DEFECTS.get(aid, FIXED_DEFECTS.get(aid, "")),
                        SCOPE_CORRECTION if aid in scope_corrected else "",
                    ) if note
                ),
                "register": entry.get("register", ""),
            }
        )

    # Backward: requirement -> assertions and exclusions.
    covered = {}
    for row in rows:
        for ref in row["sources"]:
            covered.setdefault(ref, []).append(row["assertion"])
    excluded = {}
    for ex in p1_exclusions + p2_exclusions:
        for ref in ex["sources"]:
            excluded.setdefault(ref, []).append(f"{ex['ref']} ({ex['category']})")

    requirements = []
    listed = {r["requirement"] for r in p2_requirements}
    for req in p2_requirements:
        ref = req["requirement"]
        requirements.append(
            {
                **req,
                "assertions": covered.get(ref, []),
                "exclusions": excluded.get(ref, []),
                "disposition": (
                    "covered and partly excluded" if covered.get(ref) and excluded.get(ref)
                    else "covered" if covered.get(ref)
                    else "excluded" if excluded.get(ref)
                    else "UNTRACED"
                ),
            }
        )
    # Phase I kept no separate requirement register; its sub-requirements
    # survive only as the source references on its assertions.
    for ref in sorted(set(covered) - listed, key=lambda r: [int(x) for x in re.findall(r"\d+", r)]):
        requirements.append(
            {
                "requirement": ref,
                "control": ref.split("-")[0],
                "text": "(Phase I: source text not retained as a register)",
                "cscf_section": "",
                "assertions": covered[ref],
                "exclusions": excluded.get(ref, []),
                "disposition": "covered",
            }
        )

    summary = []
    for control in CONTROL_NAMES:
        mine = [r for r in rows if r["control"] == control]
        summary.append(
            {
                "control": control,
                "name": CONTROL_NAMES[control],
                "phase": "Phase I" if control in PHASE1_CONTROLS else "Phase II",
                "assertions": len(mine),
                "rules": sum(len(r["rules"]) for r in mine),
                "exclusions": sum(1 for e in p1_exclusions + p2_exclusions if e["control"] == control),
                "fire_live": sum(1 for r in mine if r["live_verdict"].startswith("fires")),
                "undetermined_live": sum(1 for r in mine if r["live_verdict"].startswith("undetermined")),
                "explained_live": sum(1 for r in mine if r["live_verdict"].startswith("not fired")),
                "silent_live": sum(1 for r in mine if r["live_verdict"] == "SILENT"),
                "scope_not_implemented": sum(1 for r in mine if r["scope_status"].startswith("not")),
                "open_defects": sum(1 for r in mine if r["assertion"] in OPEN_DEFECTS),
            }
        )

    return {
        "schema": "swift-cscf-traceability/v1",
        "library_version": LIBRARY_VERSION,
        "assertions": rows,
        "rules": rules,
        "requirements": requirements,
        "exclusions": p1_exclusions + p2_exclusions,
        "summary": summary,
    }


# ============================================================================
# Output
# ============================================================================

def write_json_and_csv(matrix: dict) -> None:
    (OUT / "traceability.json").write_text(
        json.dumps(matrix, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    with (OUT / "traceability.csv").open("w", newline="", encoding="utf-8") as fh:
        columns = [
            "assertion", "control", "phase", "title", "sources", "cscf_section",
            "terraform_resource", "scope_level", "scope_status", "variant", "coverage",
            "rules", "live_verdict", "defect",
        ]
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in matrix["assertions"]:
            writer.writerow(
                {**row, "sources": ", ".join(row["sources"]), "rules": ", ".join(row["rules"])}
            )


def write_xlsx(matrix: dict, path: Path) -> None:
    import openpyxl
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()
    header_fill = PatternFill("solid", fgColor="0B3D6B")
    header_font = Font(bold=True, color="FFFFFF")
    wrap = Alignment(wrap_text=True, vertical="top")
    flags = {
        "SILENT": PatternFill("solid", fgColor="F4CCCC"),
        "undetermined": PatternFill("solid", fgColor="FDF3E0"),
        "not implemented": PatternFill("solid", fgColor="FDF3E0"),
    }

    def sheet(title, intro, columns, records, widths):
        ws = wb.create_sheet(title)
        ws.append([intro])
        ws["A1"].font = Font(bold=True, size=12)
        ws.append([])
        ws.append([c[0] for c in columns])
        for cell in ws[3]:
            cell.fill, cell.font, cell.alignment = header_fill, header_font, wrap
        for record in records:
            values = []
            for _, key in columns:
                value = record.get(key, "")
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                values.append(value)
            ws.append(values)
            for cell in ws[ws.max_row]:
                cell.alignment = wrap
                text = str(cell.value or "")
                for marker, fill in flags.items():
                    if text.startswith(marker):
                        cell.fill = fill
        for i, width in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(i)].width = width
        ws.freeze_panes = "B4"
        return ws

    wb.remove(wb.active)
    sheet(
        "Summary",
        f"SWIFT CSCF traceability: 15 controls, policy library {LIBRARY_VERSION}, "
        "generated from the library (build_matrix.py)",
        [("Control", "control"), ("Name", "name"), ("Phase", "phase"), ("Assertions", "assertions"),
         ("Rules", "rules"),
         ("Exclusions", "exclusions"), ("Fire on generated plan", "fire_live"),
         ("Undetermined", "undetermined_live"), ("Explained", "explained_live"),
         ("Silent", "silent_live"), ("Scope not implemented", "scope_not_implemented"),
         ("Open defects", "open_defects")],
        matrix["summary"],
        [9, 42, 10, 11, 9, 11, 12, 13, 10, 8, 12, 11],
    )
    sheet(
        "Assertions (forward)",
        "Requirement -> assertion -> rules -> verdict. Every assertion either fires on the generated "
        "non-compliant plan, is measured undetermined, or carries a stated reason.",
        [("Assertion", "assertion"), ("Control", "control"), ("Phase", "phase"), ("Title", "title"),
         ("Statement (Phase II)", "statement"), ("Source requirements", "sources"),
         ("CSCF §", "cscf_section"), ("Terraform resource", "terraform_resource"),
         ("Scope level", "scope_level"), ("Scope implemented", "scope_status"),
         ("Variant", "variant"), ("Coverage", "coverage"), ("Rules", "rules"),
         ("Verdict on generated non-compliant plan", "live_verdict"),
         ("Defect / correction", "defect"), ("Register", "register")],
        matrix["assertions"],
        [11, 8, 10, 34, 40, 18, 14, 30, 9, 24, 8, 18, 30, 34, 44, 36],
    )
    sheet(
        "Rules (backward)",
        "Rule -> assertion. Every deny rule in the library reports exactly one assertion.",
        [("Rule", "rule_id"), ("File", "file"), ("Line", "line"), ("Package", "package"),
         ("Phase", "phase"), ("CSCF version", "cscf_version"), ("Assertion", "assertion"),
         ("Role", "role"), ("Declared scope", "declared_scope"), ("Scope applied", "scope_applied")],
        matrix["rules"],
        [30, 58, 7, 30, 10, 9, 11, 50, 26, 10],
    )
    sheet(
        "Requirements",
        "CSCF sub-requirement -> assertions and exclusions. Phase I kept no separate requirement "
        "register, so its requirements appear only through their assertions.",
        [("Requirement", "requirement"), ("Control", "control"), ("Text", "text"),
         ("CSCF §", "cscf_section"), ("Assertions", "assertions"), ("Exclusions", "exclusions"),
         ("Disposition", "disposition")],
        matrix["requirements"],
        [12, 8, 70, 16, 24, 30, 22],
    )
    sheet(
        "Exclusions",
        "Requirements not decidable from a deployment plan, with category and rationale.",
        [("Ref", "ref"), ("Control", "control"), ("Source", "source"), ("Category", "category"),
         ("Rationale", "rationale"), ("Partial coverage", "partial_coverage")],
        matrix["exclusions"],
        [10, 8, 34, 14, 70, 34],
    )
    wb.save(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--xlsx", action="store_true", help="also write the spreadsheet")
    args = parser.parse_args()

    matrix = build()
    write_json_and_csv(matrix)
    if args.xlsx:
        write_xlsx(matrix, OUT / "CSCF_Traceability_Matrix.xlsx")

    totals = {k: sum(c[k] for c in matrix["summary"]) for k in
              ("assertions", "rules", "exclusions", "fire_live", "undetermined_live",
               "explained_live", "silent_live", "scope_not_implemented")}
    untraced = [r["requirement"] for r in matrix["requirements"] if r["disposition"] == "UNTRACED"]
    print(json.dumps(totals, indent=2))
    print(f"requirements: {len(matrix['requirements'])}  untraced: {untraced or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
