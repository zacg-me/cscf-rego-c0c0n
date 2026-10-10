#!/usr/bin/env python3
"""
SWIFT CSCF v2026 -- Attestation Report Generator

Turns the structured evidence JSON emitted by ``pipeline/gate.py`` into a
self-contained, human-readable HTML attestation report suitable for review by an
independent SWIFT CSP assessor. The report is deterministic: the same evidence
JSON always renders the same document, and it carries the plan SHA-256, the OPA
version, and the generation timestamp so a reader can tie the attestation back to
the exact Terraform plan and tooling that produced it.

This closes the loop for attestation evidence: the gate produces
machine-readable evidence, and this tool renders the assessor-facing artefact.

Usage:
    python report.py --evidence <evidence.json> --out <report.html>
    python report.py --evidence samples/non_compliant_evidence.json \
                     --out samples/non_compliant_report.html
"""
from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import re
import sys
from pathlib import Path

PIPELINE = Path(__file__).resolve().parents[1] / "pipeline"
DEFAULT_PUBLIC_KEY = Path(__file__).resolve().parents[1] / "keys" / "evidence_signing_public.pem"


def signature_status(evidence: dict, public_key_path: Path | None) -> tuple[str, str]:
    """('valid' | 'invalid' | 'unsigned' | 'unchecked', detail) for the attestation."""
    if not evidence.get("signature"):
        return "unsigned", "This evidence carries no signature."
    if public_key_path is None or not public_key_path.exists():
        return "unchecked", "Signed, but no public key was available to check it against."
    try:
        sys.path.insert(0, str(PIPELINE))
        import evidence_signing
    except ImportError:
        return "unchecked", "Signed, but the verification library is not installed."
    key = evidence_signing.load_public_key(public_key_path.read_bytes())
    return evidence_signing.verify(evidence, key)

# Human-readable titles for the five controls in scope (from CSCF v2026).
CONTROL_TITLES = {
    "1.1": "SWIFT Environment Protection",
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

# Violation message shape emitted by the Rego library:
#   CSCF {control} [{assertion_id}]: {description} (resource: {address})
_VIOLATION_RE = re.compile(
    r"^CSCF\s+(?P<control>\S+)\s+\[(?P<assertion>[^\]]+)\]:\s+"
    r"(?P<message>.*?)\s*(?:\(resource:\s*(?P<resource>[^)]+)\))?\s*$"
)


def parse_violation(raw: str) -> dict:
    """Split a raw deny message into assertion id, message body, and resource."""
    m = _VIOLATION_RE.match(raw)
    if not m:
        return {"assertion": "", "message": raw, "resource": ""}
    return {
        "assertion": m.group("assertion") or "",
        "message": (m.group("message") or "").strip(),
        "resource": (m.group("resource") or "").strip(),
    }


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _fmt_timestamp(iso: str) -> str:
    try:
        dt = _dt.datetime.fromisoformat(iso)
        return dt.strftime("%d %b %Y, %H:%M:%S %Z").strip() or iso
    except (ValueError, TypeError):
        return iso


def _signature_line(evidence: dict, public_key_path: Path | None) -> str:
    status, detail = signature_status(evidence, public_key_path)
    label = {
        "valid": "VALID",
        "invalid": "INVALID -- do not rely on this evidence",
        "unsigned": "UNSIGNED",
        "unchecked": "NOT CHECKED",
    }[status]
    return f"{label}. {detail}"


def _library_line(evidence: dict) -> str:
    """The policy library that produced this evidence (absent before 2.0.0)."""
    library = evidence.get("library")
    if not library:
        return "not recorded (evidence predates library versioning)"
    return f"{library.get('version', '')}  ({library.get('digest', '')})"


# Why a check could not be evaluated, by the `kind` the gate records.
UNDETERMINED_CAUSES = {
    "unresolved-value": "value unknown until apply",
    "unresolved-scope": "scope comes from a parent not in this plan",
    "incomplete-plan": "absence not decidable from an incremental plan",
    "unbound-environment": "environment binding not supplied",
}


def render_html(evidence: dict, public_key_path: Path | None = DEFAULT_PUBLIC_KEY) -> str:
    summary = evidence.get("summary", {})
    result = summary.get("result", "UNKNOWN")
    passed = result == "PASS"
    undetermined = evidence.get("undetermined", []) or []
    has_exceptions = "exceptions" in evidence
    excepted = [
        (c.get("control", ""), e)
        for c in evidence.get("controls", [])
        for e in (c.get("excepted") or [])
    ]
    risks = f"{len(excepted)} ACCEPTED RISK{'' if len(excepted) == 1 else 'S'}"
    if not passed:
        verdict_class, verdict_text = "fail", "NON-COMPLIANT"
    elif excepted:
        # An accepted risk must never look like a clean pass, nor be called compliant.
        verdict_class = "warn"
        verdict_text = f"PASS WITH {risks}" + (
            ", WITH UNDETERMINED CHECKS" if undetermined else ""
        )
    elif undetermined:
        verdict_class = "warn"
        verdict_text = "COMPLIANT, WITH UNDETERMINED CHECKS"
    else:
        verdict_class, verdict_text = "pass", "COMPLIANT"
    generated = _fmt_timestamp(evidence.get("generated_at", ""))
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")

    meta_rows = [
        ("CSCF version", evidence.get("cscf_version", "")),
        ("Terraform plan", evidence.get("plan_file", "")),
        ("Plan SHA-256", evidence.get("plan_sha256", "")),
        ("OPA engine", evidence.get("opa_version", "")),
        ("Policy library", _library_line(evidence)),
        ("Evidence schema", evidence.get("schema", "")),
        ("Signature", _signature_line(evidence, public_key_path)),
        ("Plan evaluated at", generated),
        ("Report rendered at", now),
    ]
    meta_html = "\n".join(
        f"      <tr><th>{_esc(k)}</th><td class='mono'>{_esc(v)}</td></tr>"
        for k, v in meta_rows
    )

    # Per-control summary table.
    control_rows = []
    for c in evidence.get("controls", []):
        num = c.get("control", "")
        title = CONTROL_TITLES.get(num, "")
        instances = c.get("violation_instances", 0)
        distinct = c.get("rules_fired", 0)
        cpass = instances == 0
        cundetermined = sum(1 for u in undetermined if u.get("control") == num)
        cexcepted = len(c.get("excepted") or [])
        if not cpass:
            badge, badge_class = "FAIL", "fail"
        elif cexcepted:
            badge, badge_class = "EXCEPTED", "warn"
        elif cundetermined:
            badge, badge_class = "UNDETERMINED", "warn"
        else:
            badge, badge_class = "PASS", "pass"
        excepted_cell = (
            f"<td class='num'>{cexcepted or ''}</td>" if has_exceptions else ""
        )
        control_rows.append(
            f"      <tr>"
            f"<td class='mono'>{_esc(num)}</td>"
            f"<td>{_esc(title)}</td>"
            f"<td class='num'>{instances}</td>"
            f"<td class='num'>{distinct}</td>"
            f"<td class='num'>{cundetermined or ''}</td>"
            f"{excepted_cell}"
            f"<td><span class='badge {badge_class}'>{badge}</span></td>"
            f"</tr>"
        )
    control_html = "\n".join(control_rows)

    # Detailed findings, grouped by control (only for failing controls).
    detail_sections = []
    for c in evidence.get("controls", []):
        violations = c.get("violations", [])
        if not violations:
            continue
        num = c.get("control", "")
        title = CONTROL_TITLES.get(num, "")
        rows = []
        for raw in violations:
            p = parse_violation(raw)
            rows.append(
                f"          <tr>"
                f"<td class='mono nowrap'>{_esc(p['assertion'])}</td>"
                f"<td>{_esc(p['message'])}</td>"
                f"<td class='mono'>{_esc(p['resource'])}</td>"
                f"</tr>"
            )
        detail_sections.append(
            f"""    <section class="control-detail">
      <h3>Control {_esc(num)}: {_esc(title)}
        <span class="count">{len(violations)} finding(s)</span></h3>
      <table class="findings">
        <thead><tr><th>Assertion</th><th>Finding</th><th>Resource</th></tr></thead>
        <tbody>
{chr(10).join(rows)}
        </tbody>
      </table>
    </section>"""
        )
    if detail_sections:
        detail_html = "\n".join(detail_sections)
    elif excepted:
        detail_html = (
            "    <section class='control-detail'><p>"
            f"No unaccepted control violations. {len(excepted)} finding(s) are accepted "
            "risks under approved exceptions, listed under Accepted Risks (Exceptions) "
            "below; they are not attested as compliant.</p></section>"
        )
    else:
        detail_html = (
            "    <section class='control-detail'><p class='clean'>"
            "No control violations were detected. All assertions across the five "
            "controls in scope evaluated to compliant.</p></section>"
        )

    if not passed:
        banner_detail = (
            f"{summary.get('total_violation_instances', 0)} violation instance(s) "
            f"across {summary.get('controls_with_violations', 0)} control(s). "
            "Deployment is blocked."
        )
    elif excepted:
        banner_detail = (
            f"No unaccepted CSCF control violations. {len(excepted)} finding(s) are "
            "accepted risks under approved exceptions, listed below with their owner and "
            "expiry. They are not attested as compliant."
            + (
                f" {len(undetermined)} check(s) are undetermined and require "
                "post-deployment verification."
                if undetermined
                else ""
            )
        )
    elif undetermined:
        banner_detail = (
            "No CSCF control violations detected, but "
            f"{len(undetermined)} check(s) could not be evaluated before deployment "
            "and are reported as undetermined below. They are not attested as "
            "compliant and require post-deployment verification."
        )
    else:
        banner_detail = (
            "No CSCF control violations detected. The plan may proceed to deployment."
        )

    # Undetermined checks: a value the plan does not yet know, so the assertion
    # has no verdict. Reported separately so a pass is never claimed for it.
    if undetermined:
        rows = "\n".join(
            f"          <tr>"
            f"<td class='mono nowrap'>{_esc(u.get('assertion',''))}</td>"
            f"<td class='mono'>{_esc(u.get('control',''))}</td>"
            f"<td class='mono'>{_esc(u.get('resource',''))}</td>"
            f"<td class='mono'>{_esc(u.get('attribute',''))}</td>"
            f"<td>{_esc(UNDETERMINED_CAUSES.get(u.get('kind', ''), u.get('reason', '')))}"
            f"{(': ' + _esc(u['parent'])) if u.get('parent') else ''}</td>"
            f"</tr>"
            for u in undetermined
        )
        undetermined_html = f"""  <h2>Undetermined Checks</h2>
    <section class="control-detail">
      <p>The following assertions could not be evaluated against this plan: the
      plan neither satisfies nor violates them. The cause is given for each, a
      value Terraform does not resolve until apply, a resource whose scope comes
      from a parent the plan does not contain, or an absence that a plan
      describing only a change cannot decide. They are recorded here as
      <strong>undetermined</strong>: an assessor must verify them against the
      deployed environment. Treating them as passes would overstate what a
      pre-deployment gate can attest.</p>
      <table class="findings">
        <thead><tr><th>Assertion</th><th>Control</th><th>Resource</th>
          <th>Unresolved attribute</th><th>Cause</th></tr></thead>
        <tbody>
{rows}
        </tbody>
      </table>
    </section>"""
    else:
        undetermined_html = ""

    # Accepted risks: findings the gate detected and an approved exception covers.
    if has_exceptions:
        block = evidence["exceptions"]
        risk_rows = "\n".join(
            f"          <tr>"
            f"<td class='mono'>{_esc(num)}</td>"
            f"<td class='mono nowrap'>{_esc(e['exception'].get('assertion', ''))}</td>"
            f"<td>{_esc(parse_violation(e['finding'])['message'])}</td>"
            f"<td class='mono'>{_esc(e['exception'].get('resource', ''))}</td>"
            f"<td class='mono'>{_esc(e['exception'].get('id', ''))}</td>"
            f"<td>{_esc(e['exception'].get('risk_owner', ''))}</td>"
            f"<td>{_esc(e['exception'].get('approved_by', ''))}</td>"
            f"<td class='mono'>{_esc(e['exception'].get('ticket', ''))}</td>"
            f"<td class='mono nowrap'>{_esc(e['exception'].get('expires_on', ''))}</td>"
            f"</tr>"
            for num, e in excepted
        )
        expired_items = "".join(
            f"<li class='mono'>{_esc(x['id'])} expired {_esc(x['expired_on'])}: "
            f"{_esc(x['findings'])} finding(s) counted as violations</li>"
            for x in block.get("expired", [])
        )
        unused_items = "".join(
            f"<li class='mono'>{_esc(rid)} matched no finding</li>"
            for rid in block.get("unused", [])
        )
        risks_table = (
            f"""      <table class="findings">
        <thead><tr><th>Control</th><th>Assertion</th><th>Finding</th><th>Resource</th>
          <th>Exception</th><th>Risk owner</th><th>Approved by</th><th>Ticket</th>
          <th>Expires</th></tr></thead>
        <tbody>
{risk_rows}
        </tbody>
      </table>"""
            if excepted
            else "      <p>No finding was covered by an exception in this run.</p>"
        )
        exceptions_html = f"""  <h2>Accepted Risks (Exceptions)</h2>
    <section class="control-detail">
      <p>These findings were detected and are covered by an approved exception: a
      risk acceptance for one assertion on one resource, with an owner, an approver
      and an expiry. They are <strong>excepted, not passed</strong>. Exceptions file
      <span class="mono">{_esc(block.get('file', ''))}</span>, SHA-256
      <span class="mono">{_esc(block.get('sha256', ''))}</span>, evaluated on
      {_esc(block.get('evaluated_on', ''))}.</p>
{risks_table}
      {f"<p>Expired exceptions (no longer applied):</p><ul>{expired_items}</ul>" if expired_items else ""}
      {f"<p>Unused exceptions:</p><ul>{unused_items}</ul>" if unused_items else ""}
    </section>"""
    else:
        exceptions_html = ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CSCF v2026 Compliance Attestation: {_esc(evidence.get('plan_file',''))}</title>
<style>
  :root {{
    --ink:#1a1f29; --muted:#5b6472; --line:#dfe3ea; --bg:#f6f7f9;
    --pass:#1a7f4b; --pass-bg:#e7f5ec; --fail:#b3261e; --fail-bg:#fbeceb;
    --warn:#8a5a00; --warn-bg:#fdf3e0;
    --accent:#0b3d6b;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  .page {{ max-width:960px; margin:24px auto; background:#fff; padding:40px 48px;
    border:1px solid var(--line); border-radius:8px; }}
  header.doc {{ border-bottom:3px solid var(--accent); padding-bottom:16px; margin-bottom:24px; }}
  header.doc .eyebrow {{ color:var(--accent); font-weight:700; letter-spacing:.08em;
    text-transform:uppercase; font-size:11px; }}
  header.doc h1 {{ margin:6px 0 2px; font-size:22px; }}
  header.doc .sub {{ color:var(--muted); font-size:13px; }}
  .verdict {{ display:flex; align-items:center; gap:16px; padding:16px 20px;
    border-radius:8px; margin:24px 0; }}
  .verdict.pass {{ background:var(--pass-bg); border:1px solid var(--pass); }}
  .verdict.fail {{ background:var(--fail-bg); border:1px solid var(--fail); }}
  .verdict.warn {{ background:var(--warn-bg); border:1px solid var(--warn); }}
  .verdict.warn .tag {{ color:var(--warn); }}
  .verdict .tag {{ font-size:20px; font-weight:800; letter-spacing:.02em; }}
  .verdict.pass .tag {{ color:var(--pass); }}
  .verdict.fail .tag {{ color:var(--fail); }}
  .verdict .detail {{ color:var(--ink); font-size:13px; }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.05em;
    color:var(--accent); border-bottom:1px solid var(--line); padding-bottom:6px;
    margin:32px 0 12px; }}
  table {{ border-collapse:collapse; width:100%; font-size:13px; }}
  .meta th {{ text-align:left; color:var(--muted); font-weight:600; width:180px;
    padding:5px 12px 5px 0; vertical-align:top; }}
  .meta td {{ padding:5px 0; }}
  table.grid th, table.grid td {{ border:1px solid var(--line); padding:8px 10px; text-align:left; }}
  table.grid thead th {{ background:#f0f2f5; font-size:12px; text-transform:uppercase;
    letter-spacing:.03em; color:var(--muted); }}
  td.num, th.num {{ text-align:right; width:90px; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:20px; font-size:11px;
    font-weight:700; }}
  .badge.pass {{ background:var(--pass-bg); color:var(--pass); }}
  .badge.fail {{ background:var(--fail-bg); color:var(--fail); }}
  .badge.warn {{ background:var(--warn-bg); color:var(--warn); }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; }}
  .nowrap {{ white-space:nowrap; }}
  .control-detail {{ margin:20px 0; }}
  .control-detail h3 {{ font-size:14px; margin:18px 0 8px; }}
  .control-detail h3 .count {{ color:var(--fail); font-weight:600; font-size:12px; margin-left:8px; }}
  table.findings th, table.findings td {{ border:1px solid var(--line); padding:7px 9px;
    vertical-align:top; font-size:12.5px; }}
  table.findings thead th {{ background:#f0f2f5; text-transform:uppercase; font-size:11px;
    color:var(--muted); }}
  .clean {{ color:var(--pass); font-weight:600; }}
  footer.doc {{ margin-top:36px; padding-top:16px; border-top:1px solid var(--line);
    color:var(--muted); font-size:11.5px; }}
  @media print {{ body {{ background:#fff; }} .page {{ border:none; margin:0; max-width:none; }} }}
</style>
</head>
<body>
<div class="page">
  <header class="doc">
    <div class="eyebrow">Pre-Deployment Compliance Attestation</div>
    <h1>SWIFT CSCF {_esc(evidence.get('cscf_version',''))}: Terraform Plan Evaluation</h1>
    <div class="sub">Automated Policy-as-Code assessment with Open Policy Agent (Rego).
      Plan: <span class="mono">{_esc(evidence.get('plan_file',''))}</span></div>
  </header>

  <div class="verdict {verdict_class}">
    <div class="tag">{verdict_text}</div>
    <div class="detail">{_esc(banner_detail)}</div>
  </div>

  <h2>Attestation Metadata</h2>
  <table class="meta">
    <tbody>
{meta_html}
    </tbody>
  </table>

  <h2>Control Summary</h2>
  <table class="grid">
    <thead>
      <tr><th>Control</th><th>Title</th><th class="num">Violations</th>
        <th class="num">Distinct assertions</th><th class="num">Undetermined</th>{'<th class="num">Excepted</th>' if has_exceptions else ''}
        <th>Result</th></tr>
    </thead>
    <tbody>
{control_html}
    </tbody>
  </table>
  <p style="color:var(--muted);font-size:12px;margin-top:10px;">
    Totals: {summary.get('total_violation_instances', 0)} violation instance(s),
    {summary.get('distinct_assertions_fired', 0)} distinct assertion(s) fired across
    {summary.get('controls_with_violations', 0)} control(s) with findings;
    {summary.get('undetermined_instances', 0)} check(s) undetermined.{f" {summary.get('excepted_instances', 0)} finding(s) excepted as accepted risks." if has_exceptions else ''}
  </p>

  <h2>Detailed Findings</h2>
{detail_html}

{undetermined_html}
{exceptions_html}

  <footer class="doc">
    <p><strong>Integrity.</strong> This attestation was rendered from a
    machine-generated evidence artefact (schema
    <span class="mono">{_esc(evidence.get('schema',''))}</span>). The evaluated
    Terraform plan is identified by SHA-256
    <span class="mono">{_esc(evidence.get('plan_sha256',''))}</span>; any change to the
    plan changes this digest. Findings are produced by deterministic OPA/Rego policy
    evaluation, not manual inspection.</p>
    <p>Generated by the SWIFT CSCF Phase II attestation pipeline
    (<span class="mono">gate.py</span>, then <span class="mono">report.py</span>).
    For independent assessor review; not a substitute for a formal SWIFT CSP assessment.</p>
  </footer>
</div>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a human-readable CSCF compliance attestation from gate evidence JSON"
    )
    parser.add_argument("--evidence", required=True, type=Path, help="Evidence JSON from gate.py")
    parser.add_argument("--out", required=True, type=Path, help="Output HTML report path")
    parser.add_argument(
        "--public-key",
        type=Path,
        default=DEFAULT_PUBLIC_KEY,
        help="Ed25519 public key to verify the evidence signature against",
    )
    args = parser.parse_args()

    if not args.evidence.exists():
        parser.error(f"evidence file not found: {args.evidence}")

    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    document = render_html(evidence, args.public_key)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(document, encoding="utf-8")

    summary = evidence.get("summary", {})
    verdict = summary.get("result", "UNKNOWN")
    undetermined = summary.get("undetermined_instances", 0)
    excepted = summary.get("excepted_instances", 0)
    suffix = (f", {undetermined} undetermined" if undetermined else "") + (
        f", {excepted} excepted" if excepted else ""
    )
    print(f"Attestation report written: {args.out}  (verdict: {verdict}{suffix})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
