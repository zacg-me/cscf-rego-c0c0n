"""Risk acceptances for the gate: one finding, on one resource, for a limited time.

An exception does not change what the gate detected. A finding covered by an
active exception moves from `violations` to `excepted` -- accepted risk, not
passed -- and stays visible in the console, the attestation and the signed
evidence. When the exception expires the finding is a violation again.

The file is TOML (`exceptions/exceptions.toml` by default):

    [[exception]]
    id          = "EXC-2026-001"
    assertion   = "1.1-A15"
    resource    = "aws_s3_bucket_policy.reporting_partner"
    reason      = "..."
    risk_owner  = "Head of Payments Operations"   # a role, not a name
    approved_by = "CISO"                          # a role, not a name
    ticket      = "RISK-1432"
    approved_on = 2026-10-05
    expires_on  = 2027-04-05

Approval is Git review: CODEOWNERS on exceptions/ names who must approve.
"""
from __future__ import annotations

import calendar
import dataclasses
import datetime as _dt
import hashlib
import re
import tomllib
from pathlib import Path

from findings import instance, recount

FIELDS = (
    "id", "assertion", "resource", "reason", "risk_owner",
    "approved_by", "ticket", "approved_on", "expires_on",
)
TEXT_FIELDS = FIELDS[:7]
DATE_FIELDS = FIELDS[7:]
ASSERTION_SHAPE = re.compile(r"^[0-9]+\.[0-9]+-A[0-9]+$")
MAX_MONTHS = 6


class ExceptionFileError(ValueError):
    """The exceptions file is invalid; the gate exits 2."""


@dataclasses.dataclass(frozen=True)
class Record:
    id: str
    assertion: str
    resource: str
    reason: str
    risk_owner: str
    approved_by: str
    ticket: str
    approved_on: _dt.date
    expires_on: _dt.date

    def as_json(self) -> dict:
        data = dataclasses.asdict(self)
        data["approved_on"] = self.approved_on.isoformat()
        data["expires_on"] = self.expires_on.isoformat()
        return data


def add_months(d: _dt.date, months: int) -> _dt.date:
    """Calendar-month addition, clamped: 31 Aug + 6 months = 28 (or 29) Feb."""
    index = d.month - 1 + months
    year, month = d.year + index // 12, index % 12 + 1
    day = min(d.day, calendar.monthrange(year, month)[1])
    return _dt.date(year, month, day)


def load(path: Path, today: _dt.date) -> tuple[list[Record], str]:
    """Parse and validate the exceptions file. Returns the records and the file's SHA-256."""
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        # utf-8-sig: a file saved by a Windows editor may start with a BOM.
        document = tomllib.loads(raw.decode("utf-8-sig"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as err:
        raise ExceptionFileError(f"{path}: not valid TOML: {err}") from err

    extra = set(document) - {"exception"}
    if extra:
        raise ExceptionFileError(
            f"{path}: unexpected top-level key(s): {', '.join(sorted(extra))}; "
            "only [[exception]] tables are allowed"
        )
    tables = document.get("exception", [])
    if not isinstance(tables, list) or not all(isinstance(t, dict) for t in tables):
        raise ExceptionFileError(f"{path}: 'exception' must be an array of tables ([[exception]])")

    records: list[Record] = []
    ids: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    for position, table in enumerate(tables, start=1):
        record = _record(table, position, today)
        if record.id in ids:
            raise ExceptionFileError(f"exception {record.id}: id is used more than once")
        if (record.assertion, record.resource) in pairs:
            raise ExceptionFileError(
                f"exception {record.id}: another exception already covers "
                f"{record.assertion} on {record.resource}"
            )
        ids.add(record.id)
        pairs.add((record.assertion, record.resource))
        records.append(record)
    return records, digest


def _record(table: dict, position: int, today: _dt.date) -> Record:
    raw_id = table.get("id")
    label = (
        f"exception {raw_id.strip()}"
        if isinstance(raw_id, str) and raw_id.strip()
        else f"exception #{position}"
    )
    unknown = set(table) - set(FIELDS)
    if unknown:
        raise ExceptionFileError(f"{label}: unknown field(s): {', '.join(sorted(unknown))}")
    missing = [f for f in FIELDS if f not in table]
    if missing:
        raise ExceptionFileError(f"{label}: missing field(s): {', '.join(missing)}")

    values: dict = {}
    for field in TEXT_FIELDS:
        value = table[field]
        if not isinstance(value, str) or not value.strip():
            raise ExceptionFileError(f"{label}: {field} must be a non-empty string")
        values[field] = value.strip()
    for field in DATE_FIELDS:
        value = table[field]
        # tomllib returns datetime for a date-time; datetime is a date subclass.
        if not isinstance(value, _dt.date) or isinstance(value, _dt.datetime):
            raise ExceptionFileError(
                f"{label}: {field} must be a TOML date such as 2026-10-05 (unquoted, no time)"
            )
        values[field] = value

    if not ASSERTION_SHAPE.match(values["assertion"]):
        raise ExceptionFileError(
            f"{label}: assertion {values['assertion']!r} is not an assertion id such as 1.1-A15"
        )
    if any(c in values["resource"] for c in "*?"):
        raise ExceptionFileError(
            f"{label}: resource must be one exact Terraform address; wildcards (* ?) are not allowed"
        )
    approved, expires = values["approved_on"], values["expires_on"]
    if expires <= approved:
        raise ExceptionFileError(f"{label}: expires_on must be after approved_on")
    latest = add_months(approved, MAX_MONTHS)
    if expires > latest:
        raise ExceptionFileError(
            f"{label}: expires_on {expires} is more than {MAX_MONTHS} months after "
            f"approved_on (latest allowed: {latest})"
        )
    if approved > today:
        raise ExceptionFileError(f"{label}: approved_on {approved} is in the future")
    return Record(**values)


def apply(
    report: dict,
    records: list[Record],
    today: _dt.date,
    file: str,
    sha256: str,
) -> None:
    """Move findings covered by an active exception from `violations` to `excepted`.

    Run after all undetermined detection: that detection compares witness runs
    with the report's violations, and must see what the gate actually found.
    Undetermined entries are never read or changed.
    """
    active = {
        (r.assertion, r.resource): r for r in records if r.approved_on <= today <= r.expires_on
    }
    expired = {(r.assertion, r.resource): r for r in records if today > r.expires_on}
    applied: set[str] = set()
    expired_hits: dict[str, int] = {}
    excepted_total = 0

    for control in report["controls"]:
        kept, excepted = [], []
        for violation in control["violations"]:
            key = instance(violation)
            record = active.get(key) if key else None
            if record:
                excepted.append({"finding": violation, "exception": record.as_json()})
                applied.add(record.id)
                continue
            if key in expired:
                rid = expired[key].id
                expired_hits[rid] = expired_hits.get(rid, 0) + 1
            kept.append(violation)
        control["violations"] = kept
        control["excepted"] = excepted
        excepted_total += len(excepted)

    recount(report)
    report["summary"]["excepted_instances"] = excepted_total
    report["exceptions"] = {
        "file": file,
        "sha256": sha256,
        "evaluated_on": today.isoformat(),
        "applied": sorted(applied),
        "expired": [
            {"id": r.id, "expired_on": r.expires_on.isoformat(), "findings": expired_hits[r.id]}
            for r in records
            if r.id in expired_hits
        ],
        "unused": [r.id for r in records if r.id not in applied and r.id not in expired_hits],
    }
