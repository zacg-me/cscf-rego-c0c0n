#!/usr/bin/env python3
"""CI assertion for plan completeness (review finding R1).

The case study's remediated plan is an incremental change. Evaluated as a full
plan it fails eight assertions that report the absence of account-level
infrastructure the change never claimed to create. Under --plan-scope
incremental those must be undetermined, and only the finding that names a
resource in the change itself may remain.

Usage: python assert_incremental_scope.py <evidence.json>
"""
import json
import sys
from pathlib import Path

EXPECTED_UNDETERMINED = {
    "1.1-A9",
    "6.4-A1",
    "6.4-A5",
    "6.4-A19",
    "6.4-A20",
    "6.4-A21",
    "6.4-A23",
    "6.4-A24",
}
EXPECTED_VIOLATIONS = {"6.4-A6"}


def main() -> int:
    evidence = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

    undetermined = {u["assertion"] for u in evidence.get("undetermined", [])}
    if undetermined != EXPECTED_UNDETERMINED:
        print(
            f"::error::undetermined set changed: {sorted(undetermined)} "
            f"(expected {sorted(EXPECTED_UNDETERMINED)})"
        )
        return 1

    fired = {a for c in evidence["controls"] for a in c["assertions"]}
    if fired != EXPECTED_VIOLATIONS:
        print(
            f"::error::violations changed: {sorted(fired)} "
            f"(expected {sorted(EXPECTED_VIOLATIONS)})"
        )
        return 1

    print(
        f"plan-completeness check OK: {len(undetermined)} absence assertion(s) "
        f"undetermined, {len(fired)} resource-attributed violation(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
