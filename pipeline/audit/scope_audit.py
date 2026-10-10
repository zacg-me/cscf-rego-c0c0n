"""Audit: does each rule implement the scope its header declares?

Every rule carries a `# Scope:` header (TAG / VPC / MODULE / ACCT). A rule that
declares a resource-level scope but applies no scope predicate evaluates
account-wide, which means it can report a non-Swift resource as a CSCF
violation, and it means the traceability matrix disagrees with the code.

A scope predicate is any of the shared helpers, any parent-scope lookup, or a
control-local helper whose body reads `tags` or calls one of those --
`_is_jump_server` scopes just as effectively as `is_swift_tagged`, and counting
it as unscoped is a false alarm.

Run from the repository root:

    python pipeline/audit/scope_audit.py

Prints the mismatches per file and exits non-zero if there are any. The first
library (1.0.0) carried 39 (PHASE1_MISMATCHES, kept as a record; see
docs/failure-modes.md). The current library implements every declared scope,
so any mismatch fails the build.
"""
import collections
import re
import pathlib

POLICY_ROOTS = ("policies",)

SHARED_PREDICATES = (
    "is_swift_tagged",
    "is_in_swift_vpc",
    "is_in_swift_module",
    "parent_scope.",
    "zone_scope.",
)

ASSERTION = re.compile(r"#\s+(\d+\.\d+-A\d+):")
SCOPE = re.compile(r"#\s+Scope:\s*(\w+)")
RESOURCE_TYPE = re.compile(r'\.type == "([a-z0-9_]+)"')
HELPER_CALL = re.compile(r"(_[a-z0-9_]+)\(")

# The 39 rules of library 1.0.0 that declared a resource scope and applied
# none. Kept as the record of what the 2.0.0 re-issue corrected: the archive
# must still reproduce exactly this set (a test checks it), and the library
# must reproduce none of it.
PHASE1_MISMATCHES = {
    ("ctrl_1_1.rego", a) for a in
    ("1.1-A1", "1.1-A2", "1.1-A3", "1.1-A4", "1.1-A5", "1.1-A6",
     "1.1-A7", "1.1-A8", "1.1-A9", "1.1-A10", "1.1-A11")
} | {
    ("ctrl_2_1.rego", f"2.1-A{n}") for n in list(range(1, 16))
} | {
    ("ctrl_4_1.rego", a) for a in
    ("4.1-A11", "4.1-A12", "4.1-A13", "4.1-A16", "4.1-A17", "4.1-A18")
} | {
    ("ctrl_5_1.rego", "5.1-A16"), ("ctrl_5_1.rego", "5.1-A17"),
    ("ctrl_6_4.rego", "6.4-A5"),
}


def tag_reading_helpers(text: str) -> set:
    """Control-local helpers that scope, e.g. _is_jump_server or _acl_in_swift_zone."""
    out = set()
    for name, body in re.findall(
        r"\n(_[a-z0-9_]+)\(\w+\)\s*(?::=\s*\w+\s*)?if \{(.*?)\n\}", text, re.S
    ):
        if ".tags[" in body or ".tags_all[" in body or any(
            p in body for p in SHARED_PREDICATES
        ):
            out.add(name)
    return out


def audit(roots=POLICY_ROOTS):
    rows = []
    for root in roots:
        for path in sorted(pathlib.Path(root).rglob("ctrl_*.rego")):
            text = path.read_text(encoding="utf-8")
            local = tag_reading_helpers(text)
            chunks = re.split(r"\ndeny contains msg if \{", text)
            assertion, scope = "?", "?"
            for i, chunk in enumerate(chunks[1:], start=1):
                body = chunk.split("\n}")[0]
                ids = ASSERTION.findall(chunks[i - 1])
                scopes = SCOPE.findall(chunks[i - 1])
                if ids:
                    assertion = ids[-1]
                if scopes:
                    scope = scopes[-1]
                scoped = any(p in body for p in SHARED_PREDICATES) or any(
                    call in local for call in HELPER_CALL.findall(body)
                )
                rows.append(
                    {
                        "file": path.name,
                        "assertion": assertion,
                        "declared": scope,
                        "scoped": scoped,
                        "types": sorted(set(RESOURCE_TYPE.findall(body))),
                    }
                )
    return rows


def main() -> int:
    import sys

    roots = POLICY_ROOTS
    if "--root" in sys.argv:
        roots = (sys.argv[sys.argv.index("--root") + 1],)
    rows = audit(roots)
    resource_scoped = [r for r in rows if r["declared"] in ("TAG", "VPC", "MODULE")]
    mismatched = [r for r in resource_scoped if not r["scoped"]]

    print(f"rule bodies inspected            : {len(rows)}")
    print(f"declaring TAG / VPC / MODULE     : {len(resource_scoped)}")
    print(f"  scope predicate present        : {len(resource_scoped) - len(mismatched)}")
    print(f"  scope predicate MISSING        : {len(mismatched)}")

    by_file = collections.defaultdict(set)
    for row in mismatched:
        by_file[row["file"]].add(f"{row['assertion']}({row['declared']})")
    print()
    for name in sorted(by_file):
        print(f"  {name:26} {len(by_file[name]):>2}  {' '.join(sorted(by_file[name]))}")

    if mismatched:
        print("\nMISMATCHES: these rules declare a scope they do not apply.")
        return 1
    print("\nNo mismatches: every rule implements its declared scope.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
