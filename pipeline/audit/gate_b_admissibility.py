#!/usr/bin/env python3
"""Gate B admissibility: does every attribute a rule reads actually exist?

An assertion that reads an attribute the provider does not define on that
resource type can never fire. It is not wrong in the ordinary sense -- it is
*unsatisfiable*, and it passes silently on every input, while behavioural
validation against hand-written fixtures certifies it as working, because the
fixture author supplies the impossible attribute. Three assertions in this
project's own released library were in that state (see
../../terraform/README.md and ../../translations/binding_corrections.md).

Terraform publishes the provider schema, so the check is mechanical:

    terraform -chdir=<dir> providers schema -json > schema.json
    python gate_b_admissibility.py schema.json

It resolves three things beyond a plain attribute read, because the known
defects hide in all three:

* **scope predicates** -- `is_swift_tagged(r)` reads `tags`, which is where the
  original three defects lived;
* **nested blocks** -- `values.advanced_security_options[_].saml_options[_]`;
* **private helpers** -- the read is usually one call away from the rule, so
  helper bodies are analysed with the parameter bound to the type its callers
  pass.

Exit status is non-zero when anything inadmissible is found, so it can gate CI.
"""
import json
import re
import sys
from pathlib import Path

POLICY_ROOTS = ("policies",)

# Attributes Terraform adds to every managed resource in plan output.
UNIVERSAL = {"id", "arn", "region"}

# Inadmissible reads accepted knowingly. Library 1.0.0 had three -- 1.1-A14,
# 2.1-A16 and 5.1-A11 read `tags` on attachment types that take none (found on generated plans). The
# 2.0.0 re-issue scopes all three through their parent, so the set is empty and
# any inadmissible read fails the build.
KNOWN_SUPERSEDED: set = set()
# NOTE: "tags" is deliberately NOT universal -- not every resource type has it.

VAR_TYPE = re.compile(r'(\w+)\.type == "([a-z0-9_]+)"')
DOT_ATTR = re.compile(r"(\w+)\.values\.([a-z_][a-z0-9_]*)")
GET_ATTR = re.compile(r'object\.get\(\s*(\w+)\.values,\s*"([a-z_][a-z0-9_]*)"')
BLOCK_ALIAS = re.compile(r"(\w+)\s*:=\s*(\w+)\.values\.([a-z_][a-z0-9_]*)\[")
GET_BLOCK_ALIAS = re.compile(
    r'(\w+)\s*:=\s*object\.get\(\s*(\w+)\.values,\s*"([a-z_][a-z0-9_]*)"'
)
NESTED_BLOCK = re.compile(r"(\w+)\s*:=\s*(\w+)\.([a-z_][a-z0-9_]*)\[")
ALIAS_ATTR = re.compile(r"(\w+)\.([a-z_][a-z0-9_]*)\b")
HELPER_CALL = re.compile(r"(?:^|\s|\()(_[a-z0-9_]+)\((\w+)\)")
SCOPE_TAG = re.compile(r"is_swift_tagged\((\w+)\)")
SCOPE_VPC = re.compile(r"is_in_swift_vpc\((\w+)\)")
# zone_scope.in_swift_zone holds on the VPC binding or the zone tag. The tag is
# the branch every scoped type must be able to satisfy, so it is what is checked.
SCOPE_ZONE = re.compile(r"zone_scope\.in_swift_zone\((\w+)\)")
# parent_scope.parent_swift_tagged(child, "file_system_id", "aws_efs_file_system"):
# the child must have the reference attribute and the parent must take tags.
SCOPE_PARENT = re.compile(
    r'parent_scope\.parent_\w+\(\s*(\w+),\s*"([a-z_][a-z0-9_]*)",\s*"([a-z0-9_]+)"\s*\)'
)
# helpers.block(resource.values, "name") and helpers.block(alias, "name").
HELPER_BLOCK = re.compile(
    r'(\w+)\s*:=\s*helpers\.block\(\s*(\w+)(\.values)?,\s*"([a-z_][a-z0-9_]*)"\s*\)'
)
ALIAS_GET = re.compile(r'object\.get\(\s*(\w+),\s*"([a-z_][a-z0-9_]*)"')
ASSERTION = re.compile(r"#\s+(\d+\.\d+-A\d+):")


def load_schema(path: Path) -> dict:
    schema = json.loads(path.read_text(encoding="utf-8"))
    blocks = {}
    for provider in schema.get("provider_schemas", {}).values():
        for rtype, rschema in (provider.get("resource_schemas") or {}).items():
            blocks[rtype] = rschema.get("block", {})
    return blocks


def names_of(block: dict) -> set:
    return set(block.get("attributes", {})) | set(block.get("block_types", {}))


def child_block(block: dict, name: str):
    """The schema of `name` inside `block`, whether it is a block or an attribute.

    Terraform models a repeated block two ways. `aws_opensearch_domain` declares
    `advanced_security_options` as a *block type*; `aws_security_group` declares
    `ingress` as an *attribute* whose cty type is a set of objects. Both are
    written the same way in Rego, so both must be followed -- otherwise every
    `values.ingress[_].from_port` read looks inadmissible.
    """
    entry = (block.get("block_types") or {}).get(name)
    if entry:
        return entry["block"]

    attribute = (block.get("attributes") or {}).get(name)
    if not attribute:
        return None
    return object_block(attribute.get("type"))


def object_block(cty):
    """Turn a cty type into a pseudo-block, if it carries named attributes.

    ["set", ["object", {"from_port": "number", ...}]] -> {"attributes": {...}}
    Returns None for scalars and for collections of scalars, which have no
    inner names to check.
    """
    while isinstance(cty, list) and cty and cty[0] in ("set", "list", "map"):
        cty = cty[1] if len(cty) > 1 else None
    if isinstance(cty, list) and len(cty) == 2 and cty[0] == "object":
        return {"attributes": {name: {} for name in cty[1]}}
    return None


def split_bodies(text: str):
    """Yield (assertion id, body) for each deny rule in a policy file."""
    chunks = re.split(r"\ndeny contains msg if \{", text)
    last = "?"
    for i, chunk in enumerate(chunks[1:], start=1):
        ids = ASSERTION.findall(chunks[i - 1])
        if ids:
            last = ids[-1]
        # A second rule for the same assertion (IPv4/IPv6 pairs) carries no
        # header of its own, so it inherits the one above it.
        yield last, chunk.split("\n}")[0]


def helper_bodies(text: str) -> dict:
    """Private helper name -> [(parameter, body)]."""
    out = {}
    for name, param, body in re.findall(
        r"\n(_[a-z0-9_]+)\((\w+)\)\s*(?::=\s*\w+\s*)?if \{(.*?)\n\}", text, re.S
    ):
        out.setdefault(name, []).append((param, body))
    return out


def reads_in_body(body: str, bindings: dict, blocks: dict, helpers: dict, seen=()):
    """Yield (resource type, dotted path) for every attribute this body reads.

    `bindings` maps a variable name to (resource type, block path).
    """
    for var, attr in DOT_ATTR.findall(body) + GET_ATTR.findall(body):
        if var in bindings and not bindings[var][1]:
            yield bindings[var][0], [attr]

    for var in SCOPE_TAG.findall(body):
        if var in bindings:
            yield bindings[var][0], ["tags"]
    for var in SCOPE_VPC.findall(body):
        if var in bindings:
            yield bindings[var][0], ["vpc_id"]
    for var in SCOPE_ZONE.findall(body):
        if var in bindings:
            yield bindings[var][0], ["tags"]
    for var, attribute, parent_type in SCOPE_PARENT.findall(body):
        if var in bindings:
            yield bindings[var][0], [attribute]
        yield parent_type, ["tags"]

    # Aliases into a block, then attribute reads through the alias.
    local = dict(bindings)
    for alias, var, block in (
        BLOCK_ALIAS.findall(body)
        + GET_BLOCK_ALIAS.findall(body)
        + NESTED_BLOCK.findall(body)
    ):
        if var not in local:
            continue
        rtype, path = local[var]
        local[alias] = (rtype, path + [block])
        yield rtype, path + [block]

    # helpers.block(...) aliases, in source order so a nested block can build on
    # the alias of its parent block.
    for alias, var, on_values, block in HELPER_BLOCK.findall(body):
        if var not in local or (on_values and local[var][1]) or (not on_values and not local[var][1]):
            continue
        rtype, path = local[var]
        local[alias] = (rtype, path + [block])
        yield rtype, path + [block]

    for alias, attr in ALIAS_ATTR.findall(body) + ALIAS_GET.findall(body):
        if alias in local and local[alias][1] and attr not in ("values", "type", "address"):
            rtype, path = local[alias]
            yield rtype, path + [attr]

    # Follow helper calls, binding the parameter to the caller's type.
    for helper, var in HELPER_CALL.findall(body):
        if helper in seen or var not in local or helper not in helpers:
            continue
        rtype, path = local[var]
        for param, helper_body in helpers[helper]:
            yield from reads_in_body(
                helper_body, {param: (rtype, path)}, blocks, helpers, seen + (helper,)
            )


def library_reads(roots=POLICY_ROOTS) -> set:
    """(resource type, dotted attribute path) for every attribute a rule reads.

    The reads this audit checks against the schema, without the schema. The
    conformance suite uses it to find provider-computed attributes a rule
    depends on, each of which the Target Profile must classify.
    """
    reads = set()
    for root in roots:
        for path in sorted(Path(root).rglob("*.rego")):
            text = path.read_text(encoding="utf-8")
            helpers = helper_bodies(text)
            for _, body in split_bodies(text):
                bindings = {v: (t, []) for v, t in VAR_TYPE.findall(body)}
                for rtype, read in reads_in_body(body, bindings, {}, helpers):
                    reads.add((rtype, ".".join(read)))
    return reads


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    blocks = load_schema(Path(sys.argv[1]))
    roots = POLICY_ROOTS
    if "--root" in sys.argv:
        roots = (sys.argv[sys.argv.index("--root") + 1],)

    findings, checked = [], 0
    for root in roots:
        for path in sorted(Path(root).rglob("*.rego")):
            text = path.read_text(encoding="utf-8")
            helpers = helper_bodies(text)
            for assertion, body in split_bodies(text):
                bindings = {v: (t, []) for v, t in VAR_TYPE.findall(body)}
                for rtype, read in reads_in_body(body, bindings, blocks, helpers):
                    if rtype not in blocks:
                        continue
                    checked += 1
                    block, missing, opaque = blocks[rtype], None, False
                    for segment in read[:-1]:
                        if segment not in names_of(block):
                            missing = segment
                            break
                        child = child_block(block, segment)
                        if child is None:
                            # A scalar or a collection of scalars: there are no
                            # inner names to validate, so stop rather than guess.
                            opaque = True
                            break
                        block = child
                    if opaque:
                        continue
                    if missing is None and (
                        read[-1] in names_of(block) or read[-1] in UNIVERSAL
                    ):
                        continue
                    findings.append(
                        (path.name, assertion, rtype, ".".join(read), missing or read[-1])
                    )

    unique = sorted(set(findings))
    fresh = [f for f in unique if (f[1], f[2], f[3]) not in KNOWN_SUPERSEDED]
    known = len(unique) - len(fresh)

    print(f"attribute reads checked against the provider schema: {checked}")
    print(f"INADMISSIBLE reads: {len(unique)}  ({known} known and superseded)")
    for name, assertion, rtype, read, missing in unique:
        tag = "  (known, superseded)" if (assertion, rtype, read) in KNOWN_SUPERSEDED else ""
        print(f"  {name:24} {assertion:10} {rtype}.{read}   (no '{missing}'){tag}")
    return 1 if fresh else 0


if __name__ == "__main__":
    raise SystemExit(main())
