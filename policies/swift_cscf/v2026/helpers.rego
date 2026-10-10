# SWIFT CSCF v2026: Shared Helpers
# Policy library 2.0.0 (re-issue of the Phase I helpers; see ../../CHANGELOG.md)
# Provides: resource traversal, scope filters, nested-block access, IAM policy
#   document normalisation.

package swift_cscf.v2026.helpers

import rego.v1

# ============================================================================
# Resource Traversal
# ============================================================================

# Every resource in the plan, at any module depth. Library 1.0.0 walked the root
# module and two levels of child_modules under a comment claiming recursion, so a
# resource three modules deep was invisible to every rule (review R8).
all_resources contains r if {
	walk(input.planned_values.root_module, [path, r])
	_is_resource_path(path)
}

# A path of the form child_modules/i/.../resources/j.
_is_resource_path(path) if {
	n := count(path)
	n >= 2
	path[n - 2] == "resources"
	is_number(path[n - 1])
	every i, step in array.slice(path, 0, n - 2) {
		_module_step(i, step)
	}
}

_module_step(i, step) if {
	i % 2 == 0
	step == "child_modules"
}

_module_step(i, step) if {
	i % 2 == 1
	is_number(step)
}

# ============================================================================
# Scope Filters
# ============================================================================

# TAG-scoped: resource must carry the Swift zone tag
is_swift_tagged(resource) if {
	resource.values.tags["swift:zone"] == "secure"
}

# TAG-scoped fallback: also check tags_all (for resources that inherit provider tags)
is_swift_tagged(resource) if {
	resource.values.tags_all["swift:zone"] == "secure"
}

# VPC-scoped: resource belongs to the Swift VPC. A plan does not carry the Swift
# VPC id; the resolvability pass binds it as input.swift_vpc_id.
is_in_swift_vpc(resource) if {
	resource.values.vpc_id == input.swift_vpc_id
}

# MODULE-scoped: resource deployed via a Swift-specific Terraform module
is_in_swift_module(resource) if {
	startswith(resource.address, "module.swift_zone.")
}

# ============================================================================
# Nested Blocks
# ============================================================================

# The first instance of a nested block, or {} when the block is absent or empty.
# Library 1.0.0 wrote object.get(values, "block", [{}])[0]. The default applies
# only when the key is missing: an explicitly empty list -- what Terraform emits
# for a dynamic block with no input -- made the index undefined, and the rule
# passed silently (review R9.3).
block(values, name) := b if {
	b := object.get(values, name, [])[0]
}

block(values, name) := {} if {
	count(object.get(values, name, [])) == 0
}

# Some hand-written plans give a single block as an object rather than a list.
block(values, name) := b if {
	b := object.get(values, name, [])
	is_object(b)
	count(b) > 0
}

# ============================================================================
# IAM Policy Documents
# ============================================================================

# The statements of a policy document. IAM accepts Statement as a list or as a
# single object; library 1.0.0 iterated policy.Statement[_], which over a single
# object yields the statement's fields rather than the statement (review R9.1).
statements(policy) := policy.Statement if {
	is_array(policy.Statement)
}

statements(policy) := [policy.Statement] if {
	is_object(policy.Statement)
}

# IAM condition values may be JSON booleans or strings. Terraform's jsonencode
# preserves HCL types, so `Bool = { k = false }` emits false, not "false", and
# AWS accepts both (review R7).
is_true(value) if value == true

is_true(value) if value == "true"

is_false(value) if value == false

is_false(value) if value == "false"

# Normalise Action field: may be string or array -> always return a set
actions_from_statement(stmt) := actions if {
	is_array(stmt.Action)
	actions := {a | a := stmt.Action[_]}
}

actions_from_statement(stmt) := actions if {
	is_string(stmt.Action)
	actions := {stmt.Action}
}

# Normalise Resource field: may be string or array -> always return a set
resources_from_statement(stmt) := resources if {
	is_array(stmt.Resource)
	resources := {r | r := stmt.Resource[_]}
}

resources_from_statement(stmt) := resources if {
	is_string(stmt.Resource)
	resources := {stmt.Resource}
}

# Aggregate all allowed actions across all Allow statements in a policy document
all_allowed_actions(policy_doc) := actions if {
	actions := {action |
		stmt := statements(policy_doc)[_]
		stmt.Effect == "Allow"
		action := actions_from_statement(stmt)[_]
	}
}

# Check if any action in a set matches a prefix
action_matches_prefix(actions, prefix) if {
	action := actions[_]
	startswith(action, prefix)
}

# Check if any action in a set equals a specific action
action_contains(actions, target) if {
	target in actions
}

# ============================================================================
# Principal Normalisation Helpers
# ============================================================================

# A role whose trust policy admits only AWS services (Lambda, ECS, CloudTrail...).
# Such roles cannot use MFA and do not need permissions boundaries.
is_service_only_role(role_resource) if {
	policy := json.unmarshal(role_resource.values.assume_role_policy)
	_service_only(policy)
}

# A role a person can assume: its trust policy is known, parses, and admits a
# principal other than an AWS service. Library 1.0.0 tested
# `not is_service_only_role(role)`, which also holds when the trust policy cannot
# be read at all -- unknown until apply, or not valid JSON -- so a service role
# could be flagged for lacking controls meant for people (review R9.2).
is_human_assumable(role_resource) if {
	policy := json.unmarshal(role_resource.values.assume_role_policy)
	not _service_only(policy)
}

_service_only(policy) if {
	every stmt in statements(policy) {
		stmt.Principal.Service
		not stmt.Principal.AWS
	}
}

# Check if principal allows any identity (wildcard)
principal_allows_any(p) if {
	p == "*"
}

principal_allows_any(p) if {
	p.AWS == "*"
}

principal_allows_any(p) if {
	is_array(p.AWS)
	"*" in p.AWS
}

# Check if principal contains a root ARN from another account
principal_has_cross_account_root(p) := arns if {
	is_string(p.AWS)
	endswith(p.AWS, ":root")
	arns := {p.AWS}
}

principal_has_cross_account_root(p) := arns if {
	is_array(p.AWS)
	arns := {arn | arn := p.AWS[_]; endswith(arn, ":root")}
	count(arns) > 0
}

# Check if a statement has an ExternalId condition
has_external_id_condition(stmt) if {
	stmt.Condition.StringEquals["sts:ExternalId"]
}

has_external_id_condition(stmt) if {
	stmt.Condition.StringLike["sts:ExternalId"]
}

# ============================================================================
# Principal accounts (1.1-A15)
# ============================================================================

# The AWS account ids a policy principal names: from IAM and STS ARNs in any
# partition -- including federated identity providers, which belong to an
# account -- and from bare account ids, whether written as strings or numbers.
# "*" names no account (5.1-A11 covers it); service principals and web-identity
# services carry none.
principal_accounts(p) := {account |
	some key in ["AWS", "Federated"]
	some value in _principal_values(p[key])
	account := _account_of(value)
}

_principal_values(v) := {_as_text(v)} if not is_array(v)

_principal_values(v) := {_as_text(x) | some x in v} if is_array(v)

_as_text(v) := v if is_string(v)

# A JSON number loses leading zeros; account ids are twelve digits.
_as_text(v) := _pad12(format_int(v, 10)) if is_number(v)

_pad12(s) := concat("", [substring("000000000000", 0, 12 - count(s)), s]) if count(s) < 12

_pad12(s) := s if count(s) >= 12

_account_of(value) := value if regex.match(`^[0-9]{12}$`, value)

_account_of(value) := parts[0][1] if {
	parts := regex.find_all_string_submatch_n(`^arn:aws[a-z-]*:(?:iam|sts)::([0-9]{12}):`, value, 1)
	count(parts) == 1
}

# ============================================================================
# Port Range Helpers
# ============================================================================

# Check if a port range covers a specific port
port_in_range(from_port, to_port, target) if {
	from_port <= target
	to_port >= target
}

# Check if CIDR list contains unrestricted access
has_unrestricted_cidr(cidrs) if {
	"0.0.0.0/0" in cidrs
}

has_unrestricted_ipv6_cidr(cidrs) if {
	"::/0" in cidrs
}

# ============================================================================
# Managed Policy ARN Constants
# ============================================================================

overly_permissive_policies := {
	"arn:aws:iam::aws:policy/AdministratorAccess",
	"arn:aws:iam::aws:policy/PowerUserAccess",
}

admin_access_arn := "arn:aws:iam::aws:policy/AdministratorAccess"
power_user_arn := "arn:aws:iam::aws:policy/PowerUserAccess"

# Sensitive action prefixes for need-to-know checks
sensitive_prefixes := {
	"iam:", "sts:", "kms:", "s3:", "ec2:",
	"lambda:", "rds:", "secretsmanager:",
}

# TLS 1.2+ ELB security policies (maintained per Framework §13)
approved_tls_policies := {
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-3-2021-06",
	"ELBSecurityPolicy-FS-1-2-Res-2020-10",
	"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
}

# OpenSearch TLS policies enforcing TLS 1.2+
approved_opensearch_tls_policies := {
	"Policy-Min-TLS-1-2-2019-07",
	"Policy-Min-TLS-1-2-PFS-2023-10",
}
