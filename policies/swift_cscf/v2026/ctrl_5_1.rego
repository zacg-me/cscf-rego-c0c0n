# SWIFT CSCF v2026, Control 5.1: Logical Access Control
# Policy library 2.0.0 (re-issue of the Phase I control; see ../../CHANGELOG.md)
# Assertions: 5.1-A1 through 5.1-A18
# Control Objective: Enforce the security principles of need-to-know access,
#   least privilege, and separation of duties for operator accounts.

package swift_cscf.v2026.ctrl_5_1

import rego.v1

import data.swift_cscf.v2026.helpers
import data.swift_cscf.v2026.parent_scope

# Every resource type that carries an identity policy document. Library 1.0.0
# read only the first two, so an inline policy on a user or a group was never
# examined (review R9.5).
POLICY_DOCUMENT_TYPES := {
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
}

# ============================================================================
# 5.1-A1: No Wildcard Action
# Source: CSCF v2026, § Need-to-know (S2)
# Scope: ACCT | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type in POLICY_DOCUMENT_TYPES

	policy := json.unmarshal(resource.values.policy)
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"

	actions := helpers.actions_from_statement(stmt)
	"*" in actions

	msg := sprintf(
		"CSCF 5.1 [5.1-A1]: IAM policy grants wildcard Action (*) with Allow (§ Need-to-know). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A2: No Sensitive Actions on Wildcard Resource
# Source: CSCF v2026, § Need-to-know, § Least Privilege (S2)
# Scope: ACCT | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type in POLICY_DOCUMENT_TYPES

	policy := json.unmarshal(resource.values.policy)
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"

	resources := helpers.resources_from_statement(stmt)
	"*" in resources

	actions := helpers.actions_from_statement(stmt)
	prefix := helpers.sensitive_prefixes[_]
	action := actions[_]
	startswith(action, prefix)

	msg := sprintf(
		"CSCF 5.1 [5.1-A2]: IAM policy grants sensitive action '%s' on Resource '*' (§ Need-to-know, § Least Privilege). (resource: %s)",
		[action, resource.address],
	)
}

# ============================================================================
# 5.1-A3: No Direct User Policy Attachments
# Source: CSCF v2026, § Need-to-know (S1, S3)
# Scope: ACCT | Variant: B (presence, should not exist)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_user_policy_attachment"

	user := object.get(resource.values, "user", "unknown")

	msg := sprintf(
		"CSCF 5.1 [5.1-A3]: Managed policy directly attached to user '%s'. Use IAM groups or role assumption (§ Need-to-know). (resource: %s)",
		[user, resource.address],
	)
}

# ============================================================================
# 5.1-A4: No Direct User Inline Policies
# Source: CSCF v2026, § Need-to-know (S1, S3)
# Scope: ACCT | Variant: B (presence, should not exist)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_user_policy"

	user := object.get(resource.values, "user", "unknown")

	msg := sprintf(
		"CSCF 5.1 [5.1-A4]: Inline policy on user '%s'. Use groups with managed policies (§ Need-to-know). (resource: %s)",
		[user, resource.address],
	)
}

# ============================================================================
# 5.1-A5: No AdministratorAccess on Users
# Source: CSCF v2026, § Least Privilege (S4)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_user_policy_attachment"
	resource.values.policy_arn == helpers.admin_access_arn

	msg := sprintf(
		"CSCF 5.1 [5.1-A5]: AdministratorAccess attached to user (§ Least Privilege). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A6: No AdministratorAccess on Roles
# Source: CSCF v2026, § Least Privilege (S4)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_role_policy_attachment"
	resource.values.policy_arn == helpers.admin_access_arn

	msg := sprintf(
		"CSCF 5.1 [5.1-A6]: AdministratorAccess attached to role (§ Least Privilege). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A7: No AdministratorAccess on Groups
# Source: CSCF v2026, § Least Privilege (S4)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_group_policy_attachment"
	resource.values.policy_arn == helpers.admin_access_arn

	msg := sprintf(
		"CSCF 5.1 [5.1-A7]: AdministratorAccess attached to group (§ Least Privilege). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A8: No PowerUserAccess
# Source: CSCF v2026, § Least Privilege (S4)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type in {
		"aws_iam_user_policy_attachment",
		"aws_iam_role_policy_attachment",
		"aws_iam_group_policy_attachment",
	}
	resource.values.policy_arn == helpers.power_user_arn

	msg := sprintf(
		"CSCF 5.1 [5.1-A8]: PowerUserAccess attached. Grants all actions except IAM: exceeds least privilege (§ Least Privilege). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A9: No Wildcard Principal in Trust Policy
# Source: CSCF v2026, § Need-to-know (S1, S2)
# Scope: ACCT | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_role"

	policy := json.unmarshal(resource.values.assume_role_policy)
	stmt := helpers.statements(policy)[_]
	helpers.principal_allows_any(stmt.Principal)

	msg := sprintf(
		"CSCF 5.1 [5.1-A9]: Trust policy allows any principal (Principal: '*'). Access must be scoped (§ Need-to-know). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A10: No Unrestricted iam:PassRole
# Source: CSCF v2026, § Least Privilege, § SoD (S4, S6)
# Scope: ACCT | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type in POLICY_DOCUMENT_TYPES

	policy := json.unmarshal(resource.values.policy)
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"

	actions := helpers.actions_from_statement(stmt)
	helpers.action_contains(actions, "iam:PassRole")

	resources := helpers.resources_from_statement(stmt)
	"*" in resources

	msg := sprintf(
		"CSCF 5.1 [5.1-A10]: iam:PassRole on Resource '*'. Must be scoped to specific role ARNs (§ Least Privilege, § SoD). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A11: No Open S3 Bucket Principal
# Source: CSCF v2026, § Need-to-know (S2)
# Scope: TAG (via bucket) | Variant: C (JSON parse)
# `aws_s3_bucket_policy` takes no tags, so scope comes from the bucket it
# attaches to (found on generated plans).
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_policy"
	parent_scope.in_swift_zone_via_bucket(resource)

	policy := json.unmarshal(resource.values.policy)
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"
	helpers.principal_allows_any(stmt.Principal)

	# No restrictive condition
	not stmt.Condition

	msg := sprintf(
		"CSCF 5.1 [5.1-A11]: S3 bucket allows any principal without condition (§ Need-to-know). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A12: SoD, Create User + Attach Policy
# Source: CSCF v2026, § Separation of Duties (S5, S6)
# Scope: ACCT | Variant: D (intra-resource multi-action co-occurrence)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type in POLICY_DOCUMENT_TYPES

	policy := json.unmarshal(resource.values.policy)
	all_actions := helpers.all_allowed_actions(policy)

	helpers.action_contains(all_actions, "iam:CreateUser")
	_has_attach_action(all_actions)

	msg := sprintf(
		"CSCF 5.1 [5.1-A12]: Policy grants both user creation and policy attachment, SoD violation (§ Separation of Duties). (resource: %s)",
		[resource.address],
	)
}

_has_attach_action(actions) if { "iam:AttachUserPolicy" in actions }
_has_attach_action(actions) if { "iam:AttachRolePolicy" in actions }

# ============================================================================
# 5.1-A13: SoD, Create Role + Attach Policy
# Source: CSCF v2026, § Separation of Duties (S5, S6)
# Scope: ACCT | Variant: D
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type in POLICY_DOCUMENT_TYPES

	policy := json.unmarshal(resource.values.policy)
	all_actions := helpers.all_allowed_actions(policy)

	helpers.action_contains(all_actions, "iam:CreateRole")
	helpers.action_contains(all_actions, "iam:AttachRolePolicy")

	msg := sprintf(
		"CSCF 5.1 [5.1-A13]: Policy grants both role creation and role policy attachment, SoD violation (§ Separation of Duties). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A14: SoD, Create Policy + Attach Policy
# Source: CSCF v2026, § Separation of Duties (S5, S6)
# Scope: ACCT | Variant: D
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type in POLICY_DOCUMENT_TYPES

	policy := json.unmarshal(resource.values.policy)
	all_actions := helpers.all_allowed_actions(policy)

	helpers.action_contains(all_actions, "iam:CreatePolicy")
	_has_any_attach_action(all_actions)

	msg := sprintf(
		"CSCF 5.1 [5.1-A14]: Policy grants both policy authoring and attachment, SoD violation (§ Separation of Duties). (resource: %s)",
		[resource.address],
	)
}

_has_any_attach_action(actions) if { "iam:AttachUserPolicy" in actions }
_has_any_attach_action(actions) if { "iam:AttachRolePolicy" in actions }
_has_any_attach_action(actions) if { "iam:AttachGroupPolicy" in actions }

# ============================================================================
# 5.1-A15: SoD, Security Config + User Provisioning
# Source: CSCF v2026, § Separation of Duties (S5, S6)
# Scope: ACCT | Variant: D
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type in POLICY_DOCUMENT_TYPES

	policy := json.unmarshal(resource.values.policy)
	all_actions := helpers.all_allowed_actions(policy)

	helpers.action_contains(all_actions, "iam:UpdateAccountPasswordPolicy")
	helpers.action_contains(all_actions, "iam:CreateUser")

	msg := sprintf(
		"CSCF 5.1 [5.1-A15]: Policy grants both security config and user provisioning, SoD violation (§ Separation of Duties). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.1-A16: Lambda Execution Role Least Privilege
# Source: CSCF v2026, § Least Privilege (S4)
# Scope: TAG | Variant: E (cross-resource relationship)
# The function is the scoped resource: a Swift-tagged Lambda whose execution
# role carries an overly permissive managed policy.
# ============================================================================

deny contains msg if {
	attachment := helpers.all_resources[_]
	attachment.type == "aws_iam_role_policy_attachment"
	attachment.values.policy_arn in helpers.overly_permissive_policies

	# Check if the role is used by a Swift-zone Lambda function. An empty role
	# name is contained in every ARN, so it would match every function.
	lambda := helpers.all_resources[_]
	lambda.type == "aws_lambda_function"
	helpers.is_swift_tagged(lambda)
	_names_role(object.get(lambda.values, "role", ""), attachment.values.role)

	msg := sprintf(
		"CSCF 5.1 [5.1-A16]: Lambda execution role has %s attached (§ Least Privilege). (resource: %s, lambda: %s)",
		[attachment.values.policy_arn, attachment.address, lambda.address],
	)
}

# ============================================================================
# 5.1-A17: ECS Task Role Least Privilege
# Source: CSCF v2026, § Least Privilege (S4)
# Scope: TAG | Variant: E (cross-resource relationship)
# The task definition is the scoped resource, as for 5.1-A16.
# ============================================================================

deny contains msg if {
	attachment := helpers.all_resources[_]
	attachment.type == "aws_iam_role_policy_attachment"
	attachment.values.policy_arn in helpers.overly_permissive_policies

	# Check if the role is used by a Swift-zone ECS task
	task := helpers.all_resources[_]
	task.type == "aws_ecs_task_definition"
	helpers.is_swift_tagged(task)
	_ecs_uses_role(task, attachment.values.role)

	msg := sprintf(
		"CSCF 5.1 [5.1-A17]: ECS task role has %s attached (§ Least Privilege). (resource: %s, task: %s)",
		[attachment.values.policy_arn, attachment.address, task.address],
	)
}

_ecs_uses_role(task, role_name) if {
	_names_role(object.get(task.values, "execution_role_arn", ""), role_name)
}

_ecs_uses_role(task, role_name) if {
	_names_role(object.get(task.values, "task_role_arn", ""), role_name)
}

# A role ARN refers to the named role. Both must be non-empty: contains(x, "")
# holds for every x, which made an attachment with no role match everything.
_names_role(arn, role_name) if {
	role_name != ""
	arn != ""
	contains(arn, role_name)
}

# ============================================================================
# 5.1-A18: Cross-Account Trust Requires ExternalId
# Source: CSCF v2026, § Account Review and Revocation (S7, S10)
# Scope: ACCT | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_role"

	policy := json.unmarshal(resource.values.assume_role_policy)
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Allow"

	root_arns := helpers.principal_has_cross_account_root(stmt.Principal)
	root_arn := root_arns[_]

	# Exclude same-account root trust (standard AWS pattern, not cross-account)
	not _is_same_account_root(root_arn)

	not helpers.has_external_id_condition(stmt)

	msg := sprintf(
		"CSCF 5.1 [5.1-A18]: Cross-account trust without ExternalId condition. Prevents confused deputy (§ Account Review, § Need-to-know). (resource: %s)",
		[resource.address],
	)
}

# Same-account root trust is legitimate: only flag cross-account.
# The resolvability pass binds input.swift_account_id; an empty binding must not
# match, or every root ARN would count as the same account.
_is_same_account_root(arn) if {
	account_id := input.swift_account_id
	account_id != ""
	contains(arn, account_id)
}
