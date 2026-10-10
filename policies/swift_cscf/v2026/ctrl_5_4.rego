# SWIFT CSCF v2026, Control 5.4: Password Repository Protection
# Framework v1.2.1: Phase II (new control; see translations/ctrl_5_4_translation.md)
# Assertions: 5.4-A1 through 5.4-A5 (5 deny rules)
# Control Objective: Protect physically and logically the repository of recorded
#   passwords, with access restricted on a need-to-know basis.
#
# The logical password repository in AWS is Secrets Manager / SSM Parameter Store
# (KMS-encrypted). The "no plaintext / no hardcoded" clauses also reach RDS master
# passwords and Lambda environment variables. Physical-media protection and access
# logging (-> 6.4) / general need-to-know IAM (-> 5.1) are XREF-excluded.
# Uses the shared helpers.

package swift_cscf.v2026.ctrl_5_4

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 5.4-A1: Secrets Manager secrets use a customer-managed KMS key
# Source: CSCF v2026, § logical storage (encryption-at-rest, no plaintext)
# Scope: TAG | Variant: A  (empty/absent key = default AWS-managed key = violation)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_secretsmanager_secret"
	helpers.is_swift_tagged(resource)

	object.get(resource.values, "kms_key_id", "") == ""

	msg := sprintf(
		"CSCF 5.4 [5.4-A1]: Secret is not encrypted with a customer-managed KMS key; the password repository must use a controlled key (§ logical storage). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.4-A2: SSM parameters holding credentials are SecureString (no plaintext)
# Source: CSCF v2026, § logical storage (no plain text storage)
# Scope: TAG + name heuristic | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_ssm_parameter"
	helpers.is_swift_tagged(resource)

	_looks_like_secret(resource.values.name)
	resource.values.type != "SecureString"

	msg := sprintf(
		"CSCF 5.4 [5.4-A2]: SSM parameter storing a credential is type '%s', not SecureString (plaintext storage) (§ logical storage). (resource: %s)",
		[resource.values.type, resource.address],
	)
}

# ============================================================================
# 5.4-A3: Secret resource policy grants no wildcard principal (need-to-know)
# Source: CSCF v2026, § Control Statement (access restricted need-to-know)
# Scope: ACCT | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_secretsmanager_secret_policy"

	policy := json.unmarshal(resource.values.policy)
	stmt := policy.Statement[_]
	stmt.Effect == "Allow"
	helpers.principal_allows_any(stmt.Principal)

	msg := sprintf(
		"CSCF 5.4 [5.4-A3]: Secret resource policy grants access to any principal ('*'); repository access must be need-to-know (§ Control Statement). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.4-A4: RDS instances do not hardcode an inline master password
# Source: CSCF v2026, § passwords not hardcoded in scripts or software code
# Scope: TAG | Variant: F (conditional)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_db_instance"
	helpers.is_swift_tagged(resource)

	object.get(resource.values, "password", "") != ""
	object.get(resource.values, "manage_master_user_password", false) != true

	msg := sprintf(
		"CSCF 5.4 [5.4-A4]: RDS master password is hardcoded inline; use Secrets-Manager-managed credentials (manage_master_user_password) instead (§ no hardcoded passwords). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 5.4-A5: Lambda environment variables contain no hardcoded password-like values
# Source: CSCF v2026, § passwords not hardcoded in scripts or software code
# Scope: TAG + key heuristic | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_lambda_function"
	helpers.is_swift_tagged(resource)

	env := resource.values.environment[_]
	some key, value in env.variables
	_looks_like_secret(key)
	value != ""
	not startswith(value, "arn:aws:secretsmanager")

	msg := sprintf(
		"CSCF 5.4 [5.4-A5]: Lambda environment variable '%s' hardcodes a password-like value; reference a Secrets Manager ARN instead (§ no hardcoded passwords). (resource: %s)",
		[key, resource.address],
	)
}

# Credential-name heuristic (shared by A2 and A5)
_looks_like_secret(name) if contains(lower(name), "password")

_looks_like_secret(name) if contains(lower(name), "passwd")

_looks_like_secret(name) if contains(lower(name), "secret")

_looks_like_secret(name) if contains(lower(name), "credential")

_looks_like_secret(name) if contains(lower(name), "token")

_looks_like_secret(name) if contains(lower(name), "apikey")
