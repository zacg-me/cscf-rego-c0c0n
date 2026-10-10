# SWIFT CSCF v2026, Control 4.1: Password Policy
# Policy library 2.0.0 (re-issue of the Phase I control; see ../../CHANGELOG.md)
# Assertions: 4.1-A1 through 4.1-A19
# Control Objective: Ensure passwords are sufficiently resistant against
#   common password attacks by implementing and enforcing an effective password policy.

package swift_cscf.v2026.ctrl_4_1

import rego.v1

import data.swift_cscf.v2026.helpers
import data.swift_cscf.v2026.parent_scope

# ============================================================================
# 4.1-A1: IAM Password Policy Existence
# Source: CSCF v2026, § Implementation Guidelines (S4, S7)
# Scope: ACCT | Variant: B (presence check)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_iam_account_password_policy"
	]) == 0

	msg := "CSCF 4.1 [4.1-A1]: No IAM account password policy is defined. CSCF requires password policies to be technically enforced (§ Impl. Guidelines)."
}

# ============================================================================
# 4.1-A2: Minimum Password Length
# Source: CSCF v2026, § Implementation Guidelines (S1, S3)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"

	resource.values.minimum_password_length < 14

	msg := sprintf(
		"CSCF 4.1 [4.1-A2]: Password min length is %d, must be >= 14 (§ Impl. Guidelines). (resource: %s)",
		[resource.values.minimum_password_length, resource.address],
	)
}

# ============================================================================
# 4.1-A3: Require Uppercase
# Source: CSCF v2026, § Implementation Guidelines (S1)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"
	not resource.values.require_uppercase_characters == true

	msg := sprintf(
		"CSCF 4.1 [4.1-A3]: Password policy does not require uppercase (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A4: Require Lowercase
# Source: CSCF v2026, § Implementation Guidelines (S1)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"
	not resource.values.require_lowercase_characters == true

	msg := sprintf(
		"CSCF 4.1 [4.1-A4]: Password policy does not require lowercase (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A5: Require Numbers
# Source: CSCF v2026, § Implementation Guidelines (S1)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"
	not resource.values.require_numbers == true

	msg := sprintf(
		"CSCF 4.1 [4.1-A5]: Password policy does not require numbers (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A6: Require Symbols
# Source: CSCF v2026, § Implementation Guidelines (S1)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"
	not resource.values.require_symbols == true

	msg := sprintf(
		"CSCF 4.1 [4.1-A6]: Password policy does not require symbols (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A7: Password Expiration
# Source: CSCF v2026, § Implementation Guidelines (S1)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"

	max_age := object.get(resource.values, "max_password_age", 0)
	max_age == 0

	msg := sprintf(
		"CSCF 4.1 [4.1-A7]: Password max age is 0 (never expires). Must be 1-90 days (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"

	max_age := resource.values.max_password_age
	max_age > 90

	msg := sprintf(
		"CSCF 4.1 [4.1-A7]: Password max age is %d days, must be <= 90 (§ Impl. Guidelines). (resource: %s)",
		[max_age, resource.address],
	)
}

# ============================================================================
# 4.1-A8: Password Reuse Prevention
# Source: CSCF v2026, § Implementation Guidelines (S1)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"

	reuse := object.get(resource.values, "password_reuse_prevention", 0)
	reuse < 12

	msg := sprintf(
		"CSCF 4.1 [4.1-A8]: Password reuse prevention is %d, must be >= 12 (§ Impl. Guidelines). (resource: %s)",
		[reuse, resource.address],
	)
}

# ============================================================================
# 4.1-A9: Hard Expiry Enforcement
# Source: CSCF v2026, § Implementation Guidelines (S1)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"
	not resource.values.hard_expiry == true

	msg := sprintf(
		"CSCF 4.1 [4.1-A9]: Hard expiry not enforced. Expired passwords must force change (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A10: User Self-Service Password Change
# Source: CSCF v2026, § Implementation Guidelines (S1)
# Scope: ACCT | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_account_password_policy"
	not resource.values.allow_users_to_change_password == true

	msg := sprintf(
		"CSCF 4.1 [4.1-A10]: Users cannot change own passwords. Lockout remedy required (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A11: Cognito User Pool Minimum Password Length
# Source: CSCF v2026, § Implementation Guidelines (S2, S7)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cognito_user_pool"
	helpers.is_swift_tagged(resource)

	pp := helpers.block(resource.values, "password_policy")
	min_len := object.get(pp, "minimum_length", 8)
	min_len < 14

	msg := sprintf(
		"CSCF 4.1 [4.1-A11]: Cognito password min length is %d, must be >= 14 (§ Impl. Guidelines). (resource: %s)",
		[min_len, resource.address],
	)
}

# ============================================================================
# 4.1-A12: Cognito User Pool Complexity Requirements
# Source: CSCF v2026, § Implementation Guidelines (S1, S2)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cognito_user_pool"
	helpers.is_swift_tagged(resource)

	pp := helpers.block(resource.values, "password_policy")
	_missing_cognito_complexity(pp)

	msg := sprintf(
		"CSCF 4.1 [4.1-A12]: Cognito does not require all character types (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

_missing_cognito_complexity(pp) if { not object.get(pp, "require_uppercase", false) == true }
_missing_cognito_complexity(pp) if { not object.get(pp, "require_lowercase", false) == true }
_missing_cognito_complexity(pp) if { not object.get(pp, "require_numbers", false) == true }
_missing_cognito_complexity(pp) if { not object.get(pp, "require_symbols", false) == true }

# ============================================================================
# 4.1-A13: Cognito Temporary Password Validity
# Source: CSCF v2026, § Implementation Guidelines (S1, S2)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cognito_user_pool"
	helpers.is_swift_tagged(resource)

	pp := helpers.block(resource.values, "password_policy")
	temp_days := object.get(pp, "temporary_password_validity_days", 7)
	temp_days > 7

	msg := sprintf(
		"CSCF 4.1 [4.1-A13]: Cognito temp password validity is %d days, must be <= 7 (§ Impl. Guidelines). (resource: %s)",
		[temp_days, resource.address],
	)
}

# ============================================================================
# 4.1-A14: RDS Secrets Manager Master Password
# Source: CSCF v2026, § Implementation Guidelines (S2, S5, S6)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_db_instance"
	helpers.is_swift_tagged(resource)

	not resource.values.manage_master_user_password == true

	msg := sprintf(
		"CSCF 4.1 [4.1-A14]: RDS not using Secrets Manager for master password (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A15: Redshift Secrets Manager Master Password
# Source: CSCF v2026, § Implementation Guidelines (S2, S5, S6)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_redshift_cluster"
	helpers.is_swift_tagged(resource)

	not resource.values.manage_master_password == true

	msg := sprintf(
		"CSCF 4.1 [4.1-A15]: Redshift not using Secrets Manager for master password (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A16: Secrets Manager Rotation Schedule
# Source: CSCF v2026, § Implementation Guidelines (S1, S2)
# Scope: TAG (via secret) | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_secretsmanager_secret_rotation"
	parent_scope.parent_swift_tagged(resource, "secret_id", "aws_secretsmanager_secret")

	rotation_rules := helpers.block(resource.values, "rotation_rules")
	auto_days := object.get(rotation_rules, "automatically_after_days", 0)
	auto_days > 90

	msg := sprintf(
		"CSCF 4.1 [4.1-A16]: Secrets rotation is %d days, must be <= 90 (§ Impl. Guidelines). (resource: %s)",
		[auto_days, resource.address],
	)
}

# ============================================================================
# 4.1-A17: OpenSearch Fine-Grained Access Control
# Source: CSCF v2026, § Implementation Guidelines (S2, S4, S7)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_opensearch_domain"
	helpers.is_swift_tagged(resource)

	aso := helpers.block(resource.values, "advanced_security_options")
	not aso.enabled == true

	msg := sprintf(
		"CSCF 4.1 [4.1-A17]: OpenSearch fine-grained access control not enabled (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A18: OpenSearch Master User Configuration
# Source: CSCF v2026, § Implementation Guidelines (S2, S7)
# Scope: TAG | Variant: F (conditional)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_opensearch_domain"
	helpers.is_swift_tagged(resource)

	aso := helpers.block(resource.values, "advanced_security_options")
	aso.enabled == true
	aso.internal_user_database_enabled == true

	master_opts := helpers.block(aso, "master_user_options")
	master_name := object.get(master_opts, "master_user_name", "")
	master_name == ""

	msg := sprintf(
		"CSCF 4.1 [4.1-A18]: OpenSearch internal user DB enabled but no master user configured (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.1-A19: Static IAM Access Key Warning
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: ACCT | Variant: B (presence check, should not exist)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_iam_access_key"

	user := object.get(resource.values, "user", "unknown")

	msg := sprintf(
		"CSCF 4.1 [4.1-A19]: Static IAM access key defined for user '%s'. Use role-based credentials or Secrets Manager with rotation (§ Impl. Guidelines). (resource: %s)",
		[user, resource.address],
	)
}
