# SWIFT CSCF v2026, Control 4.2: Multi-Factor Authentication
# Framework v1.2.1: Phase II (new control; see translations/ctrl_4_2_translation.md)
# Assertions: 4.2-A1 through 4.2-A4 (4 deny rules)
# Control Objective: Prevent that a compromise of a single authentication factor
#   allows access into Swift-related systems by implementing MFA.
#
# Infrastructure-layer MFA (assume-role MFA -> 1.1-A12, MFA-deny policy ->
# 1.1-A14, MFA-capable VPN -> 1.1-A10) is owned by Control 1.1 and XREF-excluded;
# OS / vendor-interface MFA is not plan-evaluable. The rules below cover the
# net-new end-user / application authentication surface: Cognito, RDS IAM auth,
# and OpenSearch federated auth. Uses the shared helpers.

package swift_cscf.v2026.ctrl_4_2

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 4.2-A1: Cognito user pools enforce MFA (mfa_configuration == "ON")
# Source: CSCF v2026, § Control Statement (MFA for interactive user access)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cognito_user_pool"
	helpers.is_swift_tagged(resource)

	mfa := object.get(resource.values, "mfa_configuration", "OFF")
	mfa != "ON"

	msg := sprintf(
		"CSCF 4.2 [4.2-A1]: Cognito user pool does not enforce MFA (mfa_configuration='%s'); interactive user access requires MFA (§ Control Statement). (resource: %s)",
		[mfa, resource.address],
	)
}

# ============================================================================
# 4.2-A2: Cognito user pools enable a TOTP software-token second factor
# Source: CSCF v2026, § guidelines (strong possession factor; SMS-only insufficient)
# Scope: TAG | Variant: A  (absence of the block = violation)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_cognito_user_pool"
	helpers.is_swift_tagged(resource)

	not _totp_enabled(resource)

	msg := sprintf(
		"CSCF 4.2 [4.2-A2]: Cognito user pool does not enable a TOTP software-token second factor; a strong possession factor is required (SMS-only is insufficient) (§ guidelines). (resource: %s)",
		[resource.address],
	)
}

_totp_enabled(resource) if {
	cfg := resource.values.software_token_mfa_configuration[_]
	cfg.enabled == true
}

# ============================================================================
# 4.2-A3: RDS instances enable IAM database authentication
# Source: CSCF v2026, § Control Statement (login process to hosted database)
# Scope: TAG | Variant: A | Coverage: Partial (stronger-than-password auth)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_db_instance"
	helpers.is_swift_tagged(resource)

	object.get(resource.values, "iam_database_authentication_enabled", false) != true

	msg := sprintf(
		"CSCF 4.2 [4.2-A3]: RDS instance does not enable IAM database authentication; database login should not rely solely on a single static password (§ Control Statement). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 4.2-A4: OpenSearch domains use federated (Cognito/SAML) authentication
# Source: CSCF v2026, § Control Statement (login process to hosted application)
# Scope: TAG | Variant: A | Coverage: Partial (MFA-backed IdP signal)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_opensearch_domain"
	helpers.is_swift_tagged(resource)

	not _federated_auth(resource)

	msg := sprintf(
		"CSCF 4.2 [4.2-A4]: OpenSearch domain does not use federated (Cognito/SAML) authentication; dashboard access should be MFA-backed via an IdP, not an internal user database alone (§ Control Statement). (resource: %s)",
		[resource.address],
	)
}

_federated_auth(resource) if {
	resource.values.cognito_options[_].enabled == true
}

# SAML federation is a separate resource in the AWS provider, not a block inside
# advanced_security_options. The earlier form read a block the provider does not
# define, so this branch could never hold -- found by the Gate B admissibility
# check (pipeline/audit/gate_b_admissibility.py), the same defect class as the
# three re-scoped assertions in translations/binding_corrections.md.
_federated_auth(resource) if {
	saml := helpers.all_resources[_]
	saml.type == "aws_opensearch_domain_saml_options"
	saml.values.domain_name == resource.values.domain_name
	saml.values.saml_options[_].enabled == true
}
