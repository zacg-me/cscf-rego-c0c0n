# SWIFT CSCF v2026, Control 2.1: Internal Data Flow Security
# Policy library 2.0.0 (re-issue of the Phase I control; see ../../CHANGELOG.md)
# Assertions: 2.1-A1 through 2.1-A16
# Control Objective: Ensure the confidentiality, integrity, and authenticity
#   of application data flows between user's Swift-related components.
#
# Every rule applies the TAG scope its header declares. The two policy
# attachments (EFS file-system policy, S3 bucket policy) take no tags, so they
# are scoped by the resource they protect.

package swift_cscf.v2026.ctrl_2_1

import rego.v1

import data.swift_cscf.v2026.helpers
import data.swift_cscf.v2026.parent_scope

# ============================================================================
# 2.1-A1: Load Balancer Listener Protocol
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_lb_listener"
	helpers.is_swift_tagged(resource)

	not resource.values.protocol in {"HTTPS", "TLS"}

	msg := sprintf(
		"CSCF 2.1 [2.1-A1]: Load balancer listener uses unencrypted protocol '%s'. All Swift data flows must use TLS (§ Impl. Guidelines). (resource: %s)",
		[resource.values.protocol, resource.address],
	)
}

# ============================================================================
# 2.1-A2: Load Balancer TLS Policy Version
# Source: CSCF v2026, § Implementation Guidelines (S3)
# Scope: TAG | Variant: F (conditional)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_lb_listener"
	helpers.is_swift_tagged(resource)

	resource.values.protocol in {"HTTPS", "TLS"}
	ssl_policy := object.get(resource.values, "ssl_policy", "")
	not ssl_policy in helpers.approved_tls_policies

	msg := sprintf(
		"CSCF 2.1 [2.1-A2]: SSL policy '%s' does not enforce TLS 1.2+ with current algorithms (§ Impl. Guidelines). (resource: %s)",
		[ssl_policy, resource.address],
	)
}

# ============================================================================
# 2.1-A3: RDS PostgreSQL Force SSL
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_db_parameter_group"
	helpers.is_swift_tagged(resource)

	startswith(resource.values.family, "postgres")
	not _has_parameter(object.get(resource.values, "parameter", []), "rds.force_ssl", "1")

	msg := sprintf(
		"CSCF 2.1 [2.1-A3]: PostgreSQL parameter group does not enforce SSL (rds.force_ssl != 1) (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 2.1-A4: RDS MySQL/MariaDB Force SSL
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_db_parameter_group"
	helpers.is_swift_tagged(resource)

	_is_mysql_family(resource.values.family)
	not _has_parameter(object.get(resource.values, "parameter", []), "require_secure_transport", "1")

	msg := sprintf(
		"CSCF 2.1 [2.1-A4]: MySQL/MariaDB parameter group does not enforce SSL (require_secure_transport != 1) (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

_is_mysql_family(family) if { startswith(family, "mysql") }
_is_mysql_family(family) if { startswith(family, "mariadb") }
_is_mysql_family(family) if { startswith(family, "aurora-mysql") }

# ============================================================================
# 2.1-A5: Redshift Require SSL
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_redshift_parameter_group"
	helpers.is_swift_tagged(resource)

	not _has_parameter(object.get(resource.values, "parameter", []), "require_ssl", "true")

	msg := sprintf(
		"CSCF 2.1 [2.1-A5]: Redshift parameter group does not enforce SSL (require_ssl != true) (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# Shared helper: check if a parameter list contains a specific name=value
_has_parameter(params, name, value) if {
	param := params[_]
	param.name == name
	param.value == value
}

# ============================================================================
# 2.1-A6: ElastiCache Transit Encryption
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_elasticache_replication_group"
	helpers.is_swift_tagged(resource)

	not resource.values.transit_encryption_enabled == true

	msg := sprintf(
		"CSCF 2.1 [2.1-A6]: ElastiCache does not enforce in-transit encryption (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 2.1-A7: MSK Client-to-Broker TLS
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_msk_cluster"
	helpers.is_swift_tagged(resource)

	info := helpers.block(resource.values, "encryption_info")
	transit := helpers.block(info, "encryption_in_transit")
	client_broker := object.get(transit, "client_broker", "TLS_PLAINTEXT")
	client_broker != "TLS"

	msg := sprintf(
		"CSCF 2.1 [2.1-A7]: MSK allows non-TLS client-broker communication ('%s'). Must be 'TLS' (§ Impl. Guidelines). (resource: %s)",
		[client_broker, resource.address],
	)
}

# ============================================================================
# 2.1-A8: MSK In-Cluster Encryption
# Source: CSCF v2026, § Implementation Guidelines (S1, S2, S5)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_msk_cluster"
	helpers.is_swift_tagged(resource)

	info := helpers.block(resource.values, "encryption_info")
	transit := helpers.block(info, "encryption_in_transit")
	in_cluster := object.get(transit, "in_cluster", false)
	in_cluster != true

	msg := sprintf(
		"CSCF 2.1 [2.1-A8]: MSK does not encrypt inter-broker traffic (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 2.1-A9: OpenSearch Enforce HTTPS
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_opensearch_domain"
	helpers.is_swift_tagged(resource)

	endpoint_opts := helpers.block(resource.values, "domain_endpoint_options")
	not endpoint_opts.enforce_https == true

	msg := sprintf(
		"CSCF 2.1 [2.1-A9]: OpenSearch does not enforce HTTPS (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 2.1-A10: OpenSearch TLS Policy Version
# Source: CSCF v2026, § Implementation Guidelines (S3)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_opensearch_domain"
	helpers.is_swift_tagged(resource)

	endpoint_opts := helpers.block(resource.values, "domain_endpoint_options")
	tls_policy := object.get(endpoint_opts, "tls_security_policy", "")
	not tls_policy in helpers.approved_opensearch_tls_policies

	msg := sprintf(
		"CSCF 2.1 [2.1-A10]: OpenSearch TLS policy '%s' does not enforce TLS 1.2+ (§ Impl. Guidelines). (resource: %s)",
		[tls_policy, resource.address],
	)
}

# ============================================================================
# 2.1-A11: OpenSearch Node-to-Node Encryption
# Source: CSCF v2026, § Implementation Guidelines (S1, S2, S5)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_opensearch_domain"
	helpers.is_swift_tagged(resource)

	n2n := helpers.block(resource.values, "node_to_node_encryption")
	not n2n.enabled == true

	msg := sprintf(
		"CSCF 2.1 [2.1-A11]: OpenSearch does not encrypt node-to-node traffic (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 2.1-A12: EFS Transit Encryption Policy
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: TAG (via file system) | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_efs_file_system_policy"
	parent_scope.parent_swift_tagged(resource, "file_system_id", "aws_efs_file_system")

	policy := json.unmarshal(resource.values.policy)
	not _has_secure_transport_deny(policy)

	msg := sprintf(
		"CSCF 2.1 [2.1-A12]: EFS policy does not deny non-TLS access (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# A Deny on non-TLS requests. The condition value may be the JSON boolean false
# or the string "false"; library 1.0.0 accepted only the string (review R7).
_has_secure_transport_deny(policy) if {
	stmt := helpers.statements(policy)[_]
	stmt.Effect == "Deny"
	helpers.is_false(stmt.Condition.Bool["aws:SecureTransport"])
}

# ============================================================================
# 2.1-A13: API Gateway Minimum TLS Version
# Source: CSCF v2026, § Implementation Guidelines (S1, S3)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_api_gateway_domain_name"
	helpers.is_swift_tagged(resource)

	security_policy := object.get(resource.values, "security_policy", "TLS_1_0")
	security_policy != "TLS_1_2"

	msg := sprintf(
		"CSCF 2.1 [2.1-A13]: API Gateway domain does not enforce TLS 1.2 (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 2.1-A14: KMS Key Rotation
# Source: CSCF v2026, § Implementation Guidelines (S4)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_kms_key"
	helpers.is_swift_tagged(resource)

	not resource.values.enable_key_rotation == true

	msg := sprintf(
		"CSCF 2.1 [2.1-A14]: KMS key does not have automatic rotation enabled (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 2.1-A15: KMS Key Deletion Protection
# Source: CSCF v2026, § Implementation Guidelines (S4)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_kms_key"
	helpers.is_swift_tagged(resource)

	deletion_window := object.get(resource.values, "deletion_window_in_days", 30)
	deletion_window < 14

	msg := sprintf(
		"CSCF 2.1 [2.1-A15]: KMS key deletion window is %d days, minimum 14 required (§ Impl. Guidelines). (resource: %s)",
		[deletion_window, resource.address],
	)
}

# ============================================================================
# 2.1-A16: S3 Bucket TLS-Only Policy
# Source: CSCF v2026, § Implementation Guidelines (S1, S5)
# Scope: TAG (via bucket) | Variant: C (JSON parse)
# `aws_s3_bucket_policy` takes no tags, so scope comes from the bucket it
# attaches to (found on generated plans).
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_policy"
	parent_scope.in_swift_zone_via_bucket(resource)

	policy := json.unmarshal(resource.values.policy)
	not _has_secure_transport_deny(policy)

	msg := sprintf(
		"CSCF 2.1 [2.1-A16]: S3 bucket policy does not enforce TLS-only access (§ Impl. Guidelines). (resource: %s)",
		[resource.address],
	)
}
