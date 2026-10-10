# SWIFT CSCF v2026, Control 2.3: System Hardening
# Framework v1.2.1: Phase II (new control; see translations/ctrl_2_3_translation.md)
# Assertions: 2.3-A1 through 2.3-A4 (4 deny rules)
# Control Objective: Reduce the cyber-attack surface of Swift-related components by
#   performing system hardening.
#
# Most hardening is OS-host runtime. Unnecessary ports/services -> 1.1, default
# passwords -> 4.1/5.4, auto-lock -> 2.6 (all XREF/excluded). The rules below
# cover the net-new cloud attack-surface reduction (the "adjust vulnerable default
# configurations" minimum): no public exposure and no privileged containers.
# Uses the shared helpers.

package swift_cscf.v2026.ctrl_2_3

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 2.3-A1: Swift RDS instances are not publicly accessible
# Source: CSCF v2026, § adjust vulnerable default configurations
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_db_instance"
	helpers.is_swift_tagged(resource)

	resource.values.publicly_accessible == true

	msg := sprintf(
		"CSCF 2.3 [2.3-A1]: RDS instance is publicly accessible; attack surface must be minimised (§ adjust vulnerable defaults). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 2.3-A2: S3 public-access blocks enable all four settings
# Source: CSCF v2026, § adjust vulnerable default configurations
# Scope: ACCT | Variant: A  (the resource type carries no tags)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_s3_bucket_public_access_block"

	not _all_public_access_blocked(resource)

	msg := sprintf(
		"CSCF 2.3 [2.3-A2]: S3 public-access block does not enable all four settings; public exposure is not fully blocked (§ adjust vulnerable defaults). (resource: %s)",
		[resource.address],
	)
}

_all_public_access_blocked(resource) if {
	resource.values.block_public_acls == true
	resource.values.block_public_policy == true
	resource.values.ignore_public_acls == true
	resource.values.restrict_public_buckets == true
}

# ============================================================================
# 2.3-A3: Swift OpenSearch domains are VPC-attached (no public endpoint)
# Source: CSCF v2026, § adjust vulnerable default configurations
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_opensearch_domain"
	helpers.is_swift_tagged(resource)

	not _in_vpc(resource)

	msg := sprintf(
		"CSCF 2.3 [2.3-A3]: OpenSearch domain is not VPC-attached (public endpoint); attack surface must be minimised (§ adjust vulnerable defaults). (resource: %s)",
		[resource.address],
	)
}

_in_vpc(resource) if {
	vpc := resource.values.vpc_options[_]
	count(vpc.subnet_ids) > 0
}

# ============================================================================
# 2.3-A4: Swift ECS task definitions run no privileged containers
# Source: CSCF v2026, § least privilege (disable unnecessary capabilities)
# Scope: TAG | Variant: C (JSON parse)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_ecs_task_definition"
	helpers.is_swift_tagged(resource)

	containers := json.unmarshal(resource.values.container_definitions)
	container := containers[_]
	container.privileged == true

	msg := sprintf(
		"CSCF 2.3 [2.3-A4]: ECS task definition runs a privileged container ('%s'); disable unnecessary capabilities (§ least privilege). (resource: %s)",
		[object.get(container, "name", "unknown"), resource.address],
	)
}
