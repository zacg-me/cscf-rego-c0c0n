# SWIFT CSCF v2026, Control 1.3: Virtualisation or Cloud Platform Protection
# Framework v1.2.1: Phase II (new control; see translations/ctrl_1_3_translation.md)
# Assertions: 1.3-A1 through 1.3-A5 (5 deny rules)
# Control Objective: Secure the virtualisation/cloud platform and VMs that host
#   Swift-related components to the same level as physical systems.
#
# 1.3 is a meta-control: most of its guidelines re-apply other controls to the
# virtualisation layer (secure zone -> 1.1, privileged access -> 1.2, password ->
# 4.1, MFA -> 4.2, updates -> 2.2, internet -> 1.4, vuln scan -> 2.7, physical ->
# 3.1) and are XREF-excluded. The rules below cover the net-new automatable
# surface: VM / cloud-platform hardening (metadata service, disk encryption at
# rest, tenancy isolation). Uses the shared helpers.

package swift_cscf.v2026.ctrl_1_3

import rego.v1

import data.swift_cscf.v2026.helpers

# ============================================================================
# 1.3-A1: Swift VMs enforce IMDSv2 (token-required instance metadata)
# Source: CSCF v2026, § guidelines (secure VMs to same level; prevent lateral move)
# Scope: TAG | Variant: A  (absence of the setting is itself a violation)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_instance"
	helpers.is_swift_tagged(resource)

	not _imdsv2_required(resource)

	msg := sprintf(
		"CSCF 1.3 [1.3-A1]: VM does not enforce IMDSv2 (token-required metadata). The instance metadata service is a credential-theft / lateral-movement vector (§ guidelines). (resource: %s)",
		[resource.address],
	)
}

_imdsv2_required(resource) if {
	opt := resource.values.metadata_options[_]
	opt.http_tokens == "required"
}

# ============================================================================
# 1.3-A2: Swift VMs restrict the IMDS hop limit to 1
# Source: CSCF v2026, § guidelines (VM isolation / prevent lateral move)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_instance"
	helpers.is_swift_tagged(resource)

	opt := resource.values.metadata_options[_]
	opt.http_put_response_hop_limit > 1

	msg := sprintf(
		"CSCF 1.3 [1.3-A2]: VM allows an IMDS hop limit of %d (> 1), enabling metadata relay beyond the instance to containers/proxies (§ guidelines). (resource: %s)",
		[opt.http_put_response_hop_limit, resource.address],
	)
}

# ============================================================================
# 1.3-A3: Swift VM root volumes are encrypted at rest
# Source: CSCF v2026, § guidelines (secure VMs to same level as physical)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_instance"
	helpers.is_swift_tagged(resource)

	rbd := resource.values.root_block_device[_]
	rbd.encrypted != true

	msg := sprintf(
		"CSCF 1.3 [1.3-A3]: VM root volume is not encrypted at rest (§ guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 1.3-A4: Swift EBS volumes are encrypted at rest
# Source: CSCF v2026, § guidelines (secure VMs to same level as physical)
# Scope: TAG | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_ebs_volume"
	helpers.is_swift_tagged(resource)

	resource.values.encrypted != true

	msg := sprintf(
		"CSCF 1.3 [1.3-A4]: Swift EBS volume is not encrypted at rest (§ guidelines). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 1.3-A5: Swift VMs use dedicated or host tenancy (platform-level VM isolation)
# Source: CSCF v2026, § guidelines (VM isolation to prevent lateral move)
# Scope: TAG | Variant: A | Coverage: Partial (tenancy is one facet of isolation)
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_instance"
	helpers.is_swift_tagged(resource)

	tenancy := object.get(resource.values, "tenancy", "default")
	not tenancy in {"dedicated", "host"}

	msg := sprintf(
		"CSCF 1.3 [1.3-A5]: VM uses '%s' tenancy; platform-level VM isolation for the Swift secure zone requires dedicated or host tenancy (§ guidelines). (resource: %s)",
		[tenancy, resource.address],
	)
}
