# SWIFT CSCF v2026, Control 1.4: Restriction of Internet Access
# Framework v1.2.1: Phase II (new control; see translations/ctrl_1_4_translation.md)
# Assertions: 1.4-A1 through 1.4-A6 (7 deny rules; A3 has IPv4 + IPv6)
# Control Objective: Control/Protect Internet access from operator PCs and
#   systems within the secure zone.
#
# Uses the shared helpers package. Requirements
# already covered by Control 1.1 (IGW routes, public-IP subnets, all-protocol
# egress, NACL egress) are intentionally NOT re-implemented here, see the
# XREF exclusions in the applied-translation document.

package swift_cscf.v2026.ctrl_1_4

import rego.v1

import data.swift_cscf.v2026.helpers
import data.swift_cscf.v2026.parent_scope
import data.swift_cscf.v2026.zone_scope

# ============================================================================
# 1.4-A1: No default route to a NAT gateway (uncontrolled IPv4 Internet egress)
# Source: CSCF v2026, § a) Internet access from the secure zone
# Scope: VPC | Variant: A
# ============================================================================

deny contains msg if {
	route := helpers.all_resources[_]
	route.type == "aws_route"
	parent_scope.route_in_swift_vpc(route)

	object.get(route.values, "destination_cidr_block", "") == "0.0.0.0/0"

	nat_gateway_id := object.get(route.values, "nat_gateway_id", "")
	nat_gateway_id != ""

	msg := sprintf(
		"CSCF 1.4 [1.4-A1]: Secure-zone route sends all IPv4 traffic (0.0.0.0/0) to a NAT gateway. Internet access from the secure zone must be highly restricted or blocked (§ a). (resource: %s)",
		[route.address],
	)
}

# ============================================================================
# 1.4-A2: No default route to an egress-only Internet gateway (IPv6 egress)
# Source: CSCF v2026, § a) Internet access from the secure zone
# Scope: VPC | Variant: A
# ============================================================================

deny contains msg if {
	route := helpers.all_resources[_]
	route.type == "aws_route"
	parent_scope.route_in_swift_vpc(route)

	object.get(route.values, "destination_ipv6_cidr_block", "") == "::/0"

	eigw_id := object.get(route.values, "egress_only_gateway_id", "")
	eigw_id != ""

	msg := sprintf(
		"CSCF 1.4 [1.4-A2]: Secure-zone route sends all IPv6 traffic (::/0) to an egress-only Internet gateway (§ a). (resource: %s)",
		[route.address],
	)
}

# ============================================================================
# 1.4-A3: No security-group egress permitting direct HTTP/HTTPS to the Internet
# Source: CSCF v2026, § a) (no general-purpose browsing), § b)
# Scope: VPC | Variant: A  (IPv4 + IPv6)
# Note: 1.1-A4 already denies all-protocol (-1) unrestricted egress; A3 targets
#       the browsing-port (80/443) case that survives that rule.
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_security_group"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.egress[_]
	browsing_port := {80, 443}[_]
	helpers.port_in_range(rule.from_port, rule.to_port, browsing_port)

	cidr_blocks := object.get(rule, "cidr_blocks", [])
	helpers.has_unrestricted_cidr(cidr_blocks)

	msg := sprintf(
		"CSCF 1.4 [1.4-A3]: Security group allows direct outbound port %d to 0.0.0.0/0. Internet browsing/egress from the secure zone must go through a controlled proxy (§ a). (resource: %s)",
		[browsing_port, resource.address],
	)
}

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_security_group"
	zone_scope.in_swift_zone(resource)

	rule := resource.values.egress[_]
	browsing_port := {80, 443}[_]
	helpers.port_in_range(rule.from_port, rule.to_port, browsing_port)

	ipv6_blocks := object.get(rule, "ipv6_cidr_blocks", [])
	helpers.has_unrestricted_ipv6_cidr(ipv6_blocks)

	msg := sprintf(
		"CSCF 1.4 [1.4-A3]: Security group allows direct outbound port %d to ::/0 (IPv6). Internet browsing/egress from the secure zone must go through a controlled proxy (§ a). (resource: %s)",
		[browsing_port, resource.address],
	)
}

# ============================================================================
# 1.4-A4: The secure zone provides at least one VPC endpoint
# Source: CSCF v2026, § a) (activities requiring Internet conducted outside), § b)
# Scope: VPC | Variant: B (presence)  | Coverage: Partial (positive signal)
# ============================================================================

deny contains msg if {
	count([r |
		r := helpers.all_resources[_]
		r.type == "aws_vpc_endpoint"
		zone_scope.in_swift_zone(r)
	]) == 0

	msg := "CSCF 1.4 [1.4-A4]: No VPC endpoint is configured. AWS-service access from the secure zone should use VPC endpoints rather than egressing to the Internet (§ a, § b)."
}

# ============================================================================
# 1.4-A5: Jump-server / operator instances do not auto-assign a public IP
# Source: CSCF v2026, § a) (jump server no Internet), § b) (operator PCs)
# Scope: TAG (swift:zone=secure AND swift:role=jump_server) | Variant: A
# ============================================================================

deny contains msg if {
	resource := helpers.all_resources[_]
	resource.type == "aws_instance"
	helpers.is_swift_tagged(resource)
	_is_jump_server(resource)

	resource.values.associate_public_ip_address == true

	msg := sprintf(
		"CSCF 1.4 [1.4-A5]: Jump-server/operator instance auto-assigns a public IP. It must have no direct Internet exposure (§ a, § b). (resource: %s)",
		[resource.address],
	)
}

# ============================================================================
# 1.4-A6: A jump server's security groups do not permit Internet egress
# Source: CSCF v2026, § a) (the jump server does not have internet access)
# Scope: TAG (swift:role=jump_server) | Variant: E (cross-resource relationship)
# Limitation: relies on SG ids being present in the plan (known-after-apply nulls
#   in a fresh terraform plan will suppress this rule), see translation doc.
# ============================================================================

deny contains msg if {
	instance := helpers.all_resources[_]
	instance.type == "aws_instance"
	_is_jump_server(instance)

	sg_id := instance.values.vpc_security_group_ids[_]

	sg := helpers.all_resources[_]
	sg.type == "aws_security_group"
	sg.values.id == sg_id

	rule := sg.values.egress[_]
	cidr_blocks := object.get(rule, "cidr_blocks", [])
	helpers.has_unrestricted_cidr(cidr_blocks)

	msg := sprintf(
		"CSCF 1.4 [1.4-A6]: Jump server's security group permits outbound Internet access (0.0.0.0/0). The jump server must have no Internet access (§ a). (resource: %s, sg: %s)",
		[instance.address, sg.address],
	)
}

# Jump-server / operator-host role tag introduced by Control 1.4
_is_jump_server(resource) if {
	resource.values.tags["swift:role"] == "jump_server"
}

_is_jump_server(resource) if {
	resource.values.tags_all["swift:role"] == "jump_server"
}
