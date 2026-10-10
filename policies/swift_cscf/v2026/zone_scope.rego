# SWIFT CSCF v2026: Zone membership for VPC-scoped assertions
# Framework: LCT v2.0, Binding plane
#
# `helpers.is_in_swift_vpc` compares a resource's `vpc_id` against
# `input.swift_vpc_id` - a field no Terraform plan carries. The resolvability
# pass supplies it for generated plans, but a hand-written fixture or a plan
# evaluated without that pass has no binding, and the predicate then matches
# nothing: every VPC-scoped rule passes silently. That is the fail-open pattern
# this project exists to remove, reappearing in the scope filter itself.
#
# This predicate holds when either signal is available, so a VPC-scoped rule
# narrows correctly when the binding is present and still applies when only the
# zone tag is.

package swift_cscf.v2026.zone_scope

import rego.v1

import data.swift_cscf.v2026.helpers

in_swift_zone(resource) if {
	helpers.is_in_swift_vpc(resource)
}

in_swift_zone(resource) if {
	helpers.is_swift_tagged(resource)
}
