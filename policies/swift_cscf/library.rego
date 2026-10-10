# SWIFT CSCF policy library: version record
#
# The gate reads this package and writes it into every evidence artefact, so an
# attestation always names the library that produced it.
#
#   1.0.0  First research library (5 controls); not published here. Its
#          defects and their corrections: docs/failure-modes.md.
#   2.0.0  Re-issue: the Phase I controls corrected and merged with the Phase II
#          controls into one library. Every change is listed, by assertion id,
#          in ../CHANGELOG.md. Assertion ids and finding messages are unchanged,
#          so a finding from either version still resolves to the same
#          regulatory requirement.
#   2.1.0  Adds 1.1-A15 (bucket policy principal outside the Swift trust boundary)
#   2.1.1  1.1-A15 also covers Federated, CanonicalUser and Allow+NotPrincipal grants
#   2.1.2  Plain punctuation in comments and messages; no rule changes

package swift_cscf.library

import rego.v1

version := "2.1.2"

supersedes := "2.1.1"
