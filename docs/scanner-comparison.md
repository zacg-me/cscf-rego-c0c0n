# What a per-resource scanner sees

*Checkov 3.3.20, 29 September 2026. Reproducible with the files in
`scanner-probe/`.*

Checkov is a widely used, open-source infrastructure-as-code scanner. It is very
good at what it is built for: checking one resource at a time against a large
catalogue of hardening rules. This page records what it reports on the case this
library was built for (a grant that crosses the Swift trust boundary) and one
thing it computes and does not report. It is not a criticism of Checkov; the two
tools answer different questions, and both belong in a pipeline.

## 1. The partner grant (CR-2107)

The change adds a Swift-zone bucket, enforces TLS, uses no wildcard principal,
and grants a partner account (`444455556666`) read access. The declared trust
boundary is the Swift account and its DR account.

**This gate:** blocked, one finding, 1.1-A15:
`S3 bucket policy grants account 444455556666, outside the declared Swift trust boundary`.

**Checkov** (`checkov -d terraform/compliant --framework terraform`), every
result naming the new resources:

| Result | Check | Resource |
|---|---|---|
| **PASSED** | **CKV_AWS_70**, "Ensure S3 bucket does not allow an action with any Principal" | **aws_s3_bucket_policy.reporting_partner** |
| **PASSED** | CKV_AWS_93, bucket policy does not lock out all but root | aws_s3_bucket_policy.reporting_partner |
| PASSED | CKV_AWS_19, CKV_AWS_20, CKV_AWS_57, CKV_AWS_93 | aws_s3_bucket.reporting_partner |
| FAILED | CKV2_AWS_6, CKV2_AWS_61, CKV2_AWS_62, CKV_AWS_18, CKV_AWS_21, CKV_AWS_144, CKV_AWS_145 | aws_s3_bucket.reporting_partner |
| UNKNOWN (not reported) | CKV_AWS_70, CKV_AWS_143 | aws_s3_bucket.reporting_partner |

Checkov passes the policy. Its seven failures are bucket hygiene, public-access
block, lifecycle, event notifications, access logging, versioning, replication,
KMS, and none concerns the account the policy lets in. That is not a gap in
Checkov's catalogue: whether `444455556666` is allowed depends on the bucket's
zone and on a boundary the institution declares, which no single-resource check
can see. (The two UNKNOWN results are benign here: CKV_AWS_70 on an
`aws_s3_bucket` returns UNKNOWN when the bucket has no inline policy.)

A note for anyone repeating this: `--quiet` suppresses passed checks, so a quiet
run shows the seven bucket failures and nothing at all for the policy.

## 2. "Unknown" is computed, and discarded

Checkov has a fourth result besides passed, failed and skipped. Its enum
(`checkov/common/models/enums.py`) documents it:

> Unknown should be used when a check does not wish to return a result,
> generally due to the inability to resolve a value or similar types of errors.

The report (`checkov/common/output/report.py`, `Report.add_record`) keeps
PASSED, FAILED and SKIPPED; an UNKNOWN result is neither printed nor counted.

The probe (`scanner-probe/main.tf`) is a bucket policy that grants
`s3:GetObject` to **any principal**, written with `data.aws_iam_policy_document`
-the policy CKV_AWS_70 exists to catch. CKV_AWS_70 returns UNKNOWN for policies
built from a policy-document data source, and the result is discarded:

```bash
checkov -d docs/scanner-probe --framework terraform --check CKV_AWS_70 -o json
# summary: passed 0, failed 0, skipped 0, exit code 0

python docs/scanner-probe/checkov_all_results.py docs/scanner-probe probe
# UNKNOWN (discarded before reporting):
#   CKV_AWS_70  aws_s3_bucket_policy.probe
```

A world-readable bucket, and the pipeline is green. The check knew it could not
decide; the report does not say so.

This library's gate reports the same situation as **undetermined** (in the
console, in the signed evidence and in the attestation) and
`--fail-on-undetermined` blocks on it. "Could not decide" is a verdict, not an
absence.

## Other tools (checked 29 September 2026)

| Tool | Result vocabulary | "Could not be determined" reported? |
|---|---|---|
| Trivy (successor to tfsec) | PASS / FAIL / EXCEPTION | No such status |
| HashiCorp Sentinel | policy true / false | An undefined main rule is treated as `false` - folded into failure |
| AWS CloudFormation Guard | PASS / FAIL / SKIP | SKIP means the rule was not triggered (not applicable) |
