"""Every Checkov result, including the UNKNOWN ones its report discards.

Run with the Python that has Checkov installed:

    python docs/scanner-probe/checkov_all_results.py <terraform dir> [name filter]

Checkov's Report.add_record keeps PASSED, FAILED and SKIPPED results only; a
check that returns UNKNOWN ("inability to resolve a value", per Checkov's own
enum) is neither printed nor counted. This script records every result before
that filter.
"""
import sys

from checkov.common.output import report as report_module
from checkov.runner_filter import RunnerFilter
from checkov.terraform.runner import Runner

records = []
original = report_module.Report.add_record


def spy(self, record):
    result = record.check_result["result"]
    records.append((str(getattr(result, "value", result)), record.check_id, record.resource))
    return original(self, record)


report_module.Report.add_record = spy
Runner().run(root_folder=sys.argv[1], runner_filter=RunnerFilter(framework=["terraform"]))
name = sys.argv[2] if len(sys.argv) > 2 else ""

print("UNKNOWN (discarded before reporting):")
for _, check_id, resource in sorted(r for r in records if r[0] == "UNKNOWN" and name in r[2]):
    print(f"  {check_id}  {resource}")
print(f"All results{' naming ' + name if name else ''}:")
for result, check_id, resource in sorted(r for r in records if name in r[2]):
    print(f"  {result:8} {check_id}  {resource}")
