package securityTests

# Block the pipeline when the scan reports any Critical issue.
# Attach this policy to a Policy Set: entity Security Tests, event On Step,
# action Error and exit.

deny[msg] {
  input[i].name == "output"
  critical := to_number(input[i].outcome.outputVariables.CRITICAL)
  critical > 0
  msg := sprintf("Fail: %d Critical issue(s). Threshold is 0.", [critical])
}
