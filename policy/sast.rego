package sast

deny[msg] {
  input.metrics._totals["SEVERITY.MEDIUM"] > 0
  msg := sprintf(”SAST Test failed: %s medium severities", [input.metrics._totals["SEVERITY.MEDIUM"])}
}
