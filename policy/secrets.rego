package secrets

files_blacklist = [
  "serverless.yml"
]

deny[msg] {
  some i
    files_blacklist[i] == input.File
    msg := sprintf("Secret found in file %v", [input.File])
}

deny[msg] {
  some i
    input.RuleID == "aws-access-token"
    msg := sprintf("AWS secret found in file %v", [input.File])
}
