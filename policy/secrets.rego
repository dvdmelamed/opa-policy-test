package secrets

files_blacklist = [
  "serverless.yml"
]

deny[msg] {
  some i
    input.RuleID == "aws-access-token"
    files_blacklist[i] == input.File
    msg := sprintf("AWS secret found in file %v", [input.File])
}
