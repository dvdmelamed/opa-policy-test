package main

files_blacklist = [
  "serverless.yml"
]

deny[msg] {
  some i, j
    input[i].RuleID == "aws-access-token"
    files_blacklist[j] == input[i].File
    msg := sprintf("AWS secret found in file %v", [input[i].File])
}
