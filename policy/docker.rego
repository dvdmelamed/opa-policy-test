package main

deny[msg] {
	endswith(input.services[_].image, ":latest")
	msg = "No images tagged latest"
}

deny[msg] {
	semver.compare(input.version, "3.5") < 1
	msg = sprintf("Must be using at least version 3.5 of the Compose file format, found %v", [semver.compare(input.version, "3.5")])
}
