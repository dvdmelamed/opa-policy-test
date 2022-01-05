package main

deny[msg] {
        endswith(input.services[_].image, ":latest")
        msg = "No images tagged latest"
}

deny[msg] {
        not semver.is_valid(input.version)
        msg = "Docker-compose file version is not valid"
}

deny[msg] {
        semver.compare(input.version, "3.5.0") <= 0
        msg = "Must be using at least version 3.5 of the Compose file format"
}
