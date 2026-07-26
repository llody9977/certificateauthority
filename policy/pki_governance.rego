package pki.governance

default allow = false

allow {
    count(violations) == 0
}

violations[msg] {
    input.validity_days > 825
    msg := sprintf("Validity period %d days exceeds maximum allowed 825 days", [input.validity_days])
}

violations[msg] {
    not valid_algorithm(input.algorithm)
    msg := sprintf("Algorithm '%s' is not in approved list", [input.algorithm])
}

violations[msg] {
    some san in input.sans
    startswith(san, "*.")
    san != "*.internal.domain"
    san != "*.local"
    msg := sprintf("Wildcard SAN '%s' is not permitted under corporate governance", [san])
}

valid_algorithm("RSA_2048")
valid_algorithm("RSA_4096")
valid_algorithm("ECDSA_P256")
valid_algorithm("ECDSA_P384")
