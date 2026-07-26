package pki.governance_test

import data.pki.governance

test_allow_valid_rsa_2048 {
    governance.allow with input as {
        "algorithm": "RSA_2048",
        "validity_days": 365,
        "sans": ["api.internal.domain"]
    }
}

test_allow_valid_ecdsa {
    governance.allow with input as {
        "algorithm": "ECDSA_P256",
        "validity_days": 90,
        "sans": ["service.local"]
    }
}

test_deny_exceeded_validity {
    not governance.allow with input as {
        "algorithm": "RSA_2048",
        "validity_days": 1000,
        "sans": ["test.local"]
    }
}

test_deny_unapproved_algorithm {
    not governance.allow with input as {
        "algorithm": "DES",
        "validity_days": 30,
        "sans": ["test.local"]
    }
}

test_deny_unauthorized_wildcard {
    not governance.allow with input as {
        "algorithm": "RSA_2048",
        "validity_days": 30,
        "sans": ["*.external.com"]
    }
}
