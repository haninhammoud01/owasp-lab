package security

############################
# DEFAULTS
############################

default allow_deployment := false
default deny := []
default warnings := []

############################
# DEPLOYMENT DECISION
############################

allow_deployment := true if {
    count(deny) == 0
    security_baseline_ok
}

############################
# SECURITY BASELINE
############################

security_baseline_ok if {
    no_critical_vulns
    high_vulns_within_limit
    coverage_ok
    complexity_ok
    tests_ok
}

############################
# DENY RULES
############################

deny contains msg if {
    input.vulnerabilities.critical[_]
    msg := "Critical vulnerabilities detected"
}

deny contains msg if {
    high_count := count(input.vulnerabilities.high)
    high_count > input.policy.max_high_severity
    msg := sprintf(
        "High severity vulnerabilities (%d) exceed allowed maximum (%d)",
        [high_count, input.policy.max_high_severity]
    )
}

deny contains msg if {
    input.code_quality.coverage < input.policy.min_coverage
    msg := sprintf(
        "Code coverage %d%% below required minimum %d%%",
        [input.code_quality.coverage, input.policy.min_coverage]
    )
}

deny contains msg if {
    input.code_quality.complexity > input.policy.max_complexity
    msg := sprintf(
        "Code complexity %d exceeds allowed maximum %d",
        [input.code_quality.complexity, input.policy.max_complexity]
    )
}

deny contains msg if {
    input.tests.passed < input.tests.total
    msg := sprintf(
        "Test failures detected (%d/%d passed)",
        [input.tests.passed, input.tests.total]
    )
}

############################
# WARNINGS (NON-BLOCKING)
############################

warnings contains msg if {
    count(input.vulnerabilities.medium) > 0
    msg := "Medium severity vulnerabilities detected"
}

############################
# HELPERS
############################

no_critical_vulns if {
    count(input.vulnerabilities.critical) == 0
}

high_vulns_within_limit if {
    count(input.vulnerabilities.high) <= input.policy.max_high_severity
}

coverage_ok if {
    input.code_quality.coverage >= input.policy.min_coverage
}

complexity_ok if {
    input.code_quality.complexity <= input.policy.max_complexity
}

tests_ok if {
    input.tests.passed == input.tests.total
}
