package security

import future.keywords.if
import future.keywords.in

default allow_deployment = false

allow_deployment if {
    not has_critical_vulnerabilities
    not has_high_severity_threshold_exceeded
    code_quality_met
    all_tests_passed
}

has_critical_vulnerabilities if {
    count(input.vulnerabilities.critical) > 0
}

has_high_severity_threshold_exceeded if {
    count(input.vulnerabilities.high) > input.policy.max_high_severity
}

code_quality_met if {
    input.code_quality.coverage >= input.policy.min_coverage
    input.code_quality.complexity <= input.policy.max_complexity
}

all_tests_passed if {
    input.tests.passed == input.tests.total
    input.tests.total > 0
}

deny[msg] {
    count(input.vulnerabilities.critical) > 0
    msg := sprintf(
        "Deployment blocked: %d critical vulnerabilities detected",
        [count(input.vulnerabilities.critical)]
    )
}

deny[msg] {
    high_count := count(input.vulnerabilities.high)
    high_count > input.policy.max_high_severity
    msg := sprintf(
        "Deployment blocked: %d high severity issues exceed limit of %d",
        [high_count, input.policy.max_high_severity]
    )
}

deny[msg] {
    input.code_quality.coverage < input.policy.min_coverage
    msg := sprintf(
        "Deployment blocked: Code coverage %d%% is below minimum %d%%",
        [input.code_quality.coverage, input.policy.min_coverage]
    )
}

warnings[msg] {
    medium_count := count(input.vulnerabilities.medium)
    medium_count > 10
    msg := sprintf(
        "Warning: %d medium severity issues detected",
        [medium_count]
    )
}

package security.scanning

default require_scan = true

require_scan if {
    input.file_changed
    is_security_relevant_file
}

is_security_relevant_file if {
    security_paths := [
        "src/routes",
        "src/controllers",
        "src/middleware",
        "src/config"
    ]
    some path in security_paths
    startswith(input.file_path, path)
}

require_rescan if {
    time.now_ns() - input.last_scan_time > 604800000000000
}

package security.authentication

default password_policy_met = false

password_policy_met if {
    input.password.length >= 12
    has_uppercase(input.password)
    has_lowercase(input.password)
    has_digit(input.password)
    has_special_char(input.password)
    not is_common_password(input.password)
}

has_uppercase(password) if {
    regex.match(`[A-Z]`, password)
}

has_lowercase(password) if {
    regex.match(`[a-z]`, password)
}

has_digit(password) if {
    regex.match(`[0-9]`, password)
}

has_special_char(password) if {
    regex.match(`[!@#$%^&*(),.?":{}|<>]`, password)
}

is_common_password(password) if {
    common := ["password123", "admin123", "qwerty123"]
    password in common
}

package security.crypto

default crypto_config_secure = false

crypto_config_secure if {
    not uses_weak_algorithm
    uses_strong_key_length
    proper_iv_usage
}

uses_weak_algorithm if {
    weak_algos := ["md5", "sha1", "des", "rc4"]
    some algo in weak_algos
    algo == input.crypto.algorithm
}

uses_strong_key_length if {
    input.crypto.key_length >= 256
}

proper_iv_usage if {
    input.crypto.uses_random_iv == true
}

package security.injection

default query_safe = false

query_safe if {
    uses_parameterized_query
    not has_string_concatenation
    input_validated
}

uses_parameterized_query if {
    input.query.type == "parameterized"
}

has_string_concatenation if {
    regex.match(`\+.*\+|concat\(`, input.query.raw)
}

input_validated if {
    input.query.validation_applied == true
}

package security.access_control

default access_allowed = false

access_allowed if {
    user_authenticated
    user_authorized
    resource_accessible
}

user_authenticated if {
    input.user.authenticated == true
    valid_session
}

user_authorized if {
    required_role := input.resource.required_role
    user_roles := input.user.roles
    required_role in user_roles
}

resource_accessible if {
    not resource_restricted
}

resource_restricted if {
    restricted_resources := ["admin", "config", "secrets"]
    some resource in restricted_resources
    startswith(input.resource.path, resource)
    input.user.role != "admin"
}

valid_session if {
    session_not_expired
    session_not_revoked
}

session_not_expired if {
    time.now_ns() < input.user.session.expires_at
}

session_not_revoked if {
    not input.user.session.revoked
}

package security.rate_limiting

default rate_limit_ok = true

rate_limit_ok if {
    not rate_limit_exceeded
}

rate_limit_exceeded if {
    input.request_count > input.rate_limit.max_requests
    within_time_window
}

within_time_window if {
    time_window := input.rate_limit.window_ms * 1000000
    time.now_ns() - input.first_request_time < time_window
}

package security.compliance

default compliant = false

compliant if {
    owasp_top_10_addressed
    cwe_top_25_mitigated
    security_headers_configured
}

owasp_top_10_addressed if {
    required_controls := {
        "A01:2021": "access_control",
        "A02:2021": "cryptography",
        "A03:2021": "injection",
        "A07:2021": "authentication"
    }
    count({key | required_controls[key]; input.controls[required_controls[key]].implemented}) == count(required_controls)
}

cwe_top_25_mitigated if {
    critical_cwes := ["CWE-79", "CWE-89", "CWE-78", "CWE-798"]
    count({cwe | cwe in critical_cwes; input.mitigations[cwe].active}) == count(critical_cwes)
}

security_headers_configured if {
    required_headers := [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy"
    ]
    count({header | header in required_headers; input.headers[header]}) == count(required_headers)
}