package security.policies

import future.keywords.if
import future.keywords.in

default allow = false

allow if {
    input.method == "GET"
    not requires_authentication[input.path]
}

allow if {
    input.method in ["POST", "PUT", "DELETE"]
    is_authenticated
    has_required_role
}

requires_authentication[path] {
    path in ["/api/admin", "/api/users", "/api/secure"]
}

is_authenticated if {
    input.headers.authorization
    token := substring(input.headers.authorization, 7, -1)
    verify_jwt(token)
}

has_required_role if {
    token := substring(input.headers.authorization, 7, -1)
    claims := decode_jwt(token)
    role := claims.role
    required_role := required_roles[input.path]
    role == required_role
}

required_roles := {
    "/api/admin": "admin",
    "/api/users": "user",
    "/api/secure": "premium"
}

deny[msg] {
    input.body.password
    not password_complexity_met(input.body.password)
    msg := "Password does not meet complexity requirements"
}

password_complexity_met(password) if {
    count(password) >= 12
    regex.match(`[A-Z]`, password)
    regex.match(`[a-z]`, password)
    regex.match(`[0-9]`, password)
    regex.match(`[!@#$%^&*]`, password)
}

deny[msg] {
    input.method == "POST"
    input.path == "/api/login"
    count(login_attempts[input.ip]) > 5
    msg := "Too many login attempts from this IP"
}

login_attempts[ip] := attempts {
    ip := input.ip
    attempts := data.login_history[ip]
}

deny[msg] {
    suspicious_patterns[pattern]
    regex.match(pattern, input.body.query)
    msg := sprintf("Suspicious pattern detected: %v", [pattern])
}

suspicious_patterns := {
    `(?i)(union|select|insert|update|delete|drop|exec|script)`,
    `(?i)(<script|javascript:|onerror=|onload=)`,
    `\.\./`,
    `cmd\.exe|/bin/sh|bash`
}

api_rate_limit[endpoint] := limit {
    endpoint_limits := {
        "/api/login": 5,
        "/api/register": 3,
        "/api/password-reset": 2
    }
    limit := endpoint_limits[endpoint]
}

deny[msg] {
    limit := api_rate_limit[input.path]
    count(requests[input.ip][input.path]) > limit
    msg := sprintf("Rate limit exceeded for %v", [input.path])
}

requests[ip][path] := reqs {
    ip := input.ip
    path := input.path
    reqs := data.request_history[ip][path]
}

sensitive_data_patterns := {
    "ssn": `\b\d{3}-\d{2}-\d{4}\b`,
    "credit_card": `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
    "api_key": `(?i)(api[_-]?key|apikey)[\s:=]+[a-zA-Z0-9]{32,}`
}

deny[msg] {
    some key, pattern in sensitive_data_patterns
    regex.match(pattern, input.body.content)
    not input.encrypted
    msg := sprintf("Sensitive data (%v) detected in unencrypted request", [key])
}