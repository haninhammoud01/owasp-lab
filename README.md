# OWASP Top 10 Security Laboratory

Enterprise-grade vulnerability research and mitigation framework demonstrating secure coding practices through practical implementation of OWASP Top 10 vulnerabilities and their remediation strategies.

## Overview

This project provides a comprehensive security testing environment that demonstrates both vulnerable and secure implementations of common web application security risks. It serves as a practical learning resource for understanding security vulnerabilities from a defensive engineering perspective.

## Core Objectives

- Demonstrate practical vulnerability exploitation and mitigation techniques
- Implement defense-in-depth security strategies
- Establish secure coding patterns used in production environments
- Integrate automated security testing into CI/CD pipelines
- Document security decisions with clear risk-benefit analysis

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Client Applications                │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│         Security Middleware Layer               │
│  ┌──────────┬──────────┬──────────┬──────────┐ │
│  │ Rate     │ Input    │ Auth     │ CORS     │ │
│  │ Limiting │ Validate │ Check    │ Policy   │ │
│  └──────────┴──────────┴──────────┴──────────┘ │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│            Application Layer                    │
│  ┌──────────────────────────────────────────┐  │
│  │  Secure Routes    │  Vulnerable Routes   │  │
│  │  (Production)     │  (Research Only)     │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│              Data Layer                         │
│  ┌──────────┬──────────┬──────────┬──────────┐ │
│  │ PostgreSQL│ Redis   │ Session  │ Cache    │ │
│  └──────────┴──────────┴──────────┴──────────┘ │
└─────────────────────────────────────────────────┘
```

## Technology Stack

### Runtime & Framework

- Node.js 18+ (LTS)
- Express.js 4.x
- PostgreSQL 15

### Security Libraries

- helmet (security headers)
- express-rate-limit (DDoS protection)
- express-validator (input validation)
- bcryptjs (password hashing)
- jsonwebtoken (JWT authentication)

### Testing & Analysis

- Jest (unit & integration testing)
- Supertest (API testing)
- OWASP ZAP (dynamic analysis)
- Semgrep (static analysis)
- Snyk (dependency scanning)

## Quick Start

### Prerequisites

- Node.js >= 18.0.0
- PostgreSQL >= 15
- Docker & Docker Compose (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/haninhammoud01/owasp-top10-lab.git

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Setup database
npm run db:setup
npm run db:seed

# Run vulnerable instance (port 3000)
npm run dev

# Run secure instance (port 3001)
npm start
```

### Docker Setup

```bash
# Start all services
docker-compose up -d

# Vulnerable app: http://localhost:3000
# Secure app: http://localhost:3001
# OWASP ZAP: http://localhost:8080
# SonarQube: http://localhost:9000

# View logs
docker-compose logs -f app-vulnerable

# Stop all services
docker-compose down
```

## Implemented Vulnerabilities

### A01:2021 - Broken Access Control
- Missing function-level access control
- Insecure direct object references
- Path traversal

### A02:2021 - Cryptographic Failures
- Weak password hashing
- Insecure random number generation
- Sensitive data exposure

### A03:2021 - Injection
- SQL injection
- NoSQL injection
- Command injection
- XSS (reflected, stored, DOM-based)

### A07:2021 - Identification and Authentication Failures
- Weak password policy
- Credential stuffing vulnerability
- Session fixation
- Missing rate limiting

## Security Testing

### Static Analysis

```bash
# Run Semgrep
npm run security:scan

# Run ESLint with security plugin
npm run lint

# Check dependencies
npm audit
```

### Dynamic Analysis

```bash
# Start OWASP ZAP proxy
docker-compose up owasp-zap

# Run baseline scan
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:3000 \
  -r zap-report.html
```

### Automated Testing

```bash
# Run all security tests
npm run test:security

# Run with coverage
npm run test -- --coverage

# Watch mode
npm run test:watch
```

## CI/CD Integration

The project includes GitHub Actions workflows for automated security scanning:

- **SAST Analysis**: Semgrep, SonarCloud, ESLint Security
- **Dependency Scanning**: Snyk, npm audit, OWASP Dependency-Check
- **Container Scanning**: Trivy for Docker images
- **DAST**: OWASP ZAP baseline scans

## Learning Path

### Phase 1: Understanding Vulnerabilities
1. Review vulnerable implementations in `src/vulnerable/`
2. Study the attack vectors and exploitation techniques
3. Analyze the business impact of each vulnerability

### Phase 2: Implementing Mitigations
1. Compare with secure implementations in `src/secure/`
2. Understand the defense strategies applied
3. Run security tests to verify mitigations

### Phase 3: Practical Testing
1. Use OWASP ZAP to scan vulnerable endpoints
2. Write security test cases
3. Integrate security scans into CI/CD

### Phase 4: Advanced Topics
1. Threat modeling with STRIDE framework
2. Policy-as-code with OPA
3. Security monitoring and incident response

## Future Enhancements

- AI-assisted vulnerability detection
- Automated remediation suggestions
- Real-time threat intelligence integration
- Advanced behavioral analysis
- Cloud-native security controls

## References

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)
- [SANS Secure Coding Guidelines](https://www.sans.org/secure-coding/)

