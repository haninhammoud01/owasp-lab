#!/bin/bash

set -e

echo "=================================="
echo "Semgrep Security Analysis Runner"
echo "=================================="
echo ""

SEMGREP_INSTALLED=$(command -v semgrep >/dev/null 2>&1 && echo "yes" || echo "no")

if [ "$SEMGREP_INSTALLED" = "no" ]; then
    echo "Semgrep not found. Installing..."
    pip3 install semgrep
fi

echo "Semgrep version:"
semgrep --version
echo ""

OUTPUT_DIR="security-reports"
mkdir -p $OUTPUT_DIR

echo "Running custom rules scan..."
semgrep scan \
    --config semgrep-rules.yml \
    --config semgrep-advanced.yml \
    src/ \
    --json \
    --output $OUTPUT_DIR/custom-rules.json

echo ""
echo "Running OWASP Top 10 scan..."
semgrep scan \
    --config "p/owasp-top-ten" \
    src/ \
    --json \
    --output $OUTPUT_DIR/owasp-top-ten.json

echo ""
echo "Running security audit scan..."
semgrep scan \
    --config "p/security-audit" \
    src/ \
    --json \
    --output $OUTPUT_DIR/security-audit.json

echo ""
echo "Running JavaScript security scan..."
semgrep scan \
    --config "p/javascript" \
    src/ \
    --json \
    --output $OUTPUT_DIR/javascript-security.json

echo ""
echo "Running Express.js specific scan..."
semgrep scan \
    --config "p/expressjs" \
    src/ \
    --json \
    --output $OUTPUT_DIR/express-security.json

echo ""
echo "Running SQL injection focused scan..."
semgrep scan \
    --config "p/sql-injection" \
    src/ \
    --json \
    --output $OUTPUT_DIR/sql-injection.json

echo ""
echo "Running XSS focused scan..."
semgrep scan \
    --config "p/xss" \
    src/ \
    --json \
    --output $OUTPUT_DIR/xss-vulnerabilities.json

echo ""
echo "Generating comprehensive report..."
semgrep scan \
    --config semgrep-rules.yml \
    --config semgrep-advanced.yml \
    --config "p/owasp-top-ten" \
    --config "p/security-audit" \
    src/ \
    --sarif \
    --output $OUTPUT_DIR/comprehensive-report.sarif

echo ""
echo "Generating human-readable report..."
semgrep scan \
    --config semgrep-rules.yml \
    --config semgrep-advanced.yml \
    src/ \
    --verbose \
    > $OUTPUT_DIR/report.txt

echo ""
echo "Running scan with metrics..."
semgrep scan \
    --config semgrep-rules.yml \
    --config semgrep-advanced.yml \
    src/ \
    --metrics=on \
    --json \
    --output $OUTPUT_DIR/scan-with-metrics.json

echo ""
echo "=================================="
echo "Scan Summary"
echo "=================================="

CRITICAL=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' $OUTPUT_DIR/custom-rules.json)
HIGH=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' $OUTPUT_DIR/custom-rules.json)
TOTAL=$(jq '.results | length' $OUTPUT_DIR/custom-rules.json)

echo "Critical Issues: $CRITICAL"
echo "High Issues: $HIGH"
echo "Total Findings: $TOTAL"
echo ""

echo "Reports saved to: $OUTPUT_DIR/"
echo "  - custom-rules.json"
echo "  - owasp-top-ten.json"
echo "  - security-audit.json"
echo "  - comprehensive-report.sarif"
echo "  - report.txt"
echo ""

if [ "$CRITICAL" -gt 0 ]; then
    echo "CRITICAL vulnerabilities detected!"
    echo "Review $OUTPUT_DIR/custom-rules.json for details"
    exit 1
fi

echo "Scan completed successfully"