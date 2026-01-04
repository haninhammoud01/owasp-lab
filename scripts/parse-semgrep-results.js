const fs = require('fs');
const path = require('path');

class SemgrepReportParser {
  constructor(reportPath) {
    this.reportPath = reportPath;
    this.results = null;
  }
  
  load() {
    try {
      const content = fs.readFileSync(this.reportPath, 'utf-8');
      this.results = JSON.parse(content);
      return true;
    } catch (error) {
      console.error('Failed to load report:', error.message);
      return false;
    }
  }
  
  getSummary() {
    if (!this.results) return null;
    
    const findings = this.results.results || [];
    const summary = {
      total: findings.length,
      bySeverity: {
        error: 0,
        warning: 0,
        info: 0
      },
      byCategory: {},
      byFile: {}
    };
    
    findings.forEach(finding => {
      const severity = finding.extra?.severity?.toLowerCase() || 'info';
      summary.bySeverity[severity] = (summary.bySeverity[severity] || 0) + 1;
      
      const category = finding.extra?.metadata?.category || 'unknown';
      summary.byCategory[category] = (summary.byCategory[category] || 0) + 1;
      
      const file = finding.path;
      summary.byFile[file] = (summary.byFile[file] || 0) + 1;
    });
    
    return summary;
  }
  
  getCriticalFindings() {
    if (!this.results) return [];
    
    return this.results.results
      .filter(f => f.extra?.severity === 'ERROR')
      .sort((a, b) => {
        const severityA = this.getRiskScore(a);
        const severityB = this.getRiskScore(b);
        return severityB - severityA;
      });
  }
  
  getRiskScore(finding) {
    const metadata = finding.extra?.metadata || {};
    let score = 0;
    
    if (metadata.likelihood === 'HIGH') score += 3;
    else if (metadata.likelihood === 'MEDIUM') score += 2;
    else score += 1;
    
    if (metadata.impact === 'HIGH') score += 3;
    else if (metadata.impact === 'MEDIUM') score += 2;
    else score += 1;
    
    if (metadata.confidence === 'HIGH') score += 2;
    else if (metadata.confidence === 'MEDIUM') score += 1;
    
    return score;
  }
  
  getVulnerabilitiesByOWASP() {
    if (!this.results) return {};
    
    const owaspMap = {};
    
    this.results.results.forEach(finding => {
      const owasp = finding.extra?.metadata?.owasp;
      if (owasp) {
        if (!owaspMap[owasp]) {
          owaspMap[owasp] = [];
        }
        owaspMap[owasp].push(finding);
      }
    });
    
    return owaspMap;
  }
  
  getVulnerabilitiesByCWE() {
    if (!this.results) return {};
    
    const cweMap = {};
    
    this.results.results.forEach(finding => {
      const cwe = finding.extra?.metadata?.cwe;
      if (cwe) {
        if (!cweMap[cwe]) {
          cweMap[cwe] = [];
        }
        cweMap[cwe].push(finding);
      }
    });
    
    return cweMap;
  }
  
  generateMarkdownReport() {
    if (!this.results) return '';
    
    const summary = this.getSummary();
    const critical = this.getCriticalFindings();
    const owaspMap = this.getVulnerabilitiesByOWASP();
    
    let markdown = '# Security Scan Report\n\n';
    markdown += `**Generated:** ${new Date().toISOString()}\n\n`;
    
    markdown += '## Summary\n\n';
    markdown += `- **Total Findings:** ${summary.total}\n`;
    markdown += `- **Critical (ERROR):** ${summary.bySeverity.error}\n`;
    markdown += `- **High (WARNING):** ${summary.bySeverity.warning}\n`;
    markdown += `- **Info:** ${summary.bySeverity.info}\n\n`;
    
    markdown += '## Findings by Category\n\n';
    Object.entries(summary.byCategory)
      .sort((a, b) => b[1] - a[1])
      .forEach(([category, count]) => {
        markdown += `- **${category}:** ${count}\n`;
      });
    markdown += '\n';
    
    markdown += '## OWASP Top 10 Mapping\n\n';
    Object.entries(owaspMap)
      .sort((a, b) => b[1].length - a[1].length)
      .forEach(([owasp, findings]) => {
        markdown += `### ${owasp}\n`;
        markdown += `**Occurrences:** ${findings.length}\n\n`;
      });
    
    if (critical.length > 0) {
      markdown += '## Critical Findings\n\n';
      critical.slice(0, 10).forEach((finding, index) => {
        markdown += `### ${index + 1}. ${finding.check_id}\n\n`;
        markdown += `**Severity:** ${finding.extra.severity}\n`;
        markdown += `**File:** ${finding.path}:${finding.start.line}\n`;
        markdown += `**CWE:** ${finding.extra?.metadata?.cwe || 'N/A'}\n`;
        markdown += `**OWASP:** ${finding.extra?.metadata?.owasp || 'N/A'}\n\n`;
        markdown += `**Description:**\n${finding.extra.message}\n\n`;
        markdown += '**Code:**\n```javascript\n';
        markdown += `${finding.extra?.lines || 'N/A'}\n`;
        markdown += '```\n\n';
        markdown += '---\n\n';
      });
    }
    
    markdown += '## Most Affected Files\n\n';
    Object.entries(summary.byFile)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .forEach(([file, count]) => {
        markdown += `- **${file}:** ${count} issues\n`;
      });
    
    return markdown;
  }
  
  generateHTMLReport() {
    if (!this.results) return '';
    
    const summary = this.getSummary();
    const critical = this.getCriticalFindings();
    
    let html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .critical { border-left: 4px solid #dc3545; }
        .high { border-left: 4px solid #fd7e14; }
        .info { border-left: 4px solid #0dcaf0; }
        .metric {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .finding {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .code {
            background: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 5px;
        }
        .badge-error { background: #dc3545; color: white; }
        .badge-warning { background: #fd7e14; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Scan Report</h1>
        <p>Generated: ${new Date().toLocaleString()}</p>
    </div>
    
    <div class="summary">
        <div class="card critical">
            <div class="label">Critical Issues</div>
            <div class="metric">${summary.bySeverity.error}</div>
        </div>
        <div class="card high">
            <div class="label">High Issues</div>
            <div class="metric">${summary.bySeverity.warning}</div>
        </div>
        <div class="card info">
            <div class="label">Total Findings</div>
            <div class="metric">${summary.total}</div>
        </div>
    </div>
    
    <h2>Critical Findings</h2>
`;
    
    critical.slice(0, 10).forEach((finding, index) => {
      const severity = finding.extra.severity.toLowerCase();
      html += `
    <div class="finding">
        <h3>${index + 1}. ${finding.check_id}</h3>
        <div>
            <span class="badge badge-${severity}">${finding.extra.severity}</span>
            <span class="badge">${finding.extra?.metadata?.cwe || 'N/A'}</span>
            <span class="badge">${finding.extra?.metadata?.owasp || 'N/A'}</span>
        </div>
        <p><strong>File:</strong> ${finding.path}:${finding.start.line}</p>
        <p>${finding.extra.message.replace(/\n/g, '<br>')}</p>
        <div class="code">${finding.extra?.lines || 'Code not available'}</div>
    </div>
`;
    });
    
    html += `
</body>
</html>
`;
    
    return html;
  }
  
  exportReports(outputDir = 'security-reports') {
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    const markdown = this.generateMarkdownReport();
    fs.writeFileSync(
      path.join(outputDir, 'security-report.md'),
      markdown
    );
    
    const html = this.generateHTMLReport();
    fs.writeFileSync(
      path.join(outputDir, 'security-report.html'),
      html
    );
    
    const summary = this.getSummary();
    fs.writeFileSync(
      path.join(outputDir, 'summary.json'),
      JSON.stringify(summary, null, 2)
    );
    
    console.log(`Reports generated in ${outputDir}/`);
    console.log('  - security-report.md');
    console.log('  - security-report.html');
    console.log('  - summary.json');
  }
}

function main() {
  const reportPath = process.argv[2] || 'security-reports/custom-rules.json';
  
  if (!fs.existsSync(reportPath)) {
    console.error(`Report file not found: ${reportPath}`);
    console.log('Usage: node parse-semgrep-results.js <path-to-semgrep-json>');
    process.exit(1);
  }
  
  console.log('Parsing Semgrep results...\n');
  
  const parser = new SemgrepReportParser(reportPath);
  
  if (!parser.load()) {
    process.exit(1);
  }
  
  const summary = parser.getSummary();
  
  console.log('Summary:');
  console.log(`  Total Findings: ${summary.total}`);
  console.log(`  Critical: ${summary.bySeverity.error}`);
  console.log(`  High: ${summary.bySeverity.warning}`);
  console.log(`  Info: ${summary.bySeverity.info}`);
  console.log('');
  
  const critical = parser.getCriticalFindings();
  if (critical.length > 0) {
    console.log(`Top ${Math.min(5, critical.length)} Critical Issues:`);
    critical.slice(0, 5).forEach((finding, index) => {
      console.log(`  ${index + 1}. ${finding.check_id}`);
      console.log(`     ${finding.path}:${finding.start.line}`);
      console.log(`     ${finding.extra?.metadata?.owasp || 'N/A'}`);
    });
    console.log('');
  }
  
  parser.exportReports();
  
  if (summary.bySeverity.error > 0) {
    console.log('\nCritical vulnerabilities detected!');
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = SemgrepReportParser;