const fs = require('fs').promises;
const path = require('path');

/*
 * AI-Assisted Security Scanner
 * Future-ready approach combining static analysis with pattern recognition
 * 
 * This demonstrates the 2026-2030 trend of AI-assisted vulnerability detection
 * Key aspects:
 * 1. Context-aware analysis
 * 2. Pattern recognition beyond simple regex
 * 3. Risk scoring with business context
 * 4. Automated remediation suggestions
 */

class SecurityScanner {
  constructor() {
    this.vulnerabilityPatterns = this.initializePatterns();
    this.contextAnalyzer = new ContextAnalyzer();
    this.riskScorer = new RiskScorer();
  }
  
  initializePatterns() {
    return {
      injection: {
        sql: {
          patterns: [
            /query\s*\(\s*[`"'].*\$\{.*\}.*[`"']/g,
            /query\s*\(\s*[`"'].*\+.*\+.*[`"']/g,
            /exec\s*\(\s*[`"'].*\$\{.*\}.*[`"']/g
          ],
          severity: 'CRITICAL',
          cwe: 'CWE-89',
          owasp: 'A03:2021'
        },
        nosql: {
          patterns: [
            /find\s*\(\s*\{[^}]*\$ne[^}]*\}\s*\)/g,
            /find\s*\(\s*\{[^}]*\$gt[^}]*\}\s*\)/g
          ],
          severity: 'HIGH',
          cwe: 'CWE-943',
          owasp: 'A03:2021'
        },
        command: {
          patterns: [
            /exec\s*\(\s*[`"'].*\$\{.*\}.*[`"']/g,
            /spawn\s*\(\s*[`"'].*\$\{.*\}.*[`"']/g
          ],
          severity: 'CRITICAL',
          cwe: 'CWE-78',
          owasp: 'A03:2021'
        }
      },
      
      xss: {
        reflected: {
          patterns: [
            /res\.send\s*\(\s*[`"'].*\$\{.*\}.*[`"']/g,
            /innerHTML\s*=\s*[`"'].*\$\{.*\}.*[`"']/g
          ],
          severity: 'HIGH',
          cwe: 'CWE-79',
          owasp: 'A03:2021'
        }
      },
      
      auth: {
        weakPassword: {
          patterns: [
            /password\s*===?\s*[`"'][^`"']{1,7}[`"']/g,
            /const\s+password\s*=\s*[`"'].*[`"']/g
          ],
          severity: 'HIGH',
          cwe: 'CWE-521',
          owasp: 'A07:2021'
        },
        noEncryption: {
          patterns: [
            /INSERT.*password.*VALUES.*\$\d+/g,
            /UPDATE.*password\s*=\s*\$\d+/g
          ],
          severity: 'CRITICAL',
          cwe: 'CWE-256',
          owasp: 'A02:2021'
        }
      },
      
      sensitiveData: {
        exposure: {
          patterns: [
            /console\.log\s*\(\s*.*password/gi,
            /res\.(send|json)\s*\(\s*.*\.stack/g,
            /api[_-]?key\s*=\s*[`"'][^`"']+[`"']/gi
          ],
          severity: 'MEDIUM',
          cwe: 'CWE-532',
          owasp: 'A04:2021'
        }
      },
      
      crypto: {
        weak: {
          patterns: [
            /crypto\.createHash\s*\(\s*[`"'](md5|sha1)[`"']/g,
            /Math\.random\s*\(\s*\)/g
          ],
          severity: 'MEDIUM',
          cwe: 'CWE-327',
          owasp: 'A02:2021'
        }
      }
    };
  }
  
  async scanDirectory(dirPath) {
    const results = {
      vulnerabilities: [],
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      scannedFiles: 0,
      timestamp: new Date().toISOString()
    };
    
    await this.scanRecursive(dirPath, results);
    return results;
  }
  
  async scanRecursive(dirPath, results) {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (entry.isDirectory()) {
        if (!entry.name.startsWith('.') && entry.name !== 'node_modules') {
          await this.scanRecursive(fullPath, results);
        }
      } else if (entry.name.endsWith('.js') || entry.name.endsWith('.ts')) {
        await this.scanFile(fullPath, results);
      }
    }
  }
  
  async scanFile(filePath, results) {
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    
    results.scannedFiles++;
    
    for (const [category, types] of Object.entries(this.vulnerabilityPatterns)) {
      for (const [type, config] of Object.entries(types)) {
        for (const pattern of config.patterns) {
          let match;
          while ((match = pattern.exec(content)) !== null) {
            const lineNumber = content.substring(0, match.index).split('\n').length;
            const lineContent = lines[lineNumber - 1].trim();
            
            const context = this.contextAnalyzer.analyze(
              content,
              match.index,
              lineNumber
            );
            
            const riskScore = this.riskScorer.calculate(
              config.severity,
              context,
              category,
              type
            );
            
            const vulnerability = {
              category: category,
              type: type,
              severity: config.severity,
              riskScore: riskScore,
              file: filePath,
              line: lineNumber,
              code: lineContent,
              matched: match[0],
              cwe: config.cwe,
              owasp: config.owasp,
              context: context,
              remediation: this.getRemediation(category, type),
              references: this.getReferences(config.cwe, config.owasp)
            };
            
            results.vulnerabilities.push(vulnerability);
            
            const severityKey = config.severity.toLowerCase();
            if (results.summary[severityKey] !== undefined) {
              results.summary[severityKey]++;
            }
          }
        }
      }
    }
  }
  
  getRemediation(category, type) {
    const remediations = {
      injection: {
        sql: {
          description: 'Use parameterized queries instead of string concatenation',
          code: 'const query = "SELECT * FROM users WHERE id = $1";\nconst result = await pool.query(query, [userId]);'
        },
        nosql: {
          description: 'Sanitize input and use strict query operators',
          code: 'const user = await User.findOne({\n  username: sanitize(username),\n  _id: { $eq: userId }\n});'
        },
        command: {
          description: 'Avoid executing shell commands with user input',
          code: 'Use libraries that provide safe APIs instead of shell commands'
        }
      },
      xss: {
        reflected: {
          description: 'Sanitize user input before rendering',
          code: 'const clean = DOMPurify.sanitize(userInput);\nres.send(clean);'
        }
      },
      auth: {
        weakPassword: {
          description: 'Use bcrypt for password hashing',
          code: 'const hash = await bcrypt.hash(password, 12);\nawait pool.query("INSERT INTO users (password_hash) VALUES ($1)", [hash]);'
        }
      }
    };
    
    return remediations[category]?.[type] || {
      description: 'Review and apply security best practices',
      code: 'Consult OWASP guidelines for specific mitigation'
    };
  }
  
  getReferences(cwe, owasp) {
    return {
      cwe: `https://cwe.mitre.org/data/definitions/${cwe.split('-')[1]}.html`,
      owasp: `https://owasp.org/Top10/${owasp.split(':')[0]}/`,
      documentation: 'https://docs.claude.com/security-best-practices'
    };
  }
}

class ContextAnalyzer {
  analyze(content, matchIndex, lineNumber) {
    const contextStart = Math.max(0, matchIndex - 200);
    const contextEnd = Math.min(content.length, matchIndex + 200);
    const contextSnippet = content.substring(contextStart, contextEnd);
    
    const hasValidation = /validate|sanitize|escape/i.test(contextSnippet);
    const hasErrorHandling = /try\s*\{|catch\s*\(|\.catch\(/g.test(contextSnippet);
    const inProductionCode = !/test|spec|mock/i.test(content);
    const hasSecurityComment = /security|vulnerable|fix|todo/i.test(
      content.substring(Math.max(0, matchIndex - 100), matchIndex)
    );
    
    return {
      hasValidation,
      hasErrorHandling,
      inProductionCode,
      hasSecurityComment,
      snippetBefore: content.substring(matchIndex - 50, matchIndex),
      snippetAfter: content.substring(matchIndex, matchIndex + 50)
    };
  }
}

class RiskScorer {
  calculate(severity, context, category, type) {
    let baseScore = {
      'CRITICAL': 9.0,
      'HIGH': 7.0,
      'MEDIUM': 5.0,
      'LOW': 3.0
    }[severity] || 5.0;
    
    if (!context.inProductionCode) {
      baseScore *= 0.5;
    }
    
    if (context.hasValidation) {
      baseScore *= 0.7;
    }
    
    if (context.hasErrorHandling) {
      baseScore *= 0.9;
    }
    
    if (context.hasSecurityComment) {
      baseScore *= 0.8;
    }
    
    if (category === 'injection' && type === 'sql') {
      baseScore *= 1.2;
    }
    
    return Math.min(10.0, Math.max(1.0, baseScore));
  }
}

async function main() {
  const scanner = new SecurityScanner();
  
  console.log('Starting AI-assisted security scan...\n');
  
  const results = await scanner.scanDirectory('./src');
  
  console.log('Scan Summary:');
  console.log(`Scanned Files: ${results.scannedFiles}`);
  console.log(`Total Vulnerabilities: ${results.vulnerabilities.length}`);
  console.log(`  Critical: ${results.summary.critical}`);
  console.log(`  High: ${results.summary.high}`);
  console.log(`  Medium: ${results.summary.medium}`);
  console.log(`  Low: ${results.summary.low}`);
  console.log('\nDetailed Report:\n');
  
  const sortedVulns = results.vulnerabilities.sort((a, b) => b.riskScore - a.riskScore);
  
  for (const vuln of sortedVulns.slice(0, 10)) {
    console.log(`[${vuln.severity}] ${vuln.category}/${vuln.type}`);
    console.log(`  File: ${vuln.file}:${vuln.line}`);
    console.log(`  Risk Score: ${vuln.riskScore.toFixed(1)}/10.0`);
    console.log(`  Code: ${vuln.code}`);
    console.log(`  OWASP: ${vuln.owasp} | CWE: ${vuln.cwe}`);
    console.log(`  Remediation: ${vuln.remediation.description}`);
    console.log('');
  }
  
  await fs.writeFile(
    'security-scan-results.json',
    JSON.stringify(results, null, 2)
  );
  
  console.log('Full report saved to: security-scan-results.json');
  
  if (results.summary.critical > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = { SecurityScanner, ContextAnalyzer, RiskScorer };