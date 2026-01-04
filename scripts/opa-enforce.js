const fs = require('fs').promises;
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class OPAPolicyEnforcer {
  constructor(policyPath, inputData) {
    this.policyPath = policyPath;
    this.inputData = inputData;
  }
  
  async evaluatePolicy(packageName) {
    const inputFile = 'opa-input.json';
    await fs.writeFile(inputFile, JSON.stringify(this.inputData, null, 2));
    
    try {
      const command = `opa eval -d ${this.policyPath} -i ${inputFile} "data.${packageName}" --format pretty`;
      const { stdout } = await execPromise(command);
      
      const result = JSON.parse(stdout);
      
      await fs.unlink(inputFile);
      
      return result;
    } catch (error) {
      console.error('OPA evaluation error:', error);
      throw error;
    }
  }
  
  async checkDeploymentPolicy() {
    const result = await this.evaluatePolicy('security');
    
    console.log('Deployment Policy Evaluation:');
    console.log('  Allow Deployment:', result.allow_deployment);
    
    if (result.deny && result.deny.length > 0) {
      console.log('\nPolicy Violations:');
      result.deny.forEach(violation => {
        console.log(`  - ${violation}`);
      });
    }
    
    if (result.warnings && result.warnings.length > 0) {
      console.log('\nWarnings:');
      result.warnings.forEach(warning => {
        console.log(`  - ${warning}`);
      });
    }
    
    return result.allow_deployment === true;
  }
  
  async checkAccessControl(user, resource) {
    const input = {
      user: user,
      resource: resource
    };
    
    const inputFile = 'opa-access-input.json';
    await fs.writeFile(inputFile, JSON.stringify(input, null, 2));
    
    try {
      const command = `opa eval -d ${this.policyPath} -i ${inputFile} "data.security.access_control.access_allowed" --format pretty`;
      const { stdout } = await execPromise(command);
      
      const result = JSON.parse(stdout);
      
      await fs.unlink(inputFile);
      
      return result;
    } catch (error) {
      console.error('Access control evaluation error:', error);
      return false;
    }
  }
  
  async validateSecurityScan(scanResults) {
    const input = {
      vulnerabilities: {
        critical: scanResults.critical || [],
        high: scanResults.high || [],
        medium: scanResults.medium || []
      },
      policy: {
        max_high_severity: 5,
        min_coverage: 80,
        max_complexity: 10
      },
      code_quality: {
        coverage: scanResults.coverage || 0,
        complexity: scanResults.complexity || 0
      },
      tests: {
        passed: scanResults.tests_passed || 0,
        total: scanResults.tests_total || 0
      }
    };
    
    this.inputData = input;
    
    return await this.checkDeploymentPolicy();
  }
}

async function loadSemgrepResults(filepath) {
  try {
    const content = await fs.readFile(filepath, 'utf-8');
    const data = JSON.parse(content);
    
    const results = data.results || [];
    
    const critical = results.filter(r => r.extra?.severity === 'ERROR');
    const high = results.filter(r => r.extra?.severity === 'WARNING');
    const medium = results.filter(r => r.extra?.severity === 'INFO');
    
    return {
      critical: critical.map(r => ({
        id: r.check_id,
        file: r.path,
        line: r.start.line
      })),
      high: high.map(r => ({
        id: r.check_id,
        file: r.path,
        line: r.start.line
      })),
      medium: medium.map(r => ({
        id: r.check_id,
        file: r.path,
        line: r.start.line
      })),
      coverage: 75,
      complexity: 8,
      tests_passed: 45,
      tests_total: 50
    };
  } catch (error) {
    console.error('Failed to load Semgrep results:', error);
    return {
      critical: [],
      high: [],
      medium: [],
      coverage: 0,
      complexity: 0,
      tests_passed: 0,
      tests_total: 0
    };
  }
}

async function main() {
  console.log('OPA Policy Enforcement');
  console.log('======================\n');
  
  const policyPath = 'opa/security-policies.rego';
  const scanResultsPath = 'security-reports/custom-rules.json';
  
  const scanResults = await loadSemgrepResults(scanResultsPath);
  
  console.log('Scan Results Summary:');
  console.log(`  Critical: ${scanResults.critical.length}`);
  console.log(`  High: ${scanResults.high.length}`);
  console.log(`  Medium: ${scanResults.medium.length}`);
  console.log(`  Code Coverage: ${scanResults.coverage}%`);
  console.log(`  Tests: ${scanResults.tests_passed}/${scanResults.tests_total}\n`);
  
  const enforcer = new OPAPolicyEnforcer(policyPath, {});
  
  const deploymentAllowed = await enforcer.validateSecurityScan(scanResults);
  
  console.log('\n======================');
  console.log('Final Decision:', deploymentAllowed ? 'APPROVED' : 'BLOCKED');
  console.log('======================\n');
  
  if (!deploymentAllowed) {
    console.log('Deployment blocked due to policy violations.');
    console.log('Please fix the issues and re-run the security scan.\n');
    process.exit(1);
  }
  
  console.log('All policies satisfied. Deployment can proceed.\n');
}

if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { OPAPolicyEnforcer, loadSemgrepResults };