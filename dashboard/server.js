const helmet = require('helmet');
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const app = express();
const PORT = 8888;

app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get('/api/security/summary', async (req, res) => {
  try {
    const reportPath = path.join(__dirname, '../security-reports/custom-rules.json');
    
    let data;
    try {
      const content = await fs.readFile(reportPath, 'utf-8');
      data = JSON.parse(content);
    } catch (error) {
      return res.json({
        summary: {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          filesScanned: 0,
          lastScan: null
        },
        message: 'No scan results available. Run a scan first.'
      });
    }
    
    const findings = data.results || [];
    
    const summary = {
      total: findings.length,
      critical: findings.filter(f => f.extra?.severity === 'ERROR').length,
      high: findings.filter(f => f.extra?.severity === 'WARNING').length,
      medium: findings.filter(f => f.extra?.severity === 'INFO').length,
      low: 0,
      filesScanned: new Set(findings.map(f => f.path)).size,
      lastScan: new Date().toISOString()
    };
    
    res.json({ summary });
  } catch (error) {
    console.error('Error reading security summary:', error);
    res.status(500).json({ error: 'Failed to read security data' });
  }
});

app.get('/api/security/findings', async (req, res) => {
  try {
    const reportPath = path.join(__dirname, '../security-reports/custom-rules.json');
    const content = await fs.readFile(reportPath, 'utf-8');
    const data = JSON.parse(content);
    
    const findings = (data.results || []).map(result => ({
      severity: result.extra?.severity === 'ERROR' ? 'critical' : 
                result.extra?.severity === 'WARNING' ? 'high' : 'medium',
      type: result.check_id.split('.').pop().replace(/-/g, ' '),
      file: result.path,
      line: result.start.line,
      cwe: result.extra?.metadata?.cwe || 'N/A',
      owasp: result.extra?.metadata?.owasp || 'N/A',
      code: result.extra?.lines || '',
      message: result.extra?.message || ''
    }));
    
    res.json({ findings });
  } catch (error) {
    console.error('Error reading findings:', error);
    res.status(500).json({ error: 'Failed to read findings data' });
  }
});

app.get('/api/security/owasp-distribution', async (req, res) => {
  try {
    const reportPath = path.join(__dirname, '../security-reports/custom-rules.json');
    const content = await fs.readFile(reportPath, 'utf-8');
    const data = JSON.parse(content);
    
    const distribution = {};
    
    (data.results || []).forEach(result => {
      const owasp = result.extra?.metadata?.owasp;
      if (owasp) {
        distribution[owasp] = (distribution[owasp] || 0) + 1;
      }
    });
    
    res.json({ distribution });
  } catch (error) {
    console.error('Error reading OWASP distribution:', error);
    res.status(500).json({ error: 'Failed to read OWASP data' });
  }
});

app.get('/api/security/file-statistics', async (req, res) => {
  try {
    const reportPath = path.join(__dirname, '../security-reports/custom-rules.json');
    const content = await fs.readFile(reportPath, 'utf-8');
    const data = JSON.parse(content);
    
    const fileStats = {};
    
    (data.results || []).forEach(result => {
      const file = result.path;
      fileStats[file] = (fileStats[file] || 0) + 1;
    });
    
    const sortedFiles = Object.entries(fileStats)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .reduce((obj, [key, value]) => {
        obj[key] = value;
        return obj;
      }, {});
    
    res.json({ fileStats: sortedFiles });
  } catch (error) {
    console.error('Error reading file statistics:', error);
    res.status(500).json({ error: 'Failed to read file statistics' });
  }
});

app.post('/api/security/scan', async (req, res) => {
  try {
    const projectRoot = path.join(__dirname, '..');
    
    res.json({
      status: 'started',
      message: 'Security scan initiated'
    });
    
    const command = `cd "${projectRoot}" && semgrep --config semgrep-rules.yml src/ --no-git-ignore --json --output security-reports/custom-rules.json`;
    
    const { stdout, stderr } = await execPromise(command);
    
    console.log('Scan completed:', stdout);
    if (stderr) console.error('Scan errors:', stderr);
    
  } catch (error) {
    console.error('Scan execution error:', error);
    res.status(500).json({
      status: 'error',
      error: error.message
    });
  }
});

app.get('/api/security/trends', async (req, res) => {
  try {
    const trends = {
      labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
      critical: [12, 10, 9, 8],
      high: [18, 16, 15, 15],
      medium: [22, 20, 19, 18]
    };
    
    res.json({ trends });
  } catch (error) {
    console.error('Error generating trends:', error);
    res.status(500).json({ error: 'Failed to generate trends' });
  }
});

app.get('/api/security/export', async (req, res) => {
  try {
    const reportPath = path.join(__dirname, '../security-reports/security-report.html');
    const content = await fs.readFile(reportPath, 'utf-8');
    
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', 'attachment; filename=security-report.html');
    res.send(content);
  } catch (error) {
    console.error('Error exporting report:', error);
    res.status(500).json({ error: 'Failed to export report' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Security Dashboard Server running on http://localhost:${PORT}`);
  console.log(`Dashboard available at http://localhost:${PORT}/index.html`);
  console.log(`API endpoints:`);
  console.log(`  GET  /api/security/summary`);
  console.log(`  GET  /api/security/findings`);
  console.log(`  GET  /api/security/owasp-distribution`);
  console.log(`  GET  /api/security/file-statistics`);
  console.log(`  GET  /api/security/trends`);
  console.log(`  POST /api/security/scan`);
  console.log(`  GET  /api/security/export`);
});