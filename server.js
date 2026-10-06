const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'swat-bank-siege')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'swat-bank-siege', 'index.html'));
});

app.post('/api/scan', (req, res) => {
  const { url } = req.body || {};
  if (!url) {
    return res.status(400).json({ error: 'Missing url' });
  }

  const value = String(url).toLowerCase();
  const threatDetails = [];
  let reputationScore = 100;
  let status = 'CLEAN';

  if (/^\d+\.\d+\.\d+\.\d+$/.test(url)) {
    threatDetails.push('Uses raw IP address instead of domain name.');
    reputationScore -= 60;
  }

  if (/(login|verify|account|bank|secure|admin|update)/i.test(value)) {
    threatDetails.push('Contains suspicious keyword(s) in URL path or host.');
    reputationScore -= 25;
  }

  if (!/^https?:\/\//i.test(url)) {
    threatDetails.push('URL is missing a standard secure scheme.');
    reputationScore -= 15;
  }

  if (reputationScore < 40) status = 'HIGH RISK';
  else if (reputationScore < 80) status = 'SUSPICIOUS';

  const result = {
    url,
    status,
    reputationScore: Math.max(0, reputationScore),
    threatCount: threatDetails.length,
    threatDetails,
    sslInfo: {
      valid: /^https:\/\//i.test(url),
      reason: /^https:\/\//i.test(url)
        ? 'Valid HTTPS scheme detected'
        : 'No HTTPS scheme detected'
    },
    timestamp: new Date().toISOString()
  };

  return res.json(result);
});

const RULES_FILE = path.join(__dirname, 'hyaet_rules.json');

function loadRules() {
  try {
    if (fs.existsSync(RULES_FILE)) {
      return JSON.parse(fs.readFileSync(RULES_FILE, 'utf8'));
    }
    return [];
  } catch (error) {
    return [];
  }
}

app.get('/api/rules', (req, res) => {
  res.json(loadRules());
});

app.post('/api/rules', (req, res) => {
  const { type, value } = req.body || {};
  if (!type || !value) {
    return res.status(400).json({ error: 'Invalid rule payload' });
  }

  const rules = loadRules();
  const record = {
    id: Date.now(),
    type,
    value
  };

  rules.push(record);
  fs.writeFileSync(RULES_FILE, JSON.stringify(rules, null, 2));
  res.json(record);
});

app.delete('/api/rules/:id', (req, res) => {
  const rules = loadRules().filter(rule => String(rule.id) !== String(req.params.id));
  fs.writeFileSync(RULES_FILE, JSON.stringify(rules, null, 2));
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`HYÆT VIEWS scanner running on http://localhost:${PORT}`);
});
