const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8000;

// 1. Core Security & Middleware (Ensure helmet & cors are initialized correctly first)
app.use(helmet());
app.use(cors());
app.use(express.json());

// 2. Health Check Endpoint
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'Hyæt Views Threat Detection API',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// 3. Scan Endpoint
app.post('/scan', (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string' || !url.trim()) {
      return res.status(400).json({
        error: 'Invalid request payload. A valid "url" string is required.'
      });
    }

    const cleanUrl = url.trim().toLowerCase();

    // Heuristic Analysis Simulation
    let status = 'CLEAN';
    let reputationScore = 100;
    let threatFlags = 0;

    const suspiciousKeywords = ['login', 'verify', 'account', 'secure', 'update', 'banking', 'signin', 'support'];
    const suspiciousTlds = ['.xyz', '.top', '.ru', '.cn', '.tk', '.ml', '.gq'];

    let matchedKeywords = 0;
    suspiciousKeywords.forEach(keyword => {
      if (cleanUrl.includes(keyword)) matchedKeywords++;
    });

    const hasSuspiciousTld = suspiciousTlds.some(tld => cleanUrl.endsWith(tld) || cleanUrl.includes(`${tld}/`));
    const isIpAddress = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(cleanUrl);

    if (isIpAddress || matchedKeywords >= 2 || hasSuspiciousTld) {
      status = 'HIGH RISK';
      reputationScore = 35;
      threatFlags = matchedKeywords + (isIpAddress ? 2 : 1) + (hasSuspiciousTld ? 2 : 0);
    } else if (matchedKeywords === 1) {
      status = 'SUSPICIOUS';
      reputationScore = 75;
      threatFlags = 1;
    }

    return res.json({
      url: url.trim(),
      status,
      reputationScore,
      threatFlags,
      scannedAt: new Date().toISOString()
    });

  } catch (err) {
    console.error('Scan processing error:', err);
    return res.status(500).json({
      error: 'Internal server error while processing the threat scan.'
    });
  }
});

// 4. Start Server
app.listen(PORT, () => {
  console.log(`Hyæt Views API server running on port ${PORT}`);
});

