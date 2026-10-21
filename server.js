require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 8000;

// 1. Core Security & Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// 2. Neon PostgreSQL Database Connection
const pool = new Pool({
  connectionString: process.env.NEON_DATABASE_URL,
  ssl: {
    rejectUnauthorized: true, // Enforces full verification instead of false
  }
});

// Test the Neon database connection on server startup
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Neon PostgreSQL connection error:', err.stack);
  } else {
    console.log('Connected to Neon PostgreSQL successfully at:', res.rows[0].now);
  }
});

// 3. Health Check Endpoint
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'Hyæt Views Threat Detection API with Neon DB',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// 4. Scan Endpoint with Optional Neon Logging
app.post('/scan', async (req, res) => {
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

    const scanResult = {
      url: url.trim(),
      status,
      reputationScore,
      threatFlags,
      scannedAt: new Date().toISOString()
    };

    // Optional: Log scan results into Neon PostgreSQL if a table exists
    try {
      await pool.query(
        'INSERT INTO scan_logs (url, status, score, flags, created_at) VALUES ($1, $2, $3, $4, NOW()) ON CONFLICT DO NOTHING',
        [scanResult.url, scanResult.status, scanResult.reputationScore, scanResult.threatFlags]
      );
    } catch (dbErr) {
      // Non-blocking fallback if the table hasn't been manually migrated yet
      console.warn('Note: Scan result not saved to DB table (table may not exist yet):', dbErr.message);
    }

    return res.json(scanResult);

  } catch (err) {
    console.error('Scan processing error:', err);
    return res.status(500).json({
      error: 'Internal server error while processing the threat scan.'
    });
  }
});

// 5. Start Server
app.listen(PORT, () => {
  console.log(`Hyæt Views API server running on port ${PORT}`);
});

