require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { Pool } = require("pg");
const { analyzeTarget } = require("./engine");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "1mb" }));

function cleanDatabaseUrl(raw) {
  if (typeof raw !== "string") return "";
  return raw.trim().replace(/^['"]+|['"]+$/g, "");
}

const connectionString = cleanDatabaseUrl(process.env.NEON_DATABASE_URL || process.env.DATABASE_URL || "");
let pool = null;

if (connectionString) {
  pool = new Pool({
    connectionString,
    ssl: { rejectUnauthorized: true },
    max: 5,
    connectionTimeoutMillis: 8000
  });
  pool.on("error", (err) => {
    console.warn("Neon pool error:", err.message);
  });
}

async function ensureSchema() {
  if (!pool) {
    console.warn("NEON_DATABASE_URL is empty. Scans will still run, but nothing will be stored.");
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scan_logs (
      id BIGSERIAL PRIMARY KEY,
      url TEXT NOT NULL,
      status TEXT NOT NULL,
      score INTEGER NOT NULL,
      flags INTEGER NOT NULL,
      reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS reasons JSONB NOT NULL DEFAULT '[]'::jsonb`);
  console.log("scan_logs table is ready");
}

async function saveScan(result) {
  if (!pool) return false;
  const reasons = JSON.stringify(result.reasons || []);
  try {
    await pool.query(
      `INSERT INTO scan_logs (url, status, score, flags, reasons, created_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, NOW())`,
      [result.url, result.status, result.reputationScore, result.threatFlags, reasons]
    );
    return true;
  } catch (err) {
    try {
      await pool.query(
        `INSERT INTO scan_logs (url, status, score, flags, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [result.url, result.status, result.reputationScore, result.threatFlags]
      );
      return true;
    } catch (fallbackErr) {
      console.warn("Database logging warning:", fallbackErr.message);
      return false;
    }
  }
}

function publicResult(result, logged) {
  return {
    url: result.url,
    status: result.status,
    reputationScore: result.reputationScore,
    threatFlags: result.threatFlags,
    reasons: result.reasons,
    checks: result.checks,
    scannedAt: result.scannedAt,
    logged
  };
}

app.get("/", (req, res) => {
  res.json({
    status: "online",
    service: "Hyæt Views Threat Detection API",
    version: "1.2.0",
    database: Boolean(pool),
    timestamp: new Date().toISOString()
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "online", database: Boolean(pool) });
});

app.post("/scan", async (req, res) => {
  try {
    const url = req.body && req.body.url;
    if (typeof url !== "string" || !url.trim()) {
      return res.status(400).json({ error: 'A valid "url" string is required.' });
    }
    const result = analyzeTarget(url);
    const logged = result.checks.some((check) => check.id === "parse" && check.hit) ? false : await saveScan(result);
    return res.json(publicResult(result, logged));
  } catch (err) {
    console.error("Scan processing error:", err);
    return res.status(500).json({ error: "Internal server error during scan." });
  }
});

app.post("/scan/batch", async (req, res) => {
  try {
    const urls = req.body && req.body.urls;
    if (!Array.isArray(urls) || urls.length < 1 || urls.length > 20) {
      return res.status(400).json({ error: "Provide between 1 and 20 urls." });
    }
    const results = [];
    for (const url of urls) {
      if (typeof url !== "string" || !url.trim()) continue;
      const result = analyzeTarget(url);
      const logged = await saveScan(result);
      results.push(publicResult(result, logged));
    }
    if (!results.length) return res.status(400).json({ error: "No usable urls in the batch." });
    return res.json({ results });
  } catch (err) {
    console.error("Batch scan error:", err);
    return res.status(500).json({ error: "Internal server error during batch scan." });
  }
});

app.get("/history", async (req, res) => {
  if (!pool) return res.json({ logs: [] });
  try {
    const { rows } = await pool.query(
      `SELECT url, status, score AS "reputationScore", flags AS "threatFlags",
              COALESCE(reasons, '[]'::jsonb) AS reasons, created_at AS "scannedAt"
       FROM scan_logs
       ORDER BY created_at DESC
       LIMIT 20`
    );
    return res.json({ logs: rows });
  } catch (err) {
    console.warn("History read warning:", err.message);
    return res.json({ logs: [] });
  }
});

ensureSchema()
  .catch((err) => {
    console.warn("Schema setup warning:", err.message);
  })
  .finally(() => {
    app.listen(PORT, () => {
      console.log("Hyæt Views API server running on port " + PORT);
    });
  });
