# HYÆT VIEWS — Real-Time Threat & Heuristic Link Security Engine

Hyæt Views is a full-stack, lightweight cross-platform cybersecurity utility designed to detect phishing links, high-risk URLs, structural obfuscation, and live malware domain threats in real time.

---

## Key Features

- **Hybrid Analysis Pipeline:** Combines a custom 5-point local heuristic engine with live threat intelligence database queries (URLHaus API).
- **5-Point Heuristic Check Engine:**
  1. *Raw IP Address Hostname Detection*
  2. *Abused & High-Risk TLD Filtering* (`.zip`, `.top`, `.xyz`, etc.)
  3. *Phishing Keyword Pattern Matcher* (`login`, `verify`, `bank`, etc.)
  4. *Excessive Subdomain Nesting Inspection*
  5. *URL Encoding & Path Obfuscation Analysis*
- **Batch Scanning Engine:** Sequential processing for multi-line target lists with progress feedback.
- **Session History & Persistence:** Remembers recent scans locally using browser `localStorage`.
- **Log Exporting:** Direct export of raw JSON security payloads or formatted text summary logs for reporting.
- **High-Contrast Dark Theme:** Optimized Cyber Gold (`#FFD700`), Alert Red (`#FF3B30`), and Obsidian Black interface.

---

## Tech Stack

- **Backend:** Node.js, Express.js
- **Frontend:** Plain JavaScript (ES6+), HTML5, Custom CSS3
- **External API:** URLHaus Threat Intelligence API (abuse.ch)

---

## Project Structure


