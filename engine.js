/**
 * Hyæt Views heuristic engine.
 * Shared by server.js (Node) and the browser bundle (global HyaetEngine).
 * Drop this file in next to server.js and index.html.
 */
const HyaetEngine = (function () {
  const RISKY_TLDS = [
    ".zip", ".mov", ".top", ".xyz", ".ru", ".cn", ".tk", ".ml", ".gq", ".cf",
    ".buzz", ".click", ".country", ".download", ".work", ".loan", ".racing",
    ".review", ".faith", ".date", ".party", ".science", ".win", ".icu",
    ".rest", ".monster", ".cfd", ".sbs"
  ];

  const KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "account", "secure", "update", "banking", "password", "wallet",
    "invoice", "unlock", "confirm", "webscr", "oauth", "credential",
    "suspended", "limited", "reset", "passwd"
  ];

  const BRANDS = [
    { name: "PayPal", token: "paypal", official: ["paypal.com"] },
    { name: "Microsoft", token: "microsoft", official: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "office365.com"] },
    { name: "Google", token: "google", official: ["google.com", "gmail.com", "youtube.com", "googleusercontent.com"] },
    { name: "Apple", token: "apple", official: ["apple.com", "icloud.com"] },
    { name: "Amazon", token: "amazon", official: ["amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com"] },
    { name: "Netflix", token: "netflix", official: ["netflix.com"] },
    { name: "Facebook", token: "facebook", official: ["facebook.com", "fb.com", "meta.com", "instagram.com"] },
    { name: "WhatsApp", token: "whatsapp", official: ["whatsapp.com"] },
    { name: "Instagram", token: "instagram", official: ["instagram.com"] }
  ];

  function isOfficial(host, suffixes) {
    return suffixes.some((suffix) => host === suffix || host.endsWith("." + suffix));
  }

  function finish(url, checks) {
    const hits = checks.filter((check) => check.hit);
    const penalty = hits.reduce((sum, check) => sum + check.weight, 0);
    const reputationScore = Math.max(0, Math.min(100, 100 - penalty));
    const keywordCheck = checks.find((check) => check.id === "keywords");
    const keywordExtra = keywordCheck && keywordCheck.hit ? keywordCheck.extra || 0 : 0;
    const threatFlags = hits.length + keywordExtra;
    const critical = hits.some((check) => check.critical);
    let status = "CLEAN";
    if (reputationScore < 60 || threatFlags >= 2 || critical) status = "HIGH RISK";
    else if (threatFlags > 0) status = "SUSPICIOUS";

    return {
      url,
      status,
      reputationScore,
      threatFlags,
      reasons: hits.map((check) => check.detail),
      checks: checks.map((check) => ({
        id: check.id,
        label: check.label,
        hit: check.hit,
        weight: check.weight,
        detail: check.detail
      })),
      scannedAt: new Date().toISOString()
    };
  }

  function analyzeTarget(rawInput) {
    const original = String(rawInput || "").trim();
    const checks = [];

    function add(id, label, hit, weight, detail, critical, extra) {
      checks.push({
        id,
        label,
        hit: Boolean(hit),
        weight: hit ? weight : 0,
        detail,
        critical: Boolean(hit && critical),
        extra: extra || 0
      });
    }

    if (!original || original.length > 2000) {
      add("parse", "URL structure", true, 50, original ? "Target is longer than 2000 characters" : "Empty target", true, 0);
      return finish(original, checks);
    }

    let candidate = original;
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
      candidate = "http://" + candidate;
    }

    let parsed;
    try {
      parsed = new URL(candidate);
    } catch (err) {
      add("parse", "URL structure", true, 50, "Target is not a valid URL or host", true, 0);
      return finish(original, checks);
    }

    const protocol = (parsed.protocol || "").replace(":", "").toLowerCase();
    const host = (parsed.hostname || "").toLowerCase();
    const path = ((parsed.pathname || "") + (parsed.search || "")).toLowerCase();
    const full = host + path;
    const identity = ((parsed.username || "") + (parsed.password || "")).toLowerCase();

    const badScheme = protocol === "javascript" || protocol === "data" || protocol === "file";
    if (badScheme) {
      add("scheme", "Scheme", true, 80, "Dangerous scheme " + protocol + ":", true, 0);
      return finish(parsed.href || original, checks);
    }

    if (!host) {
      add("parse", "URL structure", true, 50, "Target has no hostname", true, 0);
      return finish(original, checks);
    }

    add("scheme", "Scheme", false, 0, "Scheme is " + protocol, false, 0);

    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    const ipv6 = host.includes(":");
    add(
      "ip",
      "Raw IP hostname",
      ipv4 || ipv6,
      40,
      ipv4 || ipv6 ? "Host is a raw IP (" + host + "), common in phishing kits" : "Host is a domain name, not a raw IP",
      true,
      0
    );

    const tldHit = RISKY_TLDS.find((tld) => host.endsWith(tld));
    add(
      "tld",
      "High-risk TLD",
      Boolean(tldHit),
      25,
      tldHit ? "High-risk top-level domain " + tldHit : "TLD is not on the high-risk list",
      false,
      0
    );

    const officialAny = BRANDS.some((brand) => isOfficial(host, brand.official));
    let brandHit = null;
    for (let i = 0; i < BRANDS.length; i += 1) {
      const brand = BRANDS[i];
      const mentioned = host.includes(brand.token) || identity.includes(brand.token);
      if (mentioned && !isOfficial(host, brand.official)) {
        brandHit = brand;
        break;
      }
    }
    add(
      "brand",
      "Brand impersonation",
      Boolean(brandHit),
      45,
      brandHit
        ? "Mentions " + brandHit.name + " but " + host + " is not an official " + brandHit.name + " domain"
        : "No brand impersonation in the hostname",
      true,
      0
    );

    const foundKeywords = KEYWORDS.filter((keyword) => full.includes(keyword));
    const keywordHit = !officialAny && foundKeywords.length > 0;
    add(
      "keywords",
      "Phishing keywords",
      keywordHit,
      Math.min(66, foundKeywords.length * 22),
      keywordHit
        ? "Phishing keywords on an unofficial host: " + foundKeywords.slice(0, 5).join(", ")
        : officialAny && foundKeywords.length
          ? "Security words appear, but the host is a known official domain"
          : "No phishing keyword pattern",
      false,
      keywordHit ? Math.max(0, foundKeywords.length - 1) : 0
    );

    const labels = host.split(".").filter(Boolean);
    const deep = labels.length >= 5;
    add(
      "subdomains",
      "Subdomain nesting",
      deep,
      15,
      deep ? "Unusually deep host (" + labels.length + " labels)" : "Subdomain depth looks normal",
      false,
      0
    );

    const encodings = (parsed.href.match(/%[0-9a-f]{2}/gi) || []).length;
    const hasUser = Boolean(parsed.username || parsed.password);
    const puny = host.startsWith("xn--") || host.includes(".xn--");
    const obfuscated = hasUser || puny || encodings >= 4;
    let obfuscationDetail = "No userinfo, punycode, or heavy encoding";
    if (hasUser) obfuscationDetail = "URL hides the real host behind userinfo (@)";
    else if (puny) obfuscationDetail = "Punycode hostname (possible lookalike)";
    else if (encodings >= 4) obfuscationDetail = "Heavy percent-encoding (" + encodings + " sequences)";
    add("obfuscation", "Obfuscation", obfuscated, hasUser ? 35 : 20, obfuscationDetail, hasUser, 0);

    const insecure = protocol === "http" && (keywordHit || Boolean(brandHit));
    add(
      "transport",
      "Transport",
      insecure,
      10,
      insecure ? "Login-like page is served over plain HTTP" : protocol === "https" ? "HTTPS" : "Scheme is " + protocol,
      false,
      0
    );

    const longUrl = original.length > 180;
    add(
      "length",
      "URL length",
      longUrl,
      10,
      longUrl ? "Very long URL (" + original.length + " characters)" : "URL length is normal",
      false,
      0
    );

    return finish(parsed.href, checks);
  }

  return { analyzeTarget };
})();

globalThis.HyaetEngine = HyaetEngine;
if (typeof module !== "undefined" && module.exports) {
  module.exports = HyaetEngine;
}
