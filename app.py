from flask import Flask, render_template, request, jsonify
import requests
import re
import os
import base64

app = Flask(__name__)

# --- CONFIGURATION LAYER ---
# Free public API Key for global lookups (Optional)
# Get a free key from virustotal.com and set it in Termux environment or paste below
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_FREE_VIRUSTOTAL_API_KEY_HERE")

# --- NATIVE HEURISTIC ENGINES ---
BLOCKLIST_KEYWORDS = [
    "malware", "phishing", "virus-link", "get-free-money", 
    "credential-update", "secure-login-bank", "bit.ly/fake"
]

SUSPICIOUS_TLDS = [".top", ".xyz", ".click", ".gq", ".tk", ".cf", ".fit"]

def run_local_heuristics(target):
    """
    Analyzes targets offline using pattern recognition and signature keyword vectors.
    Returns: (is_flagged, threat_reason)
    """
    target_lower = target.lower()
    
    # 1. Signature Pattern Checks
    for keyword in BLOCKLIST_KEYWORDS:
        if keyword in target_lower:
            return True, f"Matched internal threat blocklist signature: [{keyword}]"
            
    # 2. Suspicious Top-Level Domain (TLD) Extraction Checks
    for tld in SUSPICIOUS_TLDS:
        if target_lower.endswith(tld) or f"{tld}/" in target_lower:
            return True, f"Untrusted high-risk Top-Level Domain detected: [{tld}]"
            
    # 3. Structural Obfuscation Verification (IP-Literal addresses replacing domain text)
    ip_pattern = r'^(https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    if re.match(ip_pattern, target_lower):
        return True, "Obfuscated network footprint bypass vector detected (Raw IP Literal Routing)."

    return False, "Passed clean local baseline parameters."


# --- CLOUD INTEL PASSAGE ENGINE (VirusTotal v3 API Wrapper) ---
def check_cloud_reputation(target):
    """
    Safely routes target hashes to VirusTotal API v3 endpoints.
    Defaults gracefully to local heuristics if cloud configurations are empty or down.
    """
    if not VT_API_KEY or "YOUR_FREE" in VT_API_KEY:
        return None  # Pass down the stack silently to use local engine execution fallback

    try:
        # VirusTotal v3 URLs endpoint requires target URLs to be converted to safe base64 strings (without '=' padding)
        url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
        api_endpoint = f"https://virustotal.com{url_id}"
        
        headers = {
            "x-apikey": VT_API_KEY, # Explicit required security passport
            "accept": "application/json"
        }
        
        # Dispatch short-timeout API request to avoid holding up the UI threads
        response = requests.get(api_endpoint, headers=headers, timeout=5)
        
        if response.status_code == 200:
            json_data = response.json()
            # Extract last analysis stats object mapping across individual vendor engines
            stats = json_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_hits = stats.get("malicious", 0) + stats.get("phishing", 0)
            
            if malicious_hits > 0:
                return {
                    "status": "malicious",
                    "reason": f"Cloud Threat Intel Alert! Flagged by {malicious_hits} global antivirus vendor engines."
                }
            return {
                "status": "safe",
                "reason": "Verified clean across global cybersecurity database arrays."
            }
            
        elif response.status_code == 404:
            # URL hasn't been scanned by VirusTotal yet - Request asynchronous remote scanning dispatch
            scan_endpoint = "https://virustotal.com"
            requests.post(scan_endpoint, headers=headers, data={"url": target}, timeout=4)
            return None # Revert context processing safety back to local heuristic engines

    except Exception as network_error:
        print(f"[DEBUG LOG] Cloud API route timed out or encountered errors: {network_error}")
        
    return None


# --- HTTP APPLICATION ROUTING CHANNELS ---
@app.route('/')
def serve_frontend_dashboard():
    """Renders the graphical theme-engine user-interface."""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def process_scan_request():
    """
    Secure API gateway endpoint handling data traffic passed by application event click components.
    """
    request_payload = request.get_json()
    
    # 1. Structural Sanity Verification Guard Rails
    if not request_payload or 'url' not in request_payload:
        return jsonify({"status": "error", "message": "Malformed request formatting layout."}), 400
        
    raw_target = str(request_payload['url']).strip()
    if not raw_target:
        return jsonify({"status": "error", "message": "Input stream target target vector cannot be empty."}), 400

    # 2. Pipeline Stage 1: Cloud Reputation Lookup Check
    cloud_result = check_cloud_reputation(raw_target)
    if cloud_result:
        return jsonify(cloud_result)

    # 3. Pipeline Stage 2: Fallback to Heuristic Engine Arrays
    is_malicious, verdict_reason = run_local_heuristics(raw_target)
    
    if is_malicious:
        return jsonify({
            "status": "malicious",
            "reason": verdict_reason
        })
        
    return jsonify({
        "status": "safe",
        "reason": verdict_reason
    })


if __name__ == '__main__':
    # Initialize the engine loop locally on internal sandbox loop parameters (Port 5000)
    print("*" * 60)
    print(" Hyæt Views Engine Backend active on: http://127.0.0.1:5000")
    print(" Running securely via Termux Linux environment framework virtualization.")
    print("*" * 60)
    app.run(host='127.0.0.1', port=5000, debug=True)

