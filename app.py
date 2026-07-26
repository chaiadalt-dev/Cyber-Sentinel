import os
import json
import hashlib
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber-sentinel-core-engine-key'

# --- Threat Intelligence Baseline ---
THREAT_INTEL = {
    "suspicious_paths": [
        "/data/local/tmp/",
        "/system/bin/rtbuddyd"
    ],
    "known_spyware_hashes": [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # Example hash
    ]
}

def scan_file(file_name, file_hash, file_path):
    """
    Mock function to represent the core scanning engine.
    In production, this interfaces with YARA, VT, and static analysis models.
    """
    report = {"filename": file_name, "status": "CLEAN", "indicators": []}
    
    # Check Path
    if any(path in file_path for path in THREAT_INTEL["suspicious_paths"]):
        report["status"] = "SUSPICIOUS"
        report["indicators"].append("Found in highly sensitive directory")
        
    # Check Hash against Threat Intel
    if file_hash in THREAT_INTEL["known_spyware_hashes"]:
        report["status"] = "CRITICAL"
        report["indicators"].append("Hash matches known Advanced Persistent Threat (APT)")
        
    return report

@app.route('/')
def dashboard():
    return jsonify({"service": "Cyber Sentinel Core Engine", "status": "Active", "engine_version": "2.0.4"})

@app.route('/api/scan', methods=['POST'])
def run_scan():
    """
    API Endpoint for submitting files for deep forensic analysis.
    """
    data = request.get_json()
    if not data or 'filename' not in data or 'hash' not in data:
        return jsonify({"error": "Invalid payload. Required fields: 'filename', 'hash', 'path'"}), 400
        
    result = scan_file(data['filename'], data['hash'], data.get('path', '/unknown/'))
    return jsonify({"scan_result": result})

if __name__ == '__main__':
    # Running securely on localhost. Do not expose in production without proper WSGI.
    print("[+] Cyber Sentinel Engine initialized.")
    app.run(host='127.0.0.1', port=5006)
