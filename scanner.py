import requests
import json
import os
import re
import time
from datetime import datetime

# --- Configuration ---
# If you add API keys as GitHub Secrets, they will be pulled here.
TRONGRID_API_KEY = os.environ.get("TRONGRID_API_KEY", "")
TRONSCAN_API_KEY = os.environ.get("TRONSCAN_API_KEY", "")

SUSPICIOUS_ABI_PATTERNS = ["Verify20", "Verify10", "WalletChecking", "trc20Withdraw"]
VULNERABILITY_PATTERNS = {
    "Ignored TransferFrom Parameter": r"function\s+transferFrom\s*\([^)]*address\s+_?from[^)]*\)[^{]*\{[^}]*transferFrom\s*\(\s*msg\.sender",
    "Reentrancy Risk": r"\.call\{.*?\}\(.*?\);(?:(?!\b(?:balances|_balances|state|mapping)\b).)*",
    "Dangerous Delegatecall": r"\.delegatecall\(",
    "Unprotected Selfdestruct": r"selfdestruct\(",
    "tx.origin Phishing": r"tx\.origin"
}

def get_recent_contracts():
    # Fetch newest verified contracts
    url = "https://apilist.tronscanapi.com/api/contracts?verified-only=true&limit=50&sort=-timestamp"
    headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY}
    try:
        res = requests.get(url, headers=headers, timeout=10)
        return res.json().get("data", [])
    except:
        return []

def get_contract_abi(contract_address):
    url = f"https://apilist.tronscanapi.com/api/contract?contract={contract_address}"
    headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY}
    try:
        res = requests.get(url, headers=headers, timeout=10)
        return res.json()
    except:
        return {}

def scan_contract_code(source_code):
    findings = []
    if not source_code:
        return findings
    normalized = re.sub(r'\s+', ' ', source_code)
    for vuln, pattern in VULNERABILITY_PATTERNS.items():
        if re.search(pattern, normalized, re.IGNORECASE):
            findings.append(vuln)
    return findings

def main():
    print("[*] Starting scan...")
    contracts = get_recent_contracts()
    flagged_results = []
    
    # Load existing database if it exists to avoid duplicates
    existing_data = {}
    if os.path.exists("flagged_contracts.json"):
        with open("flagged_contracts.json", "r") as f:
            try:
                existing_data = json.load(f)
            except:
                pass

    for c in contracts:
        addr = c.get("contract_address")
        name = c.get("name", "Unknown")
        if not addr: continue
        
        data = get_contract_abi(addr)
        abi = data.get("abi", "")
        source = data.get("source_code", "")
        
        # 1. Check for malicious drainer ABI patterns
        abi_matches = [p for p in SUSPICIOUS_ABI_PATTERNS if p in abi]
        
        # 2. Check for coding loopholes
        code_vulns = scan_contract_code(source)
        
        if abi_matches or code_vulns:
            flagged_results.append({
                "name": name,
                "address": addr,
                "tronscan_url": f"https://tronscan.org/#/contract/{addr}/code",
                "drainer_patterns": abi_matches,
                "code_vulnerabilities": code_vulns,
                "scanned_at": str(datetime.now())
            })
            print(f"🚨 Flagged: {name} ({addr})")

    # Save results
    existing_data["last_scan"] = str(datetime.now())
    if "vulnerable_contracts" not in existing_data:
        existing_data["vulnerable_contracts"] = []
        
    existing_data["vulnerable_contracts"].extend(flagged_results)
    
    # Keep only the latest 100 to prevent file from getting too big
    existing_data["vulnerable_contracts"] = existing_data["vulnerable_contracts"][-100:]

    with open("flagged_contracts.json", "w") as f:
        json.dump(existing_data, f, indent=4)
        
    print(f"[*] Scan complete. Total vulnerable tracked: {len(existing_data['vulnerable_contracts'])}")

if __name__ == "__main__":
    main()
