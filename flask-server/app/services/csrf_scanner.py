import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scan_csrf_vulnerability(domain):
    """
    Scans the domain's homepage for forms missing CSRF tokens.
    """
    try:
        res = requests.get(domain, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        forms = soup.find_all('form')
        report = []

        for i, form in enumerate(forms, start=1):
            method = form.get('method', 'get').lower()
            action = form.get('action', '')
            full_action = urljoin(domain, action)
            inputs = form.find_all('input')

            has_csrf = any(
                inp.get('name') and 'csrf' in inp.get('name').lower()
                for inp in inputs
            )

            if method == 'post' and not has_csrf:
                report.append({
                    "form_number": i,
                    "action": full_action,
                    "issue": "No CSRF token found"
                })

        if report:
            return {
                "status": "Potential CSRF vulnerability found",
                "details": report
            }
        else:
            return {
                "status": "No CSRF vulnerabilities found"
            }

    except Exception as e:
        return {
            "status": "Error during CSRF check",
            "error": str(e)
        }
