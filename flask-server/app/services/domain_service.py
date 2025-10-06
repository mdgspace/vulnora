import requests
import json
import base64
import pickle
import os
from datetime import datetime
import logging
from html import escape

from app.utils.trim_logs import trim_logs_for_llm
from app.services.scanner import analyze_url_and_collect_logs
from app.services.path_traversal import check_path_traversal
from app.utils.call_llm import call_llm
from app.utils.get_user import get_user
from app.utils.reports import save_report
from app.services.jwt_manipulation_scan import JWTVulnerabilityTester
from app.services.sql_scan import run_sqlmap
from app.services.file_upload import check_file_upload
from app.services.cmd_injection import check_cmd_injection

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

logger = logging.getLogger(__name__)

scan_results_cache = {}

supported_attacks = {
    "sql_injection": "SQL Injection",
    "cmd_injection": "Command Injection",
    "jwt_vulnerabilities": "JWT Vulnerabilities",
    "path_traversal": "Path Traversal",
    "insecure_deserialization": "Insecure Deserialization",
    "jwt": "JWT Manipulation",
    "ddos": "DDoS Attacks",
    "file_upload": "File Upload",
    "IP Scratching": "IP Scratching"
}

def check_jwt_vulnerabilities(domain):
    try:
        tester = JWTVulnerabilityTester()
        if not domain.startswith(('http://', 'https://')):
            domain = 'https://' + domain
        return tester.test_url(domain, include_brute_force=False)
    except Exception as e:
        logger.error(f"Error testing JWT vulnerabilities for {domain}: {e}")
        return {"error": f"Failed to test JWT vulnerabilities: {str(e)}"}

def check_insecure_deserialization(domain):
    test_results = {}

    class TestPayload:
        def __reduce__(self):
            return (print, ("[!] Deserialization Triggered",))

    payload = pickle.dumps(TestPayload())

    try:
        r = requests.post(domain, data=payload, headers={'Content-Type': 'application/octet-stream'}, timeout=5)
        if r.status_code == 500 or "[!]" in r.text:
            test_results['status'] = 'Possible vulnerability detected'
        else:
            test_results['status'] = 'No obvious vulnerability'
    except requests.exceptions.RequestException as e:
        test_results['error'] = str(e)

    return test_results

def check_ddos(domain):
    return "Potential ddos vulnerability found"

def scan_domain(domain, attacks, vuln_endpoint=None, upload_endpoint=None):
    results = {}

    for attack in attacks:
        print(f"Running scan for: {attack}")
        if attack == "sql_injection":
            results['sql_injection'] = run_sqlmap(domain)
        elif attack == "cmd_injection":
            results['cmd_injection'] = check_cmd_injection(domain)
        elif attack in ["jwt_vulnerabilities", "jwt"]:
            results['jwt_vulnerabilities'] = check_jwt_vulnerabilities(domain)
        elif attack == "IP Scratching":
            results['IP Scratching'] = analyze_url_and_collect_logs(domain)
        elif attack == "insecure_deserialization":
            results['insecure_deserialization'] = check_insecure_deserialization(domain)
        elif attack == "ddos":
            results['ddos'] = check_ddos(domain)
        elif attack == "file_upload":
            results['file_upload'] = check_file_upload(domain, upload_endpoint)
        elif attack == "path_traversal":
            results['path_traversal'] = check_path_traversal(domain, vuln_endpoint)
        else:
            results[attack] = "Unknown attack type"

        for key, value in results.items():
            print(f"{key} result:")
            print(json.dumps(value, indent=4))
            print()

    pass_to_llm_data = {k: trim_logs_for_llm(k, v) for k, v in results.items()}

    scan_results_cache[domain] = {
        "domain": domain,
        "results": results,
        "timestamp": datetime.now().isoformat()
    }

    scan_data = {
        "domain": domain,
        "results": pass_to_llm_data,
        "timestamp": datetime.now().isoformat()
    }

    llm_response = call_llm(scan_data)
    user_id = get_user()
    print("[REPORT INSERT] user_id=", user_id)

    report_doc = {
        "user_id": user_id,
        "website": domain,
        "tags": list(results.keys()),
        "report": llm_response,
        "created_at": datetime.now().timestamp()
    }
    save_report(report_doc)

    return {"result": scan_results_cache[domain], "llm_response": llm_response}

def get_supported_attacks():
    return supported_attacks

def generate_pdf_report(domain):
    scan_data = scan_results_cache.get(domain)
    if not scan_data:
        raise Exception("No scan data found for this domain")

    pdf_dir = "static/reports"
    os.makedirs(pdf_dir, exist_ok=True)

    safe_domain = domain.replace('/', '_').replace(':', '_')
    pdf_filename = f"{safe_domain}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_path = os.path.join(pdf_dir, pdf_filename)

    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.darkblue
    )
    story.append(Paragraph("Vulnora Security Report", title_style))
    story.append(Spacer(1, 20))

    # Domain info
    story.append(Paragraph(f"<b>Domain:</b> {scan_data['domain']}", styles['Normal']))
    story.append(Paragraph(f"<b>Scan Date:</b> {scan_data['timestamp']}", styles['Normal']))
    story.append(Spacer(1, 20))

    # Results section
    story.append(Paragraph("Vulnerability Scan Results", styles['Heading2']))
    story.append(Spacer(1, 12))

    for attack_type, result in scan_data['results'].items():
        attack_name = supported_attacks.get(attack_type, attack_type.replace('_', ' ').title())
        story.append(Paragraph(f"<b>{attack_name}:</b>", styles['Heading3']))

        if isinstance(result, dict) or isinstance(result, list):
            result_str = json.dumps(result, indent=2)
            result_str = escape(result_str).replace('\n', '<br/>').replace(' ', '&nbsp;')
        else:
            result_str = str(result)

        story.append(Paragraph(result_str, styles['Normal']))
        story.append(Spacer(1, 12))

    doc.build(story)
    return f"http://localhost:5001/api/download/{pdf_filename}"
