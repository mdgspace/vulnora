
import requests
import jwt
import json
import base64
from datetime import datetime
import logging
from urllib.parse import urljoin, urlparse
import re
import time

logger = logging.getLogger(__name__)

# import requests 
# import time
import threading
from app.services.scanner import analyze_url_and_collect_logs
from app.services.path_traversal import check_path_traversal
from app.utils.call_llm import call_llm
from app.utils.get_user import get_user
from app.utils.reports import save_report
from app.services.jwt_manipulation_scan import JWTVulnerabilityTester
# import json
import pickle
# import base64
from app.services.sql_scan import run_sqlmap
import tempfile
import os
import subprocess
# import json

from app.services.csrf_scanner import scan_csrf_vulnerability

from app.services.file_upload import check_file_upload


from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import os
from datetime import datetime

from app.services.cmd_injection import check_cmd_injection

class DomainService:

    supported_attacks = {
        #"Cross-Site Scripting": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        "cmd_injection": "Command Injection",
        "jwt_vulnerabilities": "JWT Vulnerabilities",
        "path_traversal": "Path Traversal",
        #"csrf":"CSRF",
        "path_traversal":"Path Traversal",
        "insecure_deserialization":"Insecure Deserialization",
        #"command_injection":"Command Injection",
        "jwt":"JWT Manipulation",
        "ddos":"DDoS Attacks",
        "file_upload": "File Upload",
        "IP Scratching": "IP Scratching"
        # Add more attack types here
    }
    


    scan_results_cache = {}

    @staticmethod
    def _trim_logs_for_llm(attack_type, raw_logs, max_non_vuln=3, max_chars=500):
        def trunc(x):
            return x if not isinstance(x, str) or len(x) <= max_chars else x[:max_chars] + "...[truncated]"

        def summarise(item):
            if isinstance(item, dict):
                return {k: summarise(v) for k, v in list(item.items())[:15]}
            if isinstance(item, list):
                return [summarise(x) for x in item[:max_non_vuln]]
            return trunc(item)

        if isinstance(raw_logs, dict) and "detailed_logs" in raw_logs:
            logs = raw_logs["detailed_logs"]
            vuln = [summarise(l) for l in logs if isinstance(l, dict) and l.get("vulnerable")]
            nonv = [summarise(l) for l in logs if not (isinstance(l, dict) and l.get("vulnerable"))][:max_non_vuln]
            out = {k: summarise(v) for k, v in raw_logs.items() if k != "detailed_logs"}
            out["detailed_logs_trimmed"] = vuln + nonv
            out["detailed_logs_count"] = len(logs)
            return out

        if isinstance(raw_logs, dict):
            return {k: summarise(v) for k, v in list(raw_logs.items())[:15]}

    # Handle list
        if isinstance(raw_logs, list):
            return [summarise(x) for x in raw_logs[:max_non_vuln]]
        
        return trunc(str(raw_logs))


    @staticmethod
    def scan_domain(domain, attacks, vuln_endpoint, upload_endpoint):
        results = {}

        for attack in attacks:
            print(attack)
            if attack == "Cross-Site Scripting":
                results['Cross-Site Scripting'] = DomainService.check_xss(domain)
            elif attack == "sql_injection":
                results['sql_injection'] = run_sqlmap(domain)
            elif attack == "cmd_injection":
                results['cmd_injection'] = check_cmd_injection(domain) 
            elif attack == "jwt_vulnerabilities":
                results['jwt_vulnerabilities'] = DomainService.check_jwt_vulnerabilities(domain)
            elif attack == "IP Scratching":
                results['IP Scratching'] = analyze_url_and_collect_logs(domain)
            elif attack == "csrf":
                results['csrf'] = DomainService.check_csrf(domain) 
            # elif attack == "path_traversal":
            #     results['path_traversal'] = DomainService.check_path_traversal(domain) 
            elif attack == "insecure_deserialization":
                results['insecure_deserialization'] = DomainService.check_insecure_deserialization(domain) 
            # elif attack == "command_injection":
            #     results['command_injection'] = DomainService.check_command_injection(domain) 
            elif attack == "jwt":
                results['jwt'] = DomainService.check_jwt_vulnerabilities(domain) 
            elif attack == "ddos":
                results['ddos'] = DomainService.check_ddos(domain) 
            elif attack == "file_upload":
                results['file_upload'] = check_file_upload(domain, upload_endpoint)
            elif attack == "path_traversal":
                results['path_traversal'] = check_path_traversal(domain, vuln_endpoint) 
            # Add more attack types here
            else:
                results[attack] = "Unknown attack type"

            for key, value in results.items():
                print(f"{key} result:")
                print(json.dumps(value, indent=4))
                print() 


        llm_results = json.loads(json.dumps(results, default=str))

        for attack_type in llm_results.keys():
            llm_results[attack_type] = DomainService._trim_logs_for_llm(attack_type, llm_results[attack_type])


        numOfvul = len(results)
        DomainService.scan_results_cache[domain] = {
             "domain": domain, 
             "results": results,
             "timestamp": datetime.now().isoformat()
        }
        
        scan_data = {
            "domain": domain, 
            "results": llm_results, 
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
        return {"result" :DomainService.scan_results_cache[domain], "llm_response": llm_response}


    @staticmethod
    def check_xss(domain):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "xss_report.json")
            try:
                # we are using a subservice to run the command and then storing the result on temp path in a temp json file
                command = [
                    'wapiti',
                    '-u', domain, #used to specify domain on which attack is being done, taken as parameter
                    '--module', 'xss', #used to specify which type of attack to be done
                    '--level', '2', #used to specify level of attack              
                    '-f', 'json', 
                    '-o', report_path, #used to specify path at which report is created
                    '-v', '2' #used to specify verbose of the attack (level of detail)
                    #higher levels of verbose and level will slow down o/p of subprocess                   
                ]
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=180,
                    encoding='utf-8', #some issue was coming in encoding in a specific test and so had to use utf-8
                    errors='replace'
                )

                if os.path.exists(report_path):
                    with open(report_path, 'r') as f:
                        report = json.load(f)
                        result = report.get("vulnerabilities", {}).get("Reflected Cross Site Scripting", "No XSS issues found")
                        return result
                        
                else:
                    return f"No XSS report generated.\nOutput:\n{result.stdout}\nErrors:\n{result.stderr}"

            except subprocess.TimeoutExpired:
                return "Wapiti XSS scan timed out"
            except Exception as e:
                return f"Error during Wapiti XSS scan: {str(e)}"

    
    @staticmethod
    def check_jwt_vulnerabilities(domain):
        try:
            tester = JWTVulnerabilityTester()
            # Ensure proper URL format
            if not domain.startswith(('http://', 'https://')):
                domain = 'https://' + domain
            
            results = tester.test_url(domain, include_brute_force=False)
            return results
        except Exception as e:
            logger.error(f"Error testing JWT vulnerabilities for {domain}: {e}")
            return {"error": f"Failed to test JWT vulnerabilities: {str(e)}"}
    
    
    @staticmethod
    def check_insecure_deserialization(domain):

        test_results = {}

        # Payload: harmless but detectable on server
        class TestPayload:
            def __reduce__(self):
                return (print, ("[!] Deserialization Triggered",))

        payload = pickle.dumps(TestPayload())
        encoded_payload = base64.b64encode(payload).decode()

        try:
            # Send payload as part of a cookie, header, or POST param
            headers = {'Content-Type': 'application/octet-stream'}
            r = requests.post(domain, data=payload, headers=headers, timeout=5)

            # Logic for attack detection
            if r.status_code == 500 or "[!]" in r.text:
                test_results['status'] = 'Possible vulnerability detected'
            else:
                test_results['status'] = 'No obvious vulnerability'

        except requests.exceptions.RequestException as e:
            test_results['error'] = str(e)

        return test_results
    
    
    @staticmethod
    def check_csrf(domain):
        return scan_csrf_vulnerability(domain)

    # @staticmethod
    # def check_path_traversal(domain):
    #     # Mock logic for path traversal vulnerability
    #     return "Potential path traversal vulnerability found"
 
    
    
    @staticmethod
    def check_file_upload(domain):
        # Mock logic for file_upload vulnerability
        return "Potential file_upload vulnerability found"

    @staticmethod
    def check_ddos(domain):
        # Mock logic for ddos vulnerability
        return "Potential ddos vulnerability found" 

    @classmethod
    def get_supported_attacks(cls):
        return cls.supported_attacks
    
    @staticmethod
    def generate_pdf_report(domain):
        scan_data = DomainService.scan_results_cache.get(domain)
        if not scan_data:
            raise Exception("No scan data found for this domain")
        pdf_dir = "static/reports"
        os.makedirs(pdf_dir, exist_ok=True)
    
        # Generate PDF filename
        safe_domain = domain.replace('/', '_').replace(':', '_')
        pdf_filename = f"{safe_domain}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = os.path.join(pdf_dir, pdf_filename)
    
        # Create PDF
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
    
        # Title
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
            attack_name = DomainService.supported_attacks.get(attack_type, attack_type.replace('_', ' ').title())
            story.append(Paragraph(f"<b>{attack_name}:</b>", styles['Heading3']))

            # Convert result to string safely
            if isinstance(result, dict) or isinstance(result, list):
                from html import escape
                import json
                result_str = json.dumps(result, indent=2)
                result_str = escape(result_str).replace('\n', '<br/>').replace(' ', '&nbsp;')
            else:
                result_str = str(result)

            story.append(Paragraph(result_str, styles['Normal']))
            story.append(Spacer(1, 12))
    
        doc.build(story)

        # Return the API download URL
        return f"http://localhost:5001/api/download/{pdf_filename}"

