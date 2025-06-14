import requests
import pickle
import base64

import tempfile
import os
import subprocess
import json

from app.services.csrf_scanner import scan_csrf_vulnerability

from app.services.file_upload import check_file_upload


class DomainService:

    supported_attacks = {
        "Cross-Site Scripting": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        "csrf":"CSRF",
        "path_traversal":"Path Traversal",
        "insecure_deserialization":"Insecure Deserialization",
        "command_injection":"Command Injection",
        "jwt":"JWT Manipulation",
        "ddos":"DDoS Attacks",
        "file_upload": "File Upload",
        # Add more attack types here
    }

    @staticmethod
    def scan_domain(domain, attacks, upload_endpoint):
        results = {}

        for attack in attacks:
            print(attack)
            if attack == "Cross-Site Scripting":
                results['Cross-Site Scripting'] = DomainService.check_xss(domain)
            elif attack == "sql_injection":
                results['sql_injection'] = DomainService.check_sql_injection(domain)
            elif attack == "csrf":
                results['csrf'] = DomainService.check_csrf(domain)            
            elif attack == "path_traversal":
                results['path_traversal'] = DomainService.check_path_traversal(domain)            
            elif attack == "insecure_deserialization":
                results['insecure_deserialization'] = DomainService.check_insecure_deserialization(domain)            
            elif attack == "command_injection":
                results['command_injection'] = DomainService.check_command_injection(domain)            
            elif attack == "jwt":
                results['jwt'] = DomainService.check_jwt(domain)            
            elif attack == "ddos":
                results['ddos'] = DomainService.check_ddos(domain)           
            elif attack == "file_upload":
                results['file_upload'] = check_file_upload(domain, upload_endpoint)   
            # Add more attack types here
            else:
                results[attack] = "Unknown attack type"


        numOfvul = len(results)
        return {
            "domain": domain, 
            "results": results
        }


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
                    '--level', '2',     #used to specify level of attack              
                    '-f', 'json',       
                    '-o', report_path,  #used to specify path at which report is created
                    '-v', '2'           #used to specify verbose of the attack (level of detail)
                    #higher levels of verbose and level will slow down o/p of subprocess                   
                ]
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=180,
                    encoding='utf-8',   #some issue was coming in encoding in a specific test and so had to use utf-8
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
        # Mock logic for SQLi vulnerability
        return "Potential SQL injection found"
    
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

    @staticmethod
    def check_path_traversal(domain):
        # Mock logic for path traversal vulnerability
        return "Potential path traversal vulnerability found"
    
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