import requests 
import time
import threading

from app.services.path_traversal import check_path_traversal
import json
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
        "path_traversal": "Path Traversal",
        "csrf":"CSRF",
        "path_traversal":"Path Traversal",
        "insecure_deserialization":"Insecure Deserialization",
        "command_injection":"Command Injection",
        "jwt":"JWT Manipulation",
        "ddos":"DDoS Attacks",
        "file_upload": "File Upload",
        # Add more attack types here
    }
    
    SQLMAP_API = 'http://localhost:8775'

    @staticmethod
    def scan_domain(domain, attacks, vuln_endpoint, upload_endpoint):
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
            elif attack == "path_traversal":
                results['path_traversal'] = check_path_traversal(domain, vuln_endpoint)
            else:
                results[attack] = "Unknown attack type"

            for key, value in results.items():
                print(f"{key} result:")
                print(json.dumps(value, indent=4))  # nicely formatted
                print()  


        numOfvul = len(results)
        return {
            "domain": domain, 
            "results": results
        }

    # Define methods for checking vulnerabilities over here

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
        """SQL injection check using SQLMap"""
        try:
     
            task_res = requests.get(f'{DomainService.SQLMAP_API}/task/new')
            task_data = task_res.json()
            task_id = task_data.get('taskid')
            
            if not task_id:
                return {'error': 'Failed to create new task', 'status': 'error'}
            
   
            options_payload = {
                'options': {
                    'url': domain,
                    'batch': True,
                    'crawl': 3,
                    'randomAgent': True,
                    'threads': 5,
                    'risk': 2
                }
            }
            
            requests.post(f'{DomainService.SQLMAP_API}/option/{task_id}/set', json=options_payload)
            

            scan_payload = {'url': domain}
            requests.post(f'{DomainService.SQLMAP_API}/scan/{task_id}/start', json=scan_payload)
            

            thread = threading.Thread(target=DomainService._check_scan_status, args=(task_id,))
            thread.daemon = True
            thread.start()
            
       
            time.sleep(10)
            

            status_res = requests.get(f'{DomainService.SQLMAP_API}/scan/{task_id}/status')
            status_data = status_res.json()
            is_terminated = status_data.get('status') == 'terminated'
            
            if not is_terminated:
                return {
                    'status': 'running',
                    'message': 'Scan still in progress, try again later',
                    'task_id': task_id
                }
            
        
            log_res = requests.get(f'{DomainService.SQLMAP_API}/scan/{task_id}/log')
            log_data = log_res.json()
            log_entries = log_data.get('log', [])
            
            if not log_entries:
                return {
                    'status': 'completed',
                    'message': 'No log data found.'
                }
            
            
            full_log = ' '.join(entry.get('message', '') for entry in log_entries)
            words = full_log.strip().split()
            last_1000_words = ' '.join(words[-1000:])
            
            if "no parameter(s) found for testing" in last_1000_words:
                result = "NO VULNERABILITIES FOUND"
            else:
                result = "THERE ARE VULNERABILITIES"
            
            return {
                'status': 'completed',
                'result': result,
                'response': last_1000_words,
                'task_id': task_id
            }
            
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return {'error': f'Request error: {str(e)}', 'status': 'error'}
        except Exception as e:
            print(f"Unexpected error: {e}")
            return {'error': f'Unexpected error: {str(e)}', 'status': 'error'}

    @staticmethod
    def _check_scan_status(task_id, delay=10):
        """Background function to check scan status after delay"""
        time.sleep(delay)
        
        try:
            
            status_res = requests.get(f'{DomainService.SQLMAP_API}/scan/{task_id}/status')
            status_data = status_res.json()
            is_terminated = status_data.get('status') == 'terminated'
            
            if not is_terminated:
                print(f"Scan {task_id} still running")
                return
            
            
            log_res = requests.get(f'{DomainService.SQLMAP_API}/scan/{task_id}/log')
            log_data = log_res.json()
            log_entries = log_data.get('log', [])
            
            if not log_entries:
                print(f"Scan {task_id} completed - No log data found")
                return
            
      
            full_log = ' '.join(entry.get('message', '') for entry in log_entries)
            words = full_log.strip().split()
            last_1000_words = ' '.join(words[-1000:])
            
            if "no parameter(s) found for testing" in last_1000_words:
                print("NO VULNERABILITIES FOUND")
            else:
                print("THERE ARE VULNERABILITIES")
              
            print(f"Scan {task_id} completed successfully")
            
        except Exception as e:
            print(f"Error checking scan status: {e}")
    
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