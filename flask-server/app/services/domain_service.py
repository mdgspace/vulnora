import tempfile
import os
import subprocess
import json

class DomainService:

    supported_attacks = {
        "Cross-Site Scripting": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        # Add more attack types here
    }

    @staticmethod
    def scan_domain(domain, attacks):
        results = {}

        for attack in attacks:
            print(attack)
            if attack == "Cross-Site Scripting":
                results['Cross-Site Scripting'] = DomainService.check_xss(domain)
            elif attack == "sql_injection":
                results['sql_injection'] = DomainService.check_sql_injection(domain)
            # Add more attack types here
            else:
                results[attack] = "Unknown attack type"


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
        # Mock logic for SQLi vulnerability
        return "Potential SQL injection found"
    
    @classmethod
    def get_supported_attacks(cls):
        return cls.supported_attacks