from app.services.path_traversal import check_path_traversal
import json 
class DomainService:

    supported_attacks = {
        "xss": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        "path_traversal": "Path Traversal",
        # Add more attack types here
    }

    @staticmethod
    def scan_domain(domain, attacks, vuln_endpoint):
        results = {}

        for attack in attacks:
            if attack == "xss":
                results['xss'] = DomainService.check_xss(domain)
            elif attack == "sql_injection":
                results['sql_injection'] = DomainService.check_sql_injection(domain)
            # Add more attack types here
            elif attack == "path_traversal":
                results['path_traversal'] = check_path_traversal(domain, vuln_endpoint)
            else:
                results[attack] = "Unknown attack type"

            for key, value in results.items():
                print(f"{key} result:")
                print(json.dumps(value, indent=4))  # nicely formatted
                print()  

        return {
            "domain": domain,
            "results": results
        }


    # Define methods for checking vulnerabilities over here
    @staticmethod
    def check_xss(domain):
        # Mock logic for XSS vulnerability
        return "No XSS vulnerability found"

    @staticmethod
    def check_sql_injection(domain):
        # Mock logic for SQLi vulnerability
        return "Potential SQL injection found"
    
    @classmethod
    def get_supported_attacks(cls):
        return cls.supported_attacks