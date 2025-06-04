from app.services.csrf_scanner import scan_csrf_vulnerability

class DomainService:

    supported_attacks = {
        "xss": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        "csrf":"CSRF",
        "path_traversal":"Path Traversal",
        "insecure_deserialization":"Insecure Deserialization",
        "command_injection":"Command Injection",
        "jwt":"JWT Manipulation",
        "file_upload":"File Upload",
        "ddos":"DDoS Attacks"
    }

    @staticmethod
    def scan_domain(domain, attacks):
        results = {}

        for attack in attacks:
            if attack == "xss":
                results['xss'] = DomainService.check_xss(domain)
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
            elif attack == "file_upload":
                results['file_upload'] = DomainService.check_file_upload(domain)            
            elif attack == "ddos":
                results['ddos'] = DomainService.check_ddos(domain)            
            else:            
                results[attack] = "Unknown attack type"

        return {
            "domain": domain,
            "results": results
        }


    @staticmethod
    def check_xss(domain):
        # Mock logic for XSS vulnerability
        return "No XSS vulnerability found"

    @staticmethod
    def check_sql_injection(domain):
        # Mock logic for SQLi vulnerability
        return "Potential SQL injection found"
    
    @staticmethod
    def check_csrf(domain):
        return scan_csrf_vulnerability(domain)

    @staticmethod
    def check_path_traversal(domain):
        # Mock logic for path traversal vulnerability
        return "Potential path traversal vulnerability found"
    
    @staticmethod
    def check_insecure_deserialization(domain):
        # Mock logic for insecure deserialization vulnerability
        return "Potential insecure deserialization vulnerability found"
    
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