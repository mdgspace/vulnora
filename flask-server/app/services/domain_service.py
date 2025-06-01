class DomainService:

    supported_attacks = {
        "xss": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        # Add more attack types here
    }

    @staticmethod
    def scan_domain(domain, attacks):
        results = {}

        for attack in attacks:
            if attack == "xss":
                results['xss'] = DomainService.check_xss(domain)
            elif attack == "sql_injection":
                results['sql_injection'] = DomainService.check_sql_injection(domain)
            # Add more attack types here
            else:
                results[attack] = "Unknown attack type"

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