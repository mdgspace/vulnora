import requests
import pickle
import base64

class DomainService:

    supported_attacks = {
        "xss": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        "insecure_deserialization": "Insecure Deserialization",
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
            elif attack == "insecure_deserialization":
                results['insecure_deserialization'] = DomainService.check_insecure_deserialization(domain)
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
    
    @classmethod
    def get_supported_attacks(cls):
        return cls.supported_attacks