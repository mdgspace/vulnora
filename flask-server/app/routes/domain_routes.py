from flask import Blueprint, request, jsonify
from app.services.domain_service import DomainService

domain_bp = Blueprint('domain', __name__)

# POST /api/scan - Scan a domain for selected attacks
@domain_bp.route('/scan', methods=['POST'])
def scan_domain():
    data = request.get_json()
    domain = data.get('domain')
    attacks = data.get('attacks', [])

    if not domain or not attacks:
        return jsonify({'error': 'Missing domain or attacks'}), 400

    results = DomainService.scan_domain(domain, attacks)
    return jsonify(results), 200

# GET /api/attacks - Get all supported attack types
@domain_bp.route('/attacks', methods=['GET'])
def get_supported_attacks():
    attacks = DomainService.get_supported_attacks()
    return jsonify({"attacks": attacks}), 200

# POST /api/jwt-test - Direct JWT vulnerability testing endpoint
@domain_bp.route('/jwt-test', methods=['POST'])
def test_jwt_vulnerabilities():
    """Direct endpoint for JWT vulnerability testing"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        
        # Basic URL validation
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'https://' + url)
        if not parsed.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Perform JWT vulnerability test
        results = DomainService.check_jwt_vulnerabilities(url)
        
        return jsonify(results), 200
        
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500