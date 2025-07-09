from flask import Blueprint, request, jsonify, send_from_directory
import os, re
from app.services.domain_service import DomainService

domain_bp = Blueprint('domain', __name__)

# POST /api/scan - Scan a domain for selected attacks
@domain_bp.route('/scan', methods=['POST'])
def scan_domain():
    data = request.get_json()
    print(data)
    domain = data.get('domain')
    print("domain:", domain)
    attacks = data.get('attacks', [])
    print("attacks:", attacks)
    upload_endpoint = data.get('upload_endpoint') or '/upload'  
    vuln_endpoint = data.get('vuln_endpoint') or '/vulnerable'

    if not domain or not attacks:
        return jsonify({'error': 'Missing domain or attacks'}), 400

    results = DomainService.scan_domain(domain, attacks, vuln_endpoint, upload_endpoint)
    return jsonify(results), 200

# GET /api/attacks - Get all supported attack types
@domain_bp.route('/attacks', methods=['GET'])
def get_supported_attacks():
    attacks = DomainService.get_supported_attacks()
    return jsonify({"attacks": attacks}), 200


def sanitize_domain(domain):
    # Remove scheme (http/https) and replace unsupported filename characters
    domain = domain.replace("https://", "").replace("http://", "")
    return re.sub(r'[^a-zA-Z0-9.-]', '_', domain)  # replace anything not allowed in filenames

# GET /api/report/<domain> - Get PDF report for scanned domain
@domain_bp.route('/report/<path:domain>', methods=['GET'])
def get_report_pdf(domain):
    try:
        pdf_url = DomainService.generate_pdf_report(sanitize_domain(domain))
        return jsonify({"pdf_url": pdf_url}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# GET /api/download/<filename> - Download PDF file
@domain_bp.route('/download/<filename>', methods=['GET'])
def download_pdf(filename):
    reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
    return send_from_directory(reports_dir, filename)

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
@domain_bp.route('/run-sqlmap', methods=['POST'])
def run_sqlmap():

    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing target URL'}), 400
    
    target_url = data['url']
    
   
    result = DomainService.check_sql_injection(target_url)
    
    return jsonify(result)