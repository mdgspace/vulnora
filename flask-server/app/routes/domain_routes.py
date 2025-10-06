from flask import Blueprint, request, jsonify, send_from_directory
import os, re
from datetime import datetime
from app.utils.get_user import get_user
from app.services.scanner import analyze_url_and_collect_logs
from urllib.parse import unquote
from app.services.domain_service import DomainService

domain_bp = Blueprint('domain', __name__)

@domain_bp.route('/scan', methods=['POST'])
def scan_domain():
    data = request.get_json()
    print("[SCAN INPUT DATA]", data)
    
    domain = data.get('domain')
    attacks = data.get('attacks', [])
    upload_endpoint = data.get('upload_endpoint') or '/upload'
    vuln_endpoint = data.get('vuln_endpoint') or '/vulnerable'

    if not domain or not attacks:
        return jsonify({'error': 'Missing domain or attacks'}), 400

    normalized_domain = domain.strip().lower().rstrip('/')
    
    user_id = get_user()
    print("[SCAN ROUTE] user_id =", user_id)
    results = DomainService.scan_domain(domain, attacks, vuln_endpoint, upload_endpoint)
    DomainService.scan_results_cache[normalized_domain] = {
        "domain": domain,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": results
    }

    print(f"[CACHED SCAN RESULTS FOR]: {normalized_domain}")
    return jsonify(results), 200

@domain_bp.route('/attacks', methods=['GET'])
def get_supported_attacks():
    attacks = DomainService.get_supported_attacks()
    return jsonify({"attacks": attacks}), 200

@domain_bp.route('/report/<path:domain>', methods=['GET'])
def get_report_pdf(domain):
    try:
        normalized = domain.strip().lower().rstrip('/')
        pdf_url = DomainService.generate_pdf_report(normalized)
        return jsonify({"pdf_url": pdf_url}), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@domain_bp.route('/download/<filename>', methods=['GET'])
def download_pdf(filename):
    reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
    return send_from_directory(reports_dir, filename)

@domain_bp.route('/jwt-test', methods=['POST'])
def test_jwt_vulnerabilities():
    """Direct endpoint for JWT vulnerability testing"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'https://' + url)
        if not parsed.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
        
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

@domain_bp.route('/scan-ip', methods=['POST'])
def scan_deep():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing target URL'}), 400

    target_url = data['url']
    try:
        results = analyze_url_and_collect_logs(target_url)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
