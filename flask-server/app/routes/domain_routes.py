from flask import Blueprint, request, jsonify, send_from_directory
import os
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


# GET /api/report/<domain> - Get PDF report for scanned domain
@domain_bp.route('/report/<path:domain>', methods=['GET'])
def get_report_pdf(domain):
    try:
        pdf_url = DomainService.generate_pdf_report(domain)
        return jsonify({"pdf_url": pdf_url}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# GET /api/download/<filename> - Download PDF file
@domain_bp.route('/download/<filename>', methods=['GET'])
def download_pdf(filename):
    reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
    return send_from_directory(reports_dir, filename)