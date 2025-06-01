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
