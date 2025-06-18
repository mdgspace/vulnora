from flask import Flask, send_from_directory
from app.services.domain_service import DomainService
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

@app.route('/static/reports/<filename>')
def serve_report(filename):
    reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
    return send_from_directory(reports_dir, filename)

if __name__ == "__main__":
    # Run scan
    domain = "http://127.0.0.1:6000"
    attacks = ["path_traversal"]
    vuln_endpoint = "/vulnerable?file="

    result = DomainService.scan_domain(domain, attacks, vuln_endpoint, upload_endpoint="")

    # Print final report
    print("\n--- Final Report ---")
    print(result)

    # Start Flask app
    app.run(host="0.0.0.0", port=5001, debug=True)
