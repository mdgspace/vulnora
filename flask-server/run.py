from flask import Flask
from app.services.domain_service import DomainService

app = Flask(__name__)

if __name__ == "__main__":
    domain = "http://127.0.0.1:6000"
    attacks = ["path_traversal"]
    vuln_endpoint = "/vulnerable?file="

    result = DomainService.scan_domain(domain, attacks, vuln_endpoint, upload_endpoint="")

    # Print final report
    print("\n--- Final Report ---")
    print(result)

if __name__ == '__main__':
    app.run(port=5001 , debug=True)