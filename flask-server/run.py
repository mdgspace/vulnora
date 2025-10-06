from flask import Flask, send_from_directory
from flask_cors import CORS
import os

from app.routes.domain_routes import domain_bp

app = Flask(__name__)

CORS(app, resources={r"/api/*": {"origins": "*"}})

# Register blueprints
app.register_blueprint(domain_bp, url_prefix='/api')

# Serve reports
@app.route('/static/reports/<filename>')
def serve_report(filename):
    reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
    return send_from_directory(reports_dir, filename)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001, debug=True)
