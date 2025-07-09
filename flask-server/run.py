from flask import send_from_directory
from app import create_app  
import os

app = create_app()  
# For serving PDF reports if needed

@app.route('/static/reports/<filename>')
def serve_report(filename):
    reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
    return send_from_directory(reports_dir, filename)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001, debug=True)
