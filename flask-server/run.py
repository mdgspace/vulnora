from app import create_app
from flask_cors import CORS
from flask import Flask, send_from_directory
import os

app = create_app()
CORS(app)  
if __name__ == '__main__':
    app.run(port=5001 , debug=True)


@app.route('/static/reports/<filename>')
def serve_report(filename):
    reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
    return send_from_directory(reports_dir, filename)