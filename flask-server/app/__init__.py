from flask import Flask
from flask_cors import CORS

def create_app():
    app = Flask(__name__)

    CORS(app, resources={r"/api/*": {"origins": "*"}})  

    # Register Blueprints
    from app.routes.domain_routes import domain_bp
    app.register_blueprint(domain_bp, url_prefix='/api')

    return app
