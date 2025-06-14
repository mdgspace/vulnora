from flask import Flask

def create_app():
    app = Flask(__name__)

    # Register Blueprints
    from app.routes.domain_routes import domain_bp
    app.register_blueprint(domain_bp, url_prefix='/api')

   

    return app