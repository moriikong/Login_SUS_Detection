from flask import Flask
from flask_cors import CORS

from config import Config
from models.db import db

from routes.auth_route import auth_bp
from routes.user_route import user_bp
from routes.record_route import record_bp
from routes.page_route import page_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)

    db.init_app(app)

    app.register_blueprint(page_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(record_bp)

    @app.route("/api-status")
    def api_status():
        return {
            "message": "AI/ML Enhanced MFA Backend is running"
        }

    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)