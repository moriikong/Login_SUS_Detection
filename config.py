import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = "dev-secret-key"

    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "database.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MODEL_PATH = os.path.join(
        BASE_DIR,
        "ml_model",
        "decision_tree_password_guessing_model.pkl"
    )

    FEATURE_PATH = os.path.join(
        BASE_DIR,
        "ml_model",
        "model_features.pkl"
    )