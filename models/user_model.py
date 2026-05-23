from models.db import db
from datetime import datetime


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    mfa_enabled = db.Column(db.Boolean, default=True)
    account_status = db.Column(db.String(50), default="active")

    failed_attempts = db.Column(db.Integer, default=0)
    password_age_days = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "mfa_enabled": self.mfa_enabled,
            "account_status": self.account_status,
            "failed_attempts": self.failed_attempts,
            "password_age_days": self.password_age_days,
            "created_at": self.created_at.isoformat()
        }