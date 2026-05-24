from datetime import datetime
from models.db import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    mfa_enabled = db.Column(db.Boolean, default=True)
    account_status = db.Column(db.String(50), default="active")

    # Password guessing counter
    failed_attempts = db.Column(db.Integer, default=0)

    # Account-level temporary block
    blocked_until = db.Column(db.Float, default=0)

    # Count repeated blocked OTP sessions
    otp_session_block_count = db.Column(db.Integer, default=0)

    # Count repeated wrong OTP attempts across sessions
    otp_failed_total = db.Column(db.Integer, default=0)

    password_age_days = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "mfa_enabled": self.mfa_enabled,
            "account_status": self.account_status,
            "failed_attempts": self.failed_attempts,
            "blocked_until": self.blocked_until,
            "otp_session_block_count": self.otp_session_block_count,
            "otp_failed_total": self.otp_failed_total,
            "password_age_days": self.password_age_days,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }