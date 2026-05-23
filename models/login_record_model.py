from models.db import db
from datetime import datetime


class LoginRecord(db.Model):
    __tablename__ = "login_records"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), nullable=False)

    ip_address = db.Column(db.String(100))
    device_type = db.Column(db.String(50))
    os_type = db.Column(db.String(50))
    browser = db.Column(db.String(50))
    location = db.Column(db.String(150))

    login_method = db.Column(db.String(50))
    auth_type = db.Column(db.String(50))

    success = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    mfa_enabled = db.Column(db.Boolean, default=True)
    token_expired = db.Column(db.Boolean, default=False)
    password_age_days = db.Column(db.Integer, default=0)
    account_status = db.Column(db.String(50), default="active")

    prediction = db.Column(db.String(100))
    risk_probability = db.Column(db.Float)
    risk_level = db.Column(db.String(50))
    recommended_action = db.Column(db.String(255))

    otp_code = db.Column(db.String(10), nullable=True)
    otp_verified = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "ip_address": self.ip_address,
            "device_type": self.device_type,
            "os_type": self.os_type,
            "browser": self.browser,
            "location": self.location,
            "login_method": self.login_method,
            "auth_type": self.auth_type,
            "success": self.success,
            "failed_attempts": self.failed_attempts,
            "mfa_enabled": self.mfa_enabled,
            "token_expired": self.token_expired,
            "password_age_days": self.password_age_days,
            "account_status": self.account_status,
            "prediction": self.prediction,
            "risk_probability": self.risk_probability,
            "risk_level": self.risk_level,
            "recommended_action": self.recommended_action,
            "otp_verified": self.otp_verified,
            "created_at": self.created_at.isoformat()
        }