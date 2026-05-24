from datetime import datetime
from models.db import db


class LoginRecord(db.Model):
    __tablename__ = "login_records"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), nullable=False)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    ip_address = db.Column(db.String(100))
    device_type = db.Column(db.String(50))
    os_type = db.Column(db.String(50))
    browser = db.Column(db.String(50))
    location = db.Column(db.String(150), default="unknown")

    login_method = db.Column(db.String(50), default="Password")
    auth_type = db.Column(db.String(50), default="Password")

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

    otp_attempts = db.Column(db.Integer, default=0)
    otp_blocked = db.Column(db.Boolean, default=False)
    otp_resend_count = db.Column(db.Integer, default=0)

    # New: server-side OTP expiry
    otp_expires_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
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
            "otp_attempts": self.otp_attempts,
            "otp_blocked": self.otp_blocked,
            "otp_resend_count": self.otp_resend_count,
            "otp_expires_at": self.otp_expires_at.isoformat() if self.otp_expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }