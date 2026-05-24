from flask import Blueprint
from controllers.auth_controller import (
    login,
    verify_login_otp,
    resend_otp
)

auth_bp = Blueprint("auth_bp", __name__, url_prefix="/auth")

auth_bp.route("/login", methods=["POST"])(login)
auth_bp.route("/verify-otp", methods=["POST"])(verify_login_otp)
auth_bp.route("/resend-otp", methods=["POST"])(resend_otp)