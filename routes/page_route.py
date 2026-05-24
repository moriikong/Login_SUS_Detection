from flask import Blueprint
from controllers.page_controller import (
    register_page,
    login_page,
    otp_page,
    success_page,
    blocked_page,
    records_page
)

page_bp = Blueprint("page_bp", __name__)

page_bp.route("/", methods=["GET"])(login_page)
page_bp.route("/register-page", methods=["GET"])(register_page)
page_bp.route("/login-page", methods=["GET"])(login_page)
page_bp.route("/otp-page", methods=["GET"])(otp_page)
page_bp.route("/success-page", methods=["GET"])(success_page)
page_bp.route("/blocked-page", methods=["GET"])(blocked_page)
page_bp.route("/records-page", methods=["GET"])(records_page)