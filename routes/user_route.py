from flask import Blueprint
from controllers.user_controller import (
    create_user,
    get_all_users,
    get_user_by_username
)

user_bp = Blueprint("user_bp", __name__, url_prefix="/users")

user_bp.route("/", methods=["POST"])(create_user)
user_bp.route("/", methods=["GET"])(get_all_users)
user_bp.route("/<username>", methods=["GET"])(get_user_by_username)