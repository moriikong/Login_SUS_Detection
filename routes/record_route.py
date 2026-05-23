from flask import Blueprint
from controllers.record_controller import (
    get_all_login_records,
    get_login_record_by_id
)

record_bp = Blueprint("record_bp", __name__, url_prefix="/records")

record_bp.route("/", methods=["GET"])(get_all_login_records)
record_bp.route("/<int:record_id>", methods=["GET"])(get_login_record_by_id)