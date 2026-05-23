from flask import jsonify
from models.login_record_model import LoginRecord


def get_all_login_records():
    records = LoginRecord.query.order_by(LoginRecord.created_at.desc()).all()

    return jsonify({
        "message": "Login records retrieved successfully",
        "records": [record.to_dict() for record in records]
    }), 200


def get_login_record_by_id(record_id):
    record = LoginRecord.query.get(record_id)

    if not record:
        return jsonify({
            "message": "Login record not found"
        }), 404

    return jsonify({
        "message": "Login record retrieved successfully",
        "record": record.to_dict()
    }), 200