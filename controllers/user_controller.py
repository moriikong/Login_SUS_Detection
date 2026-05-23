from flask import request, jsonify
from models.db import db
from models.user_model import User


def create_user():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({
            "message": "username and password are required"
        }), 400

    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        return jsonify({
            "message": "Username already exists"
        }), 409

    user = User(
        username=username,
        password=password,
        mfa_enabled=data.get("mfa_enabled", True),
        account_status=data.get("account_status", "active"),
        password_age_days=data.get("password_age_days", 0)
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({
        "message": "User created successfully",
        "user": user.to_dict()
    }), 201


def get_all_users():
    users = User.query.all()

    return jsonify({
        "message": "Users retrieved successfully",
        "users": [user.to_dict() for user in users]
    }), 200


def get_user_by_username(username):
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({
            "message": "User not found"
        }), 404

    return jsonify({
        "message": "User retrieved successfully",
        "user": user.to_dict()
    }), 200