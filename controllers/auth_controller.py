from flask import request, jsonify
from models.db import db
from models.user_model import User
from models.login_record_model import LoginRecord
from services.ml_service import predict_login_risk
from services.otp_service import generate_otp, verify_otp


def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({
            "message": "username and password are required"
        }), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({
            "message": "Invalid username or password"
        }), 401

    if user.account_status.lower() in ["locked", "suspended", "disabled"]:
        return jsonify({
            "message": "Account is not active",
            "account_status": user.account_status
        }), 403

    password_correct = user.password == password

    if password_correct:
        user.failed_attempts = 0
    else:
        user.failed_attempts += 1

    success = password_correct

    login_attempt = {
        "timestamp": data.get("timestamp"),
        "ip_address": data.get("ip_address"),
        "device_type": data.get("device_type"),
        "os_type": data.get("os_type"),
        "browser": data.get("browser"),
        "location": data.get("location"),
        "login_method": data.get("login_method", "Password"),
        "success": success,
        "auth_type": data.get("auth_type", "Password"),
        "account_status": user.account_status,
        "failed_attempts": user.failed_attempts,
        "mfa_enabled": user.mfa_enabled,
        "token_expired": data.get("token_expired", False),
        "password_age_days": user.password_age_days
    }

    risk_result = predict_login_risk(login_attempt)

    otp_code = None
    otp_required = False

    if not password_correct:
        record = LoginRecord(
            username=username,
            ip_address=login_attempt["ip_address"],
            device_type=login_attempt["device_type"],
            os_type=login_attempt["os_type"],
            browser=login_attempt["browser"],
            location=login_attempt["location"],
            login_method=login_attempt["login_method"],
            auth_type=login_attempt["auth_type"],
            success=False,
            failed_attempts=user.failed_attempts,
            mfa_enabled=user.mfa_enabled,
            token_expired=login_attempt["token_expired"],
            password_age_days=user.password_age_days,
            account_status=user.account_status,
            prediction=risk_result["prediction"],
            risk_probability=risk_result["risk_probability"],
            risk_level=risk_result["risk_level"],
            recommended_action=risk_result["recommended_action"]
        )

        if user.failed_attempts >= 5:
            user.account_status = "locked"
            record.account_status = "locked"
            record.recommended_action = "Account locked due to repeated failed password attempts"

        db.session.add(record)
        db.session.commit()

        return jsonify({
            "message": "Invalid username or password",
            "login_record_id": record.id,
            "risk_result": risk_result,
            "account_status": user.account_status
        }), 401

    if risk_result["risk_level"] in ["Medium", "High"] or user.mfa_enabled:
        otp_required = True
        otp_code = generate_otp()

    record = LoginRecord(
        username=username,
        ip_address=login_attempt["ip_address"],
        device_type=login_attempt["device_type"],
        os_type=login_attempt["os_type"],
        browser=login_attempt["browser"],
        location=login_attempt["location"],
        login_method=login_attempt["login_method"],
        auth_type=login_attempt["auth_type"],
        success=True,
        failed_attempts=user.failed_attempts,
        mfa_enabled=user.mfa_enabled,
        token_expired=login_attempt["token_expired"],
        password_age_days=user.password_age_days,
        account_status=user.account_status,
        prediction=risk_result["prediction"],
        risk_probability=risk_result["risk_probability"],
        risk_level=risk_result["risk_level"],
        recommended_action=risk_result["recommended_action"],
        otp_code=otp_code
    )

    db.session.add(record)
    db.session.commit()

    if otp_required:
        return jsonify({
            "message": "Password correct. OTP verification required.",
            "login_record_id": record.id,
            "demo_otp": otp_code,
            "risk_result": risk_result
        }), 200

    return jsonify({
        "message": "Login successful.",
        "login_record_id": record.id,
        "risk_result": risk_result
    }), 200


def verify_login_otp():
    data = request.get_json()

    login_record_id = data.get("login_record_id")
    otp = data.get("otp")

    if not login_record_id or not otp:
        return jsonify({
            "message": "login_record_id and otp are required"
        }), 400

    record = LoginRecord.query.get(login_record_id)

    if not record:
        return jsonify({
            "message": "Login record not found"
        }), 404

    if not record.otp_code:
        return jsonify({
            "message": "OTP was not generated for this login"
        }), 400

    if verify_otp(otp, record.otp_code):
        record.otp_verified = True
        db.session.commit()

        return jsonify({
            "message": "OTP verified. Login successful.",
            "record": record.to_dict()
        }), 200

    return jsonify({
        "message": "Invalid OTP"
    }), 401