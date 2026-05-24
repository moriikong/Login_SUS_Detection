import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask import request, jsonify

from models.db import db
from models.user_model import User
from models.login_record_model import LoginRecord

from services.ml_service import predict_login_risk
from services.otp_service import generate_otp, verify_otp
from services.request_info_service import get_client_ip, get_device_info


# Password guessing mitigation
PASSWORD_BLOCK_THRESHOLD = 5
PASSWORD_BLOCK_DURATION = 60

# OTP guessing mitigation
MAX_OTP_ATTEMPTS = 3
MAX_OTP_RESENDS = 2
OTP_EXPIRY_SECONDS = 60

# Repeated OTP failure mitigation
OTP_SESSION_BLOCK_THRESHOLD = 3
OTP_FAILED_TOTAL_THRESHOLD = 6
OTP_ACCOUNT_BLOCK_DURATION = 60

# Timezone
MALAYSIA_TZ = ZoneInfo("Asia/Kuala_Lumpur")


def get_malaysia_time():
    """
    Return Malaysia local time without timezone info.
    SQLite stores naive datetime better, so tzinfo is removed.
    """
    return datetime.now(MALAYSIA_TZ).replace(tzinfo=None)


def build_login_attempt(user, password_correct, timestamp, ip_address, device_info, location):
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": ip_address,

        "device_type": device_info["device_type"],
        "os_type": device_info["os_type"],
        "browser": device_info["browser"],
        "location": location,

        "login_method": "Password",
        "success": password_correct,
        "auth_type": "Password",
        "account_status": user.account_status,

        "failed_attempts": user.failed_attempts,
        "mfa_enabled": user.mfa_enabled,
        "token_expired": False,
        "password_age_days": user.password_age_days
    }


def create_login_record(
    username,
    timestamp,
    ip_address,
    device_info,
    location,
    user,
    success,
    risk_result,
    otp_code=None
):
    otp_expires_at = None

    if otp_code:
        otp_expires_at = get_malaysia_time() + timedelta(seconds=OTP_EXPIRY_SECONDS)

    record = LoginRecord(
        username=username,
        timestamp=timestamp,
        ip_address=ip_address,
        device_type=device_info["device_type"],
        os_type=device_info["os_type"],
        browser=device_info["browser"],
        location=location,
        login_method="Password",
        auth_type="Password",
        success=success,
        failed_attempts=user.failed_attempts,
        mfa_enabled=user.mfa_enabled,
        token_expired=False,
        password_age_days=user.password_age_days,
        account_status=user.account_status,
        prediction=risk_result["prediction"],
        risk_probability=risk_result["risk_probability"],
        risk_level=risk_result["risk_level"],
        recommended_action=risk_result["recommended_action"],
        otp_code=otp_code,
        otp_expires_at=otp_expires_at
    )

    db.session.add(record)
    return record


def login():
    data = request.get_json()

    if not data:
        return jsonify({
            "message": "No input data provided"
        }), 400

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

    current_time = time.time()

    # ===================================================
    # 1. Check temporary account block
    # ===================================================
    if user.blocked_until and current_time < user.blocked_until:
        remaining = int(user.blocked_until - current_time)

        return jsonify({
            "message": "Account is temporarily blocked.",
            "blocked": True,
            "remaining_seconds": remaining,
            "risk_result": {
                "prediction": "Suspicious Login Activity Detected",
                "risk_probability": 1.0,
                "risk_level": "High",
                "recommended_action": f"Wait {remaining} seconds before trying again."
            }
        }), 423

    # Auto-unlock after block duration
    if user.blocked_until and current_time >= user.blocked_until:
        user.blocked_until = 0
        user.failed_attempts = 0
        user.account_status = "active"
        db.session.commit()

    # Permanent restriction
    if user.account_status.lower() in ["suspended", "disabled"]:
        return jsonify({
            "message": "Account is not active",
            "account_status": user.account_status
        }), 403

    timestamp = get_malaysia_time()
    ip_address = get_client_ip()
    device_info = get_device_info()
    location = "unknown"

    # ===================================================
    # 2. Password authentication
    # ===================================================
    password_correct = user.password == password

    if password_correct:
        # Password success resets password failed attempts
        user.failed_attempts = 0
    else:
        # Wrong password increases account-level password attempts
        user.failed_attempts += 1

    login_attempt = build_login_attempt(
        user=user,
        password_correct=password_correct,
        timestamp=timestamp,
        ip_address=ip_address,
        device_info=device_info,
        location=location
    )

    risk_result = predict_login_risk(login_attempt)

    # ===================================================
    # 3. Wrong password handling
    # ===================================================
    if not password_correct:

        if user.failed_attempts >= 3 and user.failed_attempts < PASSWORD_BLOCK_THRESHOLD:
            risk_result["prediction"] = "Password Guessing Risk Detected"
            risk_result["risk_probability"] = max(risk_result["risk_probability"], 0.6)
            risk_result["risk_level"] = "Medium"

            delay_seconds = 3

            risk_result["recommended_action"] = (
                f"Repeated failed password attempts detected. "
                f"A {delay_seconds}-second login delay was applied before returning the response."
            )

            print(f"[LOGIN DELAY] Failed attempts: {user.failed_attempts}")
            print(f"[LOGIN DELAY] Backend delay started for {delay_seconds} seconds...")

            time.sleep(delay_seconds)

            print("[LOGIN DELAY] Backend delay ended.")

        if user.failed_attempts >= PASSWORD_BLOCK_THRESHOLD:
            user.blocked_until = current_time + PASSWORD_BLOCK_DURATION

            risk_result["prediction"] = "Password Guessing Risk Detected"
            risk_result["risk_probability"] = max(risk_result["risk_probability"], 0.9)
            risk_result["risk_level"] = "High"
            risk_result["recommended_action"] = (
                f"Temporarily block account for {PASSWORD_BLOCK_DURATION} seconds "
                "due to repeated failed password attempts."
            )

        record = create_login_record(
            username=username,
            timestamp=timestamp,
            ip_address=ip_address,
            device_info=device_info,
            location=location,
            user=user,
            success=False,
            risk_result=risk_result
        )

        db.session.commit()

        if user.failed_attempts >= PASSWORD_BLOCK_THRESHOLD:
            return jsonify({
                "message": "Too many failed password attempts. Account temporarily blocked.",
                "login_record_id": record.id,
                "blocked": True,
                "remaining_seconds": PASSWORD_BLOCK_DURATION,
                "auto_detected": {
                    "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "ip_address": ip_address,
                    "device_type": device_info["device_type"],
                    "os_type": device_info["os_type"],
                    "browser": device_info["browser"],
                    "location": location
                },
                "risk_result": risk_result
            }), 423

        delay_applied = user.failed_attempts >= 3 and user.failed_attempts < PASSWORD_BLOCK_THRESHOLD
        delay_seconds = 3 if delay_applied else 0

        return jsonify({
            "message": (
                f"Login failed. Incorrect username or password. "
                f"Failed password attempts: {user.failed_attempts}. "
                f"Remaining attempts before temporary block: "
                f"{PASSWORD_BLOCK_THRESHOLD - user.failed_attempts}."
            ),
            "login_record_id": record.id,
            "failed_attempts": user.failed_attempts,
            "remaining_attempts_before_block": PASSWORD_BLOCK_THRESHOLD - user.failed_attempts,
            "delay_applied": delay_applied,
            "delay_seconds": delay_seconds,
            "auto_detected": {
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "ip_address": ip_address,
                "device_type": device_info["device_type"],
                "os_type": device_info["os_type"],
                "browser": device_info["browser"],
                "location": location
            },
            "risk_result": risk_result
        }), 401

    # ===================================================
    # 4. Correct password handling
    # ===================================================
    otp_required = False
    otp_code = None

    # MFA happens only after password is correct
    if risk_result["risk_level"] in ["Medium", "High"] or user.mfa_enabled:
        otp_required = True
        otp_code = generate_otp()

    record = create_login_record(
        username=username,
        timestamp=timestamp,
        ip_address=ip_address,
        device_info=device_info,
        location=location,
        user=user,
        success=True,
        risk_result=risk_result,
        otp_code=otp_code
    )

    db.session.commit()

    if otp_required:
        return jsonify({
            "message": "Password correct. OTP verification required.",
            "login_record_id": record.id,
            "demo_otp": otp_code,
            "auto_detected": {
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "ip_address": ip_address,
                "device_type": device_info["device_type"],
                "os_type": device_info["os_type"],
                "browser": device_info["browser"],
                "location": location
            },
            "risk_result": risk_result
        }), 200

    return jsonify({
        "message": "Login successful.",
        "login_record_id": record.id,
        "auto_detected": {
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "ip_address": ip_address,
            "device_type": device_info["device_type"],
            "os_type": device_info["os_type"],
            "browser": device_info["browser"],
            "location": location
        },
        "risk_result": risk_result
    }), 200


def verify_login_otp():
    data = request.get_json()

    if not data:
        return jsonify({
            "message": "No input data provided"
        }), 400

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

    user = User.query.filter_by(username=record.username).first()

    if not user:
        return jsonify({
            "message": "User not found"
        }), 404

    if not record.otp_code:
        return jsonify({
            "message": "OTP was not generated for this login"
        }), 400

    if record.otp_verified:
        return jsonify({
            "message": "OTP already verified.",
            "record": record.to_dict()
        }), 200

    if record.otp_blocked:
        return jsonify({
            "message": "OTP verification session is blocked. Please login again.",
            "record": record.to_dict()
        }), 423

    # ===================================================
    # Server-side OTP expiry check
    # ===================================================
    if record.otp_expires_at and get_malaysia_time() > record.otp_expires_at:
        record.otp_code = None
        record.recommended_action = "OTP expired. Please request a new OTP."
        db.session.commit()

        return jsonify({
            "message": "OTP expired. Please request a new OTP.",
            "otp_expired": True,
            "record": record.to_dict()
        }), 410

    # ===================================================
    # Correct OTP
    # ===================================================
    if verify_otp(otp, record.otp_code):
        record.otp_verified = True
        record.otp_code = None
        record.otp_expires_at = None

        # Successful MFA resets account-level OTP risk counters
        user.otp_session_block_count = 0
        user.otp_failed_total = 0

        db.session.commit()

        return jsonify({
            "message": "OTP verified. Login successful.",
            "record": record.to_dict()
        }), 200

    # ===================================================
    # Wrong OTP
    # ===================================================
    record.otp_attempts += 1

    # Account-level OTP failure counter across sessions
    user.otp_failed_total += 1

    # If user keeps failing OTP across multiple login sessions,
    # block the whole account temporarily.
    if user.otp_failed_total >= OTP_FAILED_TOTAL_THRESHOLD:
        record.otp_blocked = True
        record.otp_code = None
        record.otp_expires_at = None

        record.prediction = "MFA Verification Risk Detected"
        record.risk_probability = 1.0
        record.risk_level = "High"
        record.recommended_action = (
            "Account temporarily blocked due to repeated OTP verification failures "
            "across multiple login sessions."
        )

        user.blocked_until = time.time() + OTP_ACCOUNT_BLOCK_DURATION
        user.otp_failed_total = 0
        user.otp_session_block_count = 0

        db.session.commit()

        return jsonify({
            "message": (
                "Too many incorrect OTP attempts across login sessions. "
                "Account temporarily blocked due to repeated MFA verification failures."
            ),
            "otp_session_blocked": True,
            "account_blocked": True,
            "remaining_seconds": OTP_ACCOUNT_BLOCK_DURATION,
            "record": record.to_dict()
        }), 423

    # Wrong OTP 3 times in current session -> block current OTP session
    if record.otp_attempts >= MAX_OTP_ATTEMPTS:
        record.otp_blocked = True
        record.otp_code = None
        record.otp_expires_at = None

        record.prediction = "MFA Verification Risk Detected"
        record.risk_probability = 1.0
        record.risk_level = "High"

        user.otp_session_block_count += 1

        record.recommended_action = (
            "OTP verification session blocked due to repeated incorrect OTP attempts. "
            "Please login again."
        )

        # If OTP session blocked many times for same account,
        # temporarily block whole account.
        if user.otp_session_block_count >= OTP_SESSION_BLOCK_THRESHOLD:
            user.blocked_until = time.time() + OTP_ACCOUNT_BLOCK_DURATION
            user.otp_session_block_count = 0
            user.otp_failed_total = 0

            db.session.commit()

            return jsonify({
                "message": (
                    "Too many blocked OTP sessions. Account temporarily blocked "
                    "due to repeated MFA verification failures."
                ),
                "otp_session_blocked": True,
                "account_blocked": True,
                "remaining_seconds": OTP_ACCOUNT_BLOCK_DURATION,
                "record": record.to_dict()
            }), 423

        db.session.commit()

        return jsonify({
            "message": (
                "Too many incorrect OTP attempts. OTP session blocked. "
                "Please login again."
            ),
            "otp_session_blocked": True,
            "account_blocked": False,
            "otp_session_block_count": user.otp_session_block_count,
            "remaining_attempts": 0,
            "record": record.to_dict()
        }), 423

    # Wrong OTP but retry still allowed
    # Auto-refresh OTP after each wrong OTP
    new_otp = generate_otp()
    record.otp_code = new_otp
    record.otp_expires_at = get_malaysia_time() + timedelta(seconds=OTP_EXPIRY_SECONDS)

    remaining_attempts = MAX_OTP_ATTEMPTS - record.otp_attempts
    db.session.commit()

    return jsonify({
        "message": "Invalid OTP. A new OTP has been generated.",
        "remaining_attempts": remaining_attempts,
        "demo_otp": new_otp,
        "otp_refreshed": True,
        "otp_expires_in": OTP_EXPIRY_SECONDS,
        "otp_failed_total": user.otp_failed_total,
        "record": record.to_dict()
    }), 401


def resend_otp():
    data = request.get_json()

    if not data:
        return jsonify({
            "message": "No input data provided"
        }), 400

    login_record_id = data.get("login_record_id")

    if not login_record_id:
        return jsonify({
            "message": "login_record_id is required"
        }), 400

    record = LoginRecord.query.get(login_record_id)

    if not record:
        return jsonify({
            "message": "Login record not found"
        }), 404

    if record.otp_verified:
        return jsonify({
            "message": "OTP already verified. Resend is not allowed."
        }), 400

    if record.otp_blocked:
        return jsonify({
            "message": "OTP verification session is blocked. Please login again.",
            "record": record.to_dict()
        }), 423

    # Do not allow resend while current OTP is still valid
    if record.otp_expires_at and get_malaysia_time() < record.otp_expires_at:
        remaining_seconds = int(
            (record.otp_expires_at - get_malaysia_time()).total_seconds()
        )

        return jsonify({
            "message": f"Current OTP is still valid. Please wait {remaining_seconds} seconds before requesting a new OTP.",
            "otp_still_valid": True,
            "remaining_seconds": remaining_seconds,
            "record": record.to_dict()
        }), 429

    if record.otp_resend_count >= MAX_OTP_RESENDS:
        record.otp_blocked = True

        user = User.query.filter_by(username=record.username).first()

        if user:
            user.otp_session_block_count += 1

            # If too many OTP sessions were blocked, block the whole account
            if user.otp_session_block_count >= OTP_SESSION_BLOCK_THRESHOLD:
                user.blocked_until = time.time() + OTP_ACCOUNT_BLOCK_DURATION
                user.otp_session_block_count = 0

                record.recommended_action = (
                    "Account temporarily blocked due to repeated MFA verification failures."
                )

                db.session.commit()

                return jsonify({
                    "message": (
                        "Too many blocked OTP sessions. Account temporarily blocked "
                        "due to repeated MFA verification failures."
                    ),
                    "account_blocked": True,
                    "remaining_seconds": OTP_ACCOUNT_BLOCK_DURATION,
                    "record": record.to_dict()
                }), 423

        record.recommended_action = (
            "OTP session blocked due to too many resend requests. Please login again."
        )

        db.session.commit()

        return jsonify({
            "message": "Too many OTP resend requests. OTP session blocked. Please login again.",
            "account_blocked": False,
            "record": record.to_dict()
        }), 423

    new_otp = generate_otp()
    record.otp_code = new_otp
    record.otp_expires_at = get_malaysia_time() + timedelta(seconds=OTP_EXPIRY_SECONDS)
    record.otp_resend_count += 1

    db.session.commit()

    return jsonify({
        "message": "New OTP generated successfully.",
        "demo_otp": new_otp,
        "remaining_resends": MAX_OTP_RESENDS - record.otp_resend_count,
        "otp_expires_in": OTP_EXPIRY_SECONDS,
        "record": record.to_dict()
    }), 200