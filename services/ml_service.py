import pandas as pd
import ipaddress
import joblib
from datetime import datetime
from flask import current_app


model = None
feature_info = None

def load_model():
    global model, feature_info

    if model is None:
        model = joblib.load(current_app.config["MODEL_PATH"])

    if feature_info is None:
        feature_info = joblib.load(current_app.config["FEATURE_PATH"])

    return model, feature_info


def convert_bool(value):
    if value is None:
        return 0

    value = str(value).strip().lower()

    if value in ["true", "yes", "1", "success", "successful"]:
        return 1
    elif value in ["false", "no", "0", "fail", "failed"]:
        return 0
    return 0


def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(str(ip)))
    except Exception:
        return 0


def get_login_features(timestamp_value):
    dt = pd.to_datetime(timestamp_value, errors="coerce")

    if pd.isna(dt):
        dt = datetime.now()

    login_hour = dt.hour
    unusual_hour = 1 if login_hour < 5 else 0

    return login_hour, unusual_hour


def predict_login_risk(login_attempt):
    model, feature_info = load_model()

    numeric_cols = feature_info["numeric_cols"]
    categorical_cols = feature_info["categorical_cols"]

    login_hour, unusual_hour = get_login_features(login_attempt.get("timestamp"))

    processed_input = {
        "login_hour": login_hour,
        "unusual_hour": unusual_hour,
        "ip_int": ip_to_int(login_attempt.get("ip_address")),

        "failed_attempts": login_attempt.get("failed_attempts", 0),
        "success": convert_bool(login_attempt.get("success")),
        "mfa_enabled": convert_bool(login_attempt.get("mfa_enabled")),
        "token_expired": convert_bool(login_attempt.get("token_expired")),
        "password_age_days": login_attempt.get("password_age_days", 0),

        "device_type": str(login_attempt.get("device_type", "unknown")).strip().lower(),
        "os_type": str(login_attempt.get("os_type", "unknown")).strip().lower(),
        "browser": str(login_attempt.get("browser", "unknown")).strip().lower(),
        "location": str(login_attempt.get("location", "unknown")).strip().lower(),
        "login_method": str(login_attempt.get("login_method", "unknown")).strip().lower(),
        "auth_type": str(login_attempt.get("auth_type", "unknown")).strip().lower(),
        "account_status": str(login_attempt.get("account_status", "unknown")).strip().lower()
    }

    all_expected_cols = numeric_cols + categorical_cols
    final_input = {}

    for col in all_expected_cols:
        if col in processed_input:
            final_input[col] = processed_input[col]
        else:
            final_input[col] = 0 if col in numeric_cols else "unknown"

    input_df = pd.DataFrame([final_input])
    input_df = input_df[all_expected_cols]

    prediction = model.predict(input_df)[0]
    probabilities = model.predict_proba(input_df)[0]

    if 1 in model.classes_:
        risk_index = list(model.classes_).index(1)
        risk_probability = float(probabilities[risk_index])
    else:
        risk_probability = 0.0

    prediction_label = (
        "Password Guessing Risk Detected"
        if prediction == 1
        else "Normal Login"
    )

    if risk_probability >= 0.70:
        risk_level = "High"
        recommended_action = "Temporarily block login or require stronger MFA"
    elif risk_probability >= 0.40:
        risk_level = "Medium"
        recommended_action = "Require OTP verification and add login delay"
    else:
        risk_level = "Low"
        recommended_action = "Allow normal MFA flow"

    failed_attempts = int(login_attempt.get("failed_attempts", 0))
    success = convert_bool(login_attempt.get("success"))
    mfa_enabled = convert_bool(login_attempt.get("mfa_enabled"))
    account_status = str(login_attempt.get("account_status", "unknown")).strip().lower()

    if success == 0 and failed_attempts >= 5:
        risk_level = "High"
        recommended_action = "Temporarily block account due to repeated failed password attempts"

    elif success == 0 and failed_attempts >= 3:
        if risk_level != "High":
            risk_level = "Medium"
            recommended_action = "Require OTP verification and delay next login attempt"

    elif mfa_enabled == 0 and failed_attempts >= 2:
        if risk_level == "Low":
            risk_level = "Medium"
            recommended_action = "Require MFA setup or OTP verification"

    elif account_status in ["locked", "suspended", "disabled"]:
        risk_level = "High"
        recommended_action = "Block login because account status is not active"

    return {
        "prediction": prediction_label,
        "risk_probability": round(risk_probability, 4),
        "risk_level": risk_level,
        "recommended_action": recommended_action,
        "model_input": final_input
    }