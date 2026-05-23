import pandas as pd
import ipaddress
import joblib
from datetime import datetime


# ===================================================
# 1. Load Model and Feature Info
# ===================================================

MODEL_PATH = "decision_tree_password_guessing_model.pkl"
FEATURE_PATH = "model_features.pkl"

model = joblib.load(MODEL_PATH)
feature_info = joblib.load(FEATURE_PATH)

numeric_cols = feature_info["numeric_cols"]
categorical_cols = feature_info["categorical_cols"]
target_col = feature_info["target_col"]

print("Model loaded successfully.")
print("Target:", target_col)

print("\nNumeric columns expected:")
print(numeric_cols)

print("\nCategorical columns expected:")
print(categorical_cols)


# ===================================================
# 2. Helper Functions
# ===================================================

def convert_bool(value):
    """
    Convert True/False, Yes/No, 1/0 into numeric 1/0.
    """
    if value is None:
        return 0

    value = str(value).strip().lower()

    if value in ["true", "yes", "1", "success", "successful"]:
        return 1
    elif value in ["false", "no", "0", "fail", "failed"]:
        return 0
    else:
        return 0


def ip_to_int(ip):
    """
    Convert IP address into integer.
    If invalid IP, return 0.
    """
    try:
        return int(ipaddress.ip_address(str(ip)))
    except Exception:
        return 0


def get_login_features(timestamp_value):
    """
    Extract login_hour and unusual_hour from timestamp.
    """
    dt = pd.to_datetime(timestamp_value, errors="coerce")

    if pd.isna(dt):
        dt = datetime.now()

    login_hour = dt.hour
    unusual_hour = 1 if login_hour < 5 else 0

    return login_hour, unusual_hour


# ===================================================
# 3. Example Login Attempt
# ===================================================
# Only important columns are used.

login_attempt = {
    "timestamp": "2026-05-23 02:30:00",
    "ip_address": "45.155.205.10",

    "device_type": "PC",
    "os_type": "Windows",
    "browser": "Chrome",
    "location": "Kuala Lumpur, Malaysia",

    "login_method": "Password",
    "success": False,
    "auth_type": "Password",
    "account_status": "Active",

    "failed_attempts": 6,
    "mfa_enabled": False,
    "token_expired": False,
    "password_age_days": 120
}


# ===================================================
# 4. Feature Engineering
# ===================================================

login_hour, unusual_hour = get_login_features(login_attempt.get("timestamp"))

processed_input = {
    # Engineered numeric features
    "login_hour": login_hour,
    "unusual_hour": unusual_hour,
    "ip_int": ip_to_int(login_attempt.get("ip_address")),

    # Numeric / boolean features
    "failed_attempts": login_attempt.get("failed_attempts", 0),
    "success": convert_bool(login_attempt.get("success")),
    "mfa_enabled": convert_bool(login_attempt.get("mfa_enabled")),
    "token_expired": convert_bool(login_attempt.get("token_expired")),
    "password_age_days": login_attempt.get("password_age_days", 0),

    # Categorical features
    "device_type": str(login_attempt.get("device_type", "unknown")).strip().lower(),
    "os_type": str(login_attempt.get("os_type", "unknown")).strip().lower(),
    "browser": str(login_attempt.get("browser", "unknown")).strip().lower(),
    "location": str(login_attempt.get("location", "unknown")).strip().lower(),
    "login_method": str(login_attempt.get("login_method", "unknown")).strip().lower(),
    "auth_type": str(login_attempt.get("auth_type", "unknown")).strip().lower(),
    "account_status": str(login_attempt.get("account_status", "unknown")).strip().lower()
}


# ===================================================
# 5. Build Input DataFrame Based on Model Features
# ===================================================

all_expected_cols = numeric_cols + categorical_cols
final_input = {}

for col in all_expected_cols:
    if col in processed_input:
        final_input[col] = processed_input[col]
    else:
        if col in numeric_cols:
            final_input[col] = 0
        else:
            final_input[col] = "unknown"

input_df = pd.DataFrame([final_input])
input_df = input_df[all_expected_cols]


# ===================================================
# 6. Predict
# ===================================================

prediction = model.predict(input_df)[0]
probabilities = model.predict_proba(input_df)[0]

if 1 in model.classes_:
    risk_index = list(model.classes_).index(1)
    risk_probability = probabilities[risk_index]
else:
    risk_probability = 0.0


# ===================================================
# 7. Interpret Prediction
# ===================================================

if prediction == 1:
    prediction_label = "Password Guessing Risk Detected"
else:
    prediction_label = "Normal Login"

if risk_probability >= 0.70:
    risk_level = "High"
    recommended_action = "Temporarily block login or require stronger MFA"
elif risk_probability >= 0.40:
    risk_level = "Medium"
    recommended_action = "Require OTP verification and add login delay"
else:
    risk_level = "Low"
    recommended_action = "Allow normal MFA flow"


# ===================================================
# 8. Additional Safety Rule for MFA System
# ===================================================
# This is system response logic, not the ML model.

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


# ===================================================
# 9. Output Result
# ===================================================

print("\n===== PASSWORD GUESSING DETECTION RESULT =====")
print("Prediction:", prediction_label)
print("Risk Probability:", round(float(risk_probability), 4))
print("Risk Level:", risk_level)
print("Recommended Action:", recommended_action)

print("\n===== IMPORTANT INPUT USED =====")
for key, value in login_attempt.items():
    print(f"{key}: {value}")

print("\n===== INPUT SENT TO MODEL =====")
print(input_df)