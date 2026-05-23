import pandas as pd
import ipaddress
import joblib

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)


# ===================================================
# 1. Load Dataset
# ===================================================

DATASET_PATH = "dataset/login_security_dataset.csv"

data = pd.read_csv(DATASET_PATH)

# Clean column names
data.columns = data.columns.str.strip().str.lower()

print("Dataset loaded successfully.")
print("Columns found:")
print(data.columns.tolist())


# ===================================================
# 2. Helper Functions
# ===================================================

def convert_bool(value):
    """
    Convert True/False, Yes/No, 1/0 into numeric 1/0.
    """
    if pd.isna(value):
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


# ===================================================
# 3. Timestamp Feature Engineering
# ===================================================

if "timestamp" in data.columns:
    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce")
    data["login_hour"] = data["timestamp"].dt.hour.fillna(0).astype(int)

    # Unusual hour = login between 12 AM and 5 AM
    data["unusual_hour"] = data["login_hour"].apply(
        lambda x: 1 if x < 5 else 0
    )
else:
    data["login_hour"] = 0
    data["unusual_hour"] = 0


# ===================================================
# 4. IP Address Conversion
# ===================================================

if "ip_address" in data.columns:
    data["ip_int"] = data["ip_address"].apply(ip_to_int)
else:
    data["ip_int"] = 0


# ===================================================
# 5. Convert Boolean Columns
# ===================================================

bool_cols = [
    "success",
    "mfa_enabled",
    "token_expired",
    "blocked"
]

converted_cols = []

for col in bool_cols:
    if col in data.columns:
        data[col] = data[col].apply(convert_bool)
        converted_cols.append(col)
    else:
        data[col] = 0

print("\nBoolean columns converted:")
print(converted_cols)


# ===================================================
# 6. Clean Text Columns
# ===================================================

text_cols = [
    "device_type",
    "os_type",
    "browser",
    "location",
    "login_method",
    "auth_type",
    "account_status"
]

for col in text_cols:
    if col in data.columns:
        data[col] = data[col].fillna("unknown").astype(str).str.strip().str.lower()
    else:
        data[col] = "unknown"


# ===================================================
# 7. Clean Numeric Columns
# ===================================================

numeric_base_cols = [
    "failed_attempts",
    "password_age_days"
]

for col in numeric_base_cols:
    if col in data.columns:
        data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0)
    else:
        data[col] = 0


# ===================================================
# 8. Create Target Label: password_guessing_risk
# ===================================================
# This target focuses on password guessing behaviour.
# The original suspicious_activity column is not used because it was not meaningful.

data["password_guessing_risk"] = (
    # Failed login with many failed attempts
    ((data["success"] == 0) & (data["failed_attempts"] >= 5)) |

    # Very high failed attempts, even if latest attempt succeeded
    (data["failed_attempts"] >= 8) |

    # Blocked account with repeated failed attempts
    ((data["blocked"] == 1) & (data["failed_attempts"] >= 3)) |

    # MFA disabled + failed login + repeated attempts
    ((data["mfa_enabled"] == 0) & (data["success"] == 0) & (data["failed_attempts"] >= 4)) |

    # Locked/suspended/disabled account + failed login + repeated attempts
    (
        data["account_status"].isin(["locked", "suspended", "disabled"]) &
        (data["success"] == 0) &
        (data["failed_attempts"] >= 3)
    )
).astype(int)

target_col = "password_guessing_risk"


# ===================================================
# 9. Select Final Features
# ===================================================
# Removed:
# user_id, username, role, privilege_level, error_code,
# failure_reason, session_duration, suspicious_activity,
# threat_level, blocked, system_component

numeric_cols = [
    "login_hour",
    "unusual_hour",
    "ip_int",
    "failed_attempts",
    "success",
    "mfa_enabled",
    "token_expired",
    "password_age_days"
]

categorical_cols = [
    "device_type",
    "os_type",
    "browser",
    "location",
    "login_method",
    "auth_type",
    "account_status"
]

features = numeric_cols + categorical_cols

print("\nNumeric features used:")
print(numeric_cols)

print("\nCategorical features used:")
print(categorical_cols)

print("\nTarget label:")
print(target_col)

print("\nTarget distribution:")
print(data[target_col].value_counts())


# ===================================================
# 10. Prepare X and y
# ===================================================

X = data[features]
y = data[target_col].astype(int)


# ===================================================
# 11. Preprocessing
# ===================================================

numeric_transformer = Pipeline(steps=[
    ("imputer", SimpleImputer(strategy="median")),
    ("scaler", StandardScaler())
])

categorical_transformer = Pipeline(steps=[
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("onehot", OneHotEncoder(handle_unknown="ignore"))
])

preprocessor = ColumnTransformer(
    transformers=[
        ("num", numeric_transformer, numeric_cols),
        ("cat", categorical_transformer, categorical_cols)
    ]
)


# ===================================================
# 12. Decision Tree Model
# ===================================================

decision_tree = DecisionTreeClassifier(
    max_depth=8,
    min_samples_split=20,
    min_samples_leaf=10,
    random_state=42,
    class_weight="balanced"
)

model_pipeline = Pipeline(steps=[
    ("preprocessor", preprocessor),
    ("classifier", decision_tree)
])


# ===================================================
# 13. Train-Test Split
# ===================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# ===================================================
# 14. Train Model
# ===================================================

print("\nTraining Decision Tree model...")
model_pipeline.fit(X_train, y_train)
print("Training completed.")


# ===================================================
# 15. Evaluate Model
# ===================================================

predictions = model_pipeline.predict(X_test)

print("\n===== MODEL EVALUATION =====")
print("Accuracy:", accuracy_score(y_test, predictions))

try:
    probabilities = model_pipeline.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, probabilities)
    print("AUC Score:", auc)
except Exception as e:
    print("AUC Score could not be calculated:", e)

print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))


# ===================================================
# 16. Save Model and Feature Info
# ===================================================

MODEL_PATH = "decision_tree_password_guessing_model.pkl"
FEATURE_PATH = "model_features.pkl"

joblib.dump(model_pipeline, MODEL_PATH)

feature_info = {
    "numeric_cols": numeric_cols,
    "categorical_cols": categorical_cols,
    "target_col": target_col
}

joblib.dump(feature_info, FEATURE_PATH)

print(f"\nModel saved successfully as: {MODEL_PATH}")
print(f"Feature information saved as: {FEATURE_PATH}")