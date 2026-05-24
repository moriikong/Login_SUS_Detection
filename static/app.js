const API_URL = "http://127.0.0.1:5000";


// ===================================================
// 1. Common UI Helper
// ===================================================

function showFlash(message, type = "info") {
    const flashBox = document.getElementById("flashBox");

    if (!flashBox) {
        alert(message);
        return;
    }

    flashBox.style.display = "block";
    flashBox.textContent = message;

    if (type === "error") {
        flashBox.style.background = "#fee2e2";
        flashBox.style.borderLeftColor = "#dc2626";
        flashBox.style.color = "#7f1d1d";
    } else {
        flashBox.style.background = "#dbeafe";
        flashBox.style.borderLeftColor = "#2563eb";
        flashBox.style.color = "#1e3a8a";
    }
}

function saveBlockedState(message, remainingSeconds = null) {
    localStorage.setItem("blocked_message", message || "Access temporarily blocked.");

    if (remainingSeconds !== null && remainingSeconds !== undefined) {
        const blockedUntil = Date.now() + Number(remainingSeconds) * 1000;
        localStorage.setItem("blocked_until_ms", blockedUntil);
        localStorage.setItem("blocked_remaining_seconds", remainingSeconds);
    } else {
        localStorage.removeItem("blocked_until_ms");
        localStorage.removeItem("blocked_remaining_seconds");
    }
}

// ===================================================
// 2. Register User
// ===================================================

async function registerUser(event) {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirm_password").value;

    if (password !== confirmPassword) {
        showFlash("Passwords do not match.", "error");
        return;
    }

    try {
        const response = await fetch(`${API_URL}/users/`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                username: username,
                password: password,
                mfa_enabled: true,
                account_status: "active"
            }),
        });

        const data = await response.json();

        if (!response.ok) {
            showFlash(data.message || "Registration failed.", "error");
            return;
        }

        showFlash("Account created successfully. Redirecting to login...");

        setTimeout(() => {
            window.location.href = "/login-page";
        }, 1000);

    } catch (error) {
        console.error(error);
        showFlash("Cannot connect to backend server.", "error");
    }
}


// ===================================================
// 3. Login User
// ===================================================

async function loginUser(event) {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                username: username,
                password: password
            }),
        });

        const data = await response.json();

        localStorage.setItem("lastLoginResponse", JSON.stringify(data));

        if (data.risk_result) {
            showRiskResult(data.risk_result);
        }

        // Correct password + OTP required
        if (response.status === 200 && data.demo_otp && data.login_record_id) {
            localStorage.setItem("login_record_id", data.login_record_id);
            localStorage.setItem("demo_otp", data.demo_otp);
            localStorage.setItem("risk_result", JSON.stringify(data.risk_result));
            localStorage.removeItem("blocked_message");
            localStorage.removeItem("blocked_remaining_seconds");

            window.location.href = "/otp-page";
            return;
        }

        // Correct password + no OTP required
        if (response.status === 200) {
            localStorage.setItem("risk_result", JSON.stringify(data.risk_result));
            localStorage.removeItem("blocked_message");
            localStorage.removeItem("blocked_remaining_seconds");

            window.location.href = "/success-page";
            return;
        }

        // Wrong password but account not blocked yet
        if (response.status === 401) {
            const message = data.message || "Login failed. Incorrect username or password.";
            showFlash(message, "error");
            return;
        }

        // Temporary account block
        if (response.status === 423) {
            saveBlockedState(
                data.message || "Account or OTP session is temporarily blocked.",
                data.remaining_seconds
            );

            window.location.href = "/blocked-page";
            return;
        }

        // Suspended / disabled account
        if (response.status === 403) {
            localStorage.setItem("blocked_message", data.message || "Account is not active.");
            localStorage.removeItem("blocked_remaining_seconds");

            window.location.href = "/blocked-page";
            return;
        }

        showFlash(data.message || "Login failed.", "error");

    } catch (error) {
        console.error(error);
        showFlash("Cannot connect to backend server.", "error");
    }
}


// ===================================================
// 4. Show Risk Result on Login Page
// ===================================================

function showRiskResult(riskResult) {
    const riskResultBox = document.getElementById("riskResultBox");

    if (!riskResultBox) return;

    riskResultBox.style.display = "block";

    const riskPrediction = document.getElementById("riskPrediction");
    const riskLevel = document.getElementById("riskLevel");
    const riskProbability = document.getElementById("riskProbability");
    const recommendedAction = document.getElementById("recommendedAction");

    if (riskPrediction) {
        riskPrediction.textContent = `Prediction: ${riskResult.prediction}`;
    }

    if (riskLevel) {
        riskLevel.textContent = `Risk Level: ${riskResult.risk_level}`;
    }

    if (riskProbability) {
        riskProbability.textContent = `Risk Probability: ${riskResult.risk_probability}`;
    }

    if (recommendedAction) {
        recommendedAction.textContent = `Recommended Action: ${riskResult.recommended_action}`;
    }
}


// ===================================================
// 5. OTP Verification
// ===================================================

async function verifyOtp(event) {
    event.preventDefault();

    const otp = document.getElementById("otp").value.trim();
    const loginRecordId = localStorage.getItem("login_record_id");

    if (!loginRecordId) {
        showFlash("Missing login record ID. Please login again.", "error");
        return;
    }

    try {
        const response = await fetch(`${API_URL}/auth/verify-otp`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                login_record_id: Number(loginRecordId),
                otp: otp
            }),
        });

        const data = await response.json();

        // OTP expired
        if (response.status === 410) {
            showFlash(data.message || "OTP expired. Please request a new OTP.", "error");

            const info = document.getElementById("otpAttemptInfo");
            if (info) {
                info.textContent = "OTP expired. Click Resend OTP to continue.";
            }

            const otpInput = document.getElementById("otp");
            if (otpInput) {
                otpInput.value = "";
            }

            return;
        }

        // OTP session blocked or account blocked
        if (response.status === 423) {
            localStorage.setItem("lastLoginResponse", JSON.stringify(data));

            if (data.account_blocked === true && data.remaining_seconds !== undefined) {
                saveBlockedState(data.message || "Account temporarily blocked.", data.remaining_seconds);
            } else {
                saveBlockedState(data.message || "OTP session blocked. Please login again.", null);
            }

            window.location.href = "/blocked-page";
            return;
        }

        // Wrong OTP but still can retry
        if (!response.ok) {
            const message = data.remaining_attempts !== undefined
                ? `${data.message} Remaining OTP attempts: ${data.remaining_attempts}`
                : data.message || "OTP verification failed.";

            showFlash(message, "error");

            const info = document.getElementById("otpAttemptInfo");
            if (info) {
                info.textContent = message;
            }

            // Auto-refresh demo OTP after wrong OTP
            if (data.demo_otp) {
                localStorage.setItem("demo_otp", data.demo_otp);

                const demoOtpBox = document.getElementById("demoOtpBox");
                if (demoOtpBox) {
                    demoOtpBox.textContent = `New Demo OTP: ${data.demo_otp}`;
                }

                restartOtpCountdown(data.otp_expires_in || 60);
            }

            const otpInput = document.getElementById("otp");
            if (otpInput) {
                otpInput.value = "";
            }

            return;
        }

        // OTP correct
        localStorage.setItem("otp_verified_record", JSON.stringify(data.record));
        localStorage.removeItem("blocked_message");
        localStorage.removeItem("blocked_remaining_seconds");

        window.location.href = "/success-page";

    } catch (error) {
        console.error(error);
        showFlash("Cannot connect to backend server.", "error");
    }
}


// ===================================================
// 6. Resend OTP
// ===================================================

async function resendOtp() {
    const resendOtpBtn = document.getElementById("resendOtpBtn");

    if (resendOtpBtn && resendOtpBtn.disabled) {
        showFlash("Please wait until the current OTP expires before requesting a new one.", "error");
        return;
    }

    const loginRecordId = localStorage.getItem("login_record_id");

    if (!loginRecordId) {
        showFlash("Missing login record ID. Please login again.", "error");
        return;
    }

    try {
        const response = await fetch(`${API_URL}/auth/resend-otp`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                login_record_id: Number(loginRecordId)
            }),
        });

        const data = await response.json();

        if (response.status === 429) {
            showFlash(data.message || "Current OTP is still valid. Please wait until it expires.", "error");

            if (data.remaining_seconds !== undefined) {
                restartOtpCountdown(data.remaining_seconds);
            }

            return;
        }

        if (response.status === 423) {
            localStorage.setItem("lastLoginResponse", JSON.stringify(data));

            if (data.account_blocked === true && data.remaining_seconds !== undefined) {
                saveBlockedState(data.message || "Account temporarily blocked.", data.remaining_seconds);
            } else {
                saveBlockedState(data.message || "OTP session blocked. Please login again.", null);
            }

            window.location.href = "/blocked-page";
            return;
        }

        if (!response.ok) {
            showFlash(data.message || "Failed to resend OTP.", "error");
            return;
        }

        localStorage.setItem("demo_otp", data.demo_otp);

        const demoOtpBox = document.getElementById("demoOtpBox");

        if (demoOtpBox) {
            demoOtpBox.textContent = `New Demo OTP: ${data.demo_otp}`;
        }

        const info = document.getElementById("otpAttemptInfo");

        if (info) {
            info.textContent = `New OTP generated. Remaining resend attempts: ${data.remaining_resends}`;
        }

        const otpInput = document.getElementById("otp");
        if (otpInput) {
            otpInput.value = "";
        }

        restartOtpCountdown(data.otp_expires_in || 60);

        showFlash("New OTP generated successfully.");

    } catch (error) {
        console.error(error);
        showFlash("Cannot connect to backend server.", "error");
    }
}


// ===================================================
// 7. OTP Page Helpers
// ===================================================

function showDemoOtp() {
    const demoOtpBox = document.getElementById("demoOtpBox");
    const demoOtp = localStorage.getItem("demo_otp");

    if (!demoOtpBox) return;

    if (demoOtp) {
        demoOtpBox.textContent = `Demo OTP: ${demoOtp}`;
    } else {
        demoOtpBox.textContent = "No OTP found. Please login again.";
    }
}


let otpTimer = null;

function startOtpCountdown(seconds = 60) {
    restartOtpCountdown(seconds);
}

function restartOtpCountdown(seconds = 60) {
    let otpTimeLeft = seconds;
    const otpCountdown = document.getElementById("otpCountdown");
    const resendOtpBtn = document.getElementById("resendOtpBtn");

    if (!otpCountdown) return;

    if (otpTimer) {
        clearInterval(otpTimer);
    }

    if (resendOtpBtn) {
        resendOtpBtn.disabled = true;
        resendOtpBtn.textContent = `Resend OTP after ${otpTimeLeft}s`;
    }

    otpCountdown.textContent = otpTimeLeft;

    otpTimer = setInterval(() => {
        otpTimeLeft--;

        if (otpTimeLeft <= 0) {
            clearInterval(otpTimer);
            otpCountdown.textContent = "0";

            showFlash("OTP expired. You may request a new OTP.", "error");

            const info = document.getElementById("otpAttemptInfo");
            if (info) {
                info.textContent = "OTP expired. Click Resend OTP to generate a new OTP.";
            }

            if (resendOtpBtn) {
                resendOtpBtn.disabled = false;
                resendOtpBtn.textContent = "Resend OTP";
            }

        } else {
            otpCountdown.textContent = otpTimeLeft;

            if (resendOtpBtn) {
                resendOtpBtn.disabled = true;
                resendOtpBtn.textContent = `Resend OTP after ${otpTimeLeft}s`;
            }
        }
    }, 1000);
}


// ===================================================
// 8. Success Page
// ===================================================

function showSuccessResult() {
    const box = document.getElementById("successRiskBox");

    if (!box) return;

    const riskResult = JSON.parse(localStorage.getItem("risk_result") || "null");
    const verifiedRecord = JSON.parse(localStorage.getItem("otp_verified_record") || "null");

    if (!riskResult && !verifiedRecord) {
        box.innerHTML = "No login result found.";
        return;
    }

    if (riskResult) {
        box.innerHTML = `
            <strong>ML Detection Result</strong><br>
            Prediction: ${riskResult.prediction}<br>
            Risk Level: ${riskResult.risk_level}<br>
            Risk Probability: ${riskResult.risk_probability}<br>
            Recommended Action: ${riskResult.recommended_action}
        `;
        return;
    }

    box.innerHTML = `
        <strong>Login Result</strong><br>
        OTP Verified: ${verifiedRecord.otp_verified ? "Yes" : "No"}<br>
        Username: ${verifiedRecord.username}
    `;
}


// ===================================================
// 9. Blocked Page
// ===================================================

function showBlockedResult() {
    const blockedMessageStorage = localStorage.getItem("blocked_message");
    const lastLoginResponse = JSON.parse(localStorage.getItem("lastLoginResponse") || "null");

    const blockedMessage = document.getElementById("blockedMessage");
    const countdownBox = document.getElementById("countdownBox");

    if (!blockedMessage) return;

    if (blockedMessageStorage) {
        blockedMessage.textContent = blockedMessageStorage;
    } else if (lastLoginResponse && lastLoginResponse.risk_result) {
        blockedMessage.textContent = lastLoginResponse.risk_result.recommended_action;
    } else {
        blockedMessage.textContent = "Access is blocked. Please return to login.";
    }

    const blockedUntil = localStorage.getItem("blocked_until_ms");

    if (blockedUntil && countdownBox) {
        countdownBox.style.display = "block";
    } else if (countdownBox) {
        countdownBox.style.display = "none";
    }
}


function startBlockedCountdown() {
    const countdown = document.getElementById("countdown");
    const countdownBox = document.getElementById("countdownBox");

    if (!countdown || !countdownBox) return;

    const blockedUntil = localStorage.getItem("blocked_until_ms");

    if (!blockedUntil) {
        countdownBox.style.display = "none";
        return;
    }

    countdownBox.style.display = "block";

    const timer = setInterval(() => {
        const remainingMs = Number(blockedUntil) - Date.now();
        const remainingSeconds = Math.max(0, Math.ceil(remainingMs / 1000));

        countdown.textContent = remainingSeconds;

        if (remainingSeconds <= 0) {
            clearInterval(timer);

            localStorage.removeItem("blocked_until_ms");
            localStorage.removeItem("blocked_remaining_seconds");
            localStorage.removeItem("blocked_message");

            window.location.href = "/login-page";
        }
    }, 1000);
}

function formatDateTime(dateString) {
    if (!dateString) return "-";

    const date = new Date(dateString);

    if (isNaN(date.getTime())) {
        return dateString;
    }

    return date.toLocaleString("en-MY", {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true
    });
}

// ===================================================
// 10. Login Records Page
// ===================================================

async function loadRecords() {
    const tbody = document.getElementById("recordsTableBody");

    if (!tbody) return;

    try {
        const response = await fetch(`${API_URL}/records/`);
        const data = await response.json();

        if (!response.ok) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="12">Failed to load records.</td>
                </tr>
            `;
            return;
        }

        const records = data.records || [];

        if (records.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="12">No login records found.</td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = records.map(record => `
            <tr>
                <td>${record.id}</td>
                <td>${record.username}</td>
                <td>${record.success ? "Success" : "Failed"}</td>
                <td>${record.failed_attempts}</td>
                <td>${record.otp_attempts ?? 0}</td>
                <td>${record.otp_blocked ? "Yes" : "No"}</td>
                <td>${record.prediction || "-"}</td>
                <td>${record.risk_probability ?? "-"}</td>
                <td>${record.risk_level || "-"}</td>
                <td>${record.recommended_action || "-"}</td>
                <td>${record.browser || "-"}</td>
                <td>${record.os_type || "-"}</td>
                <td>${record.ip_address || "-"}</td>
                <td>${formatDateTime(record.timestamp)}</td>
            </tr>
        `).join("");

    } catch (error) {
        console.error(error);

        tbody.innerHTML = `
            <tr>
                <td colspan="12">Cannot connect to backend server.</td>
            </tr>
        `;
    }
}


// ===================================================
// 11. Attach Events When Page Loads
// ===================================================

document.addEventListener("DOMContentLoaded", () => {
    const registerForm = document.getElementById("registerForm");
    const loginForm = document.getElementById("loginForm");
    const otpForm = document.getElementById("otpForm");
    const resendOtpBtn = document.getElementById("resendOtpBtn");

    const recordsTableBody = document.getElementById("recordsTableBody");
    const successRiskBox = document.getElementById("successRiskBox");
    const blockedMessage = document.getElementById("blockedMessage");

    if (registerForm) {
        registerForm.addEventListener("submit", registerUser);
    }

    if (loginForm) {
        loginForm.addEventListener("submit", loginUser);
    }

    if (otpForm) {
        showDemoOtp();
        startOtpCountdown();
        otpForm.addEventListener("submit", verifyOtp);
    }

    if (resendOtpBtn) {
        resendOtpBtn.addEventListener("click", resendOtp);
    }

    if (recordsTableBody) {
        loadRecords();
    }

    if (successRiskBox) {
        showSuccessResult();
    }

    if (blockedMessage) {
        showBlockedResult();
        startBlockedCountdown();
    }
});