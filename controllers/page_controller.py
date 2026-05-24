from flask import render_template


def register_page():
    return render_template("register.html")


def login_page():
    return render_template("login.html")


def otp_page():
    return render_template("otp.html")


def success_page():
    return render_template("success.html")


def blocked_page():
    return render_template("blocked.html")


def records_page():
    return render_template("records.html")