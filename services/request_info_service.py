from flask import request
from user_agents import parse


def get_client_ip():
    """
    Get client IP address from request.
    In local development, this may show 127.0.0.1.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")

    if real_ip:
        return real_ip.strip()

    return request.remote_addr or "0.0.0.0"


def get_device_info():
    """
    Detect browser, operating system, and device type from User-Agent.
    """
    user_agent_string = request.headers.get("User-Agent", "")
    user_agent = parse(user_agent_string)

    browser = user_agent.browser.family or "unknown"
    os_type = user_agent.os.family or "unknown"

    if user_agent.is_mobile:
        device_type = "Mobile"
    elif user_agent.is_tablet:
        device_type = "Tablet"
    elif user_agent.is_pc:
        device_type = "PC"
    else:
        device_type = "Unknown"

    return {
        "device_type": device_type,
        "os_type": os_type,
        "browser": browser
    }