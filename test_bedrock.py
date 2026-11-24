
from app.bedrock import analyze_security_event

security_event = {
    "event_type": "failed_login_attempts",
    "source_ip": "203.0.113.25",
    "failed_attempts": 25,
    "time_window": "2 minutes",
    "target": "test-iam-user",
    "mfa_enabled": False
}

try:
    result = analyze_security_event(security_event)

    print("\n===== CLOUDSENTINEL AI ANALYSIS =====\n")

    for key, value in result.items():
        print(f"{key}: {value}")

except Exception as error:
    print("Bedrock error:", error)