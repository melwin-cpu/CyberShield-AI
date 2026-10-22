def calculate_risk(stats):
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    score = (
        malicious * 20 +
        suspicious * 10
    )

    if harmless > 50:
        score -= 10

    if score < 0:
        score = 0

    if score > 100:
        score = 100

    return score


def get_threat_level(score):

    if score <= 10:
        return "🟢 SAFE"

    elif score <= 40:
        return "🟡 LOW RISK"

    elif score <= 70:
        return "🟠 MEDIUM RISK"

    elif score <= 90:
        return "🔴 HIGH RISK"

    else:
        return "☠️ CRITICAL"


def get_recommendation(score):

    if score <= 10:
        return "No action required."

    elif score <= 40:
        return "Monitor this file."

    elif score <= 70:
        return "Scan using multiple antivirus engines."

    elif score <= 90:
        return "Quarantine this file immediately."

    else:
        return "Delete the file immediately and investigate the system."