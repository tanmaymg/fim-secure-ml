
def make_risk_decision(file_event, crypto_result, ml_label):
    # Convert numeric labels to readable labels
    labels = {
        0: "benign",
        1: "suspicious",
        2: "malicious"
    }

    if isinstance(ml_label, (int, float)):
        label = labels.get(int(ml_label), "unknown")
    else:
        label = str(ml_label).strip().lower()

    risk_map = {
        "benign": (0, "LOW"),
        "suspicious": (1, "MEDIUM"),
        "malicious": (2, "CRITICAL"),
        "unknown": (2, "CRITICAL")
    }

    risk_score, risk_level = risk_map.get(
        label, (2, "CRITICAL")
    )

    file_path = file_event.get("file_path", "unknown")

    status = str(
        crypto_result.get("integrity_status", "UNKNOWN")
    ).strip().upper()

    if status == "TAMPERED":
        status = "MISMATCH"

    
# Decide the action using integrity status and ML risk
    if label == "malicious" or label == "unknown":
        alert = True
    elif label == "suspicious":
        alert = True
    elif status == "MISMATCH":
        alert = True
    else:
        alert = False


    return {
        "file_path": file_path,
        "integrity_status": status,
        "ml_label": label,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "final_action": "ALERT RAISED" if alert else "LOG ONLY"
    }
