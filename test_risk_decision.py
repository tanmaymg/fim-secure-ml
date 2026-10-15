
from common.risk_decision import make_risk_decision

file_event = {
    "file_path": "test.exe",
    "event_type": "modified"
}

scenarios = [
    ("Benign", 0, "MATCH"),
    ("Suspicious", 1, "MISMATCH"),
    ("Malicious", 2, "TAMPERED"),
]

for name, ml_label, status in scenarios:
    result = make_risk_decision(
        file_event,
        {"integrity_status": status},
        ml_label
    )

    print(f"\n--- {name} Scenario ---")
    print(result)
