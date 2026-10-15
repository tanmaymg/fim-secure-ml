import json

from alerts.alert_engine import evaluate_event
from ui.logging.audit_logs import log_event
from pathlib import Path


def run_pipeline(payload_path: str):
    # 1. Load mock payload
    with open(payload_path, "r") as f:
        event = json.load(f)

    # 2. Run alert engine
    alert_decision = evaluate_event(event)

    # 3. Build final log entry
    log_entry = {
        **event,
        **alert_decision
    }

    # 4. Write to audit log
    log_event(log_entry)

    return log_entry




# Streamlit dashboard
import streamlit as st

st.set_page_config(
    page_title="Intelligent File Integrity Monitoring",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Intelligent File Integrity Monitoring")
st.caption("ML-Based File Integrity Monitoring with False-Alarm Reduction")

st.subheader("Pipeline Test")

UI_DIR = Path(__file__).resolve().parent
PAYLOAD_DIR = UI_DIR / "test_payloads"

payload_name = st.selectbox(
    "Select a test scenario",
    ["benign.json", "suspicious.json", "malicious.json"]
)

if st.button("Run Integrity Check"):
    payload_path = PAYLOAD_DIR / payload_name

    try:
        if not payload_path.exists():
            st.error(f"Payload not found: {payload_path}")
        else:
            result = run_pipeline(str(payload_path))

            st.subheader("Pipeline Test Result")
            st.metric(
                "Integrity Status",
                str(result.get("integrity_status", "Unknown"))
            )
            st.metric(
                "Alert Severity",
                str(result.get("alert_severity", "Unknown"))
            )

            st.write("**File:**", result.get("file_path", "Unknown"))
            st.write(
                "**Alert Generated:**",
                result.get("alert_generated", False)
            )
            st.write(
                "**Reason:**",
                result.get("alert_reason", "Not provided")
            )

            st.subheader("Complete Pipeline Output")
            st.json(result)

    except Exception as e:
        st.error(f"Pipeline execution failed: {e}")



# Audit Log Viewer
st.divider()
st.header("📋 Audit Log & Alert History")

UI_DIR = Path(__file__).resolve().parent
LOG_FILE = UI_DIR / "storage" / "audit_logs.jsonl"

if st.button("Refresh Audit History"):
    st.rerun()

if LOG_FILE.exists():
    entries = []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if entries:
        # Newest events first
        entries.reverse()

        alerts = [
            entry for entry in entries
            if entry.get("alert_generated") is True
        ]

        col1, col2 = st.columns(2)
        col1.metric("Total Events Logged", len(entries))
        col2.metric("Alerts Generated", len(alerts))

        st.subheader("Recent Security Events")
        st.dataframe(entries, use_container_width=True)

        st.subheader("Alert History")
        if alerts:
            st.dataframe(alerts, use_container_width=True)
        else:
            st.info("No alerts have been recorded yet.")
    else:
        st.info("The audit log exists but contains no entries.")
else:
    st.info("Audit log not found. Run a pipeline test first.")



# Security Analytics
st.divider()
st.header("📊 Security Analytics")

if entries:
    import pandas as pd

    df = pd.DataFrame(entries)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Events by Integrity Status")
        if "integrity_status" in df.columns:
            counts = df["integrity_status"].value_counts()
            st.bar_chart(counts)

    with col2:
        st.subheader("Events by Alert Severity")
        if "alert_severity" in df.columns:
            counts = df["alert_severity"].value_counts()
            st.bar_chart(counts)

    st.subheader("Alert Outcome Summary")
    if "alert_generated" in df.columns:
        alert_counts = (
            df["alert_generated"]
            .map({True: "Alert generated", False: "No alert"})
            .fillna("Unknown")
            .value_counts()
        )
        st.bar_chart(alert_counts)
else:
    st.info("Run a pipeline test to generate analytics.")
