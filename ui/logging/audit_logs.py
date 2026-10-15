
import json
from datetime import datetime, timezone
from pathlib import Path

# Project root is the parent of the ui directory
PROJECT_ROOT = Path(__file__).resolve().parents[2]
STORAGE_DIR = PROJECT_ROOT / "ui" / "storage"
LOG_FILE = STORAGE_DIR / "audit_logs.jsonl"


def log_event(event: dict):
    """Append a security event to the audit log."""

    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary")

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    log_entry = {
        "logged_at": datetime.now(timezone.utc).isoformat(),
        **event
    }

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

    return log_entry
