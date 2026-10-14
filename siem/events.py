"""Event normalization, severity scoring, and phishing detection."""

import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse


def build_event(url, vt_report, indicator_type="url", file_name=None):
    # Normalize URL and file reports to the shared BigQuery event schema.
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.path) if indicator_type == "url" else None
    timestamp = datetime.now(timezone.utc).isoformat()
    event_id = str(uuid.uuid4())
    indicator_value = url

    attrs = vt_report.get("data", {}).get("attributes", {}) if isinstance(vt_report, dict) else {}
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 5:
        severity = "CRITICAL"
    elif malicious > 0:
        severity = "HIGH"
    elif suspicious > 0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if malicious > 0:
        final_verdict = "Malicious"
    elif suspicious > 0:
        final_verdict = "Suspicious"
    else:
        final_verdict = "Benign"

    tags = attrs.get("tags", [])
    # Only retain explicit technique IDs; generic VT tags are not ATT&CK mappings.
    mitre_techniques = [tag for tag in tags if isinstance(tag, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", tag)] if isinstance(tags, list) else []

    event = {
        "event_id": event_id,
        "timestamp": timestamp,
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "domain": domain,
        "mitre_techniques": mitre_techniques,
        "severity": severity,
        "final_verdict": final_verdict,
        "vt_malicious": malicious,
        "vt_suspicious": suspicious,
        "vt_harmless": stats.get("harmless", 0),
        "reputation": attrs.get("reputation"),
        "source": "virustotal",
        "file_name": file_name
    }

    return event

def detect_mitre_threat(event):
    alerts = []

    if "T1566" in event["mitre_techniques"] or "T1566.002" in event["mitre_techniques"]:
        alerts.append({
            "alert_id": str(uuid.uuid4()),
            "timestamp": event["timestamp"],
            "alert_type": "PHISHING_ACTIVITY",
            "technique": "T1566",
            "indicator": event["indicator_value"],
            "domain": event["domain"],
            "severity": event["severity"],
            "source_event_id": event["event_id"]
        })

    return alerts
