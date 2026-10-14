import requests
import base64
import yaml
import json
import uuid
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from publisher import publish_event
import hashlib
import os


def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)
    
def sha256_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def url_to_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def analyze_url(url, api_key):
    headers = {"x-apikey": api_key}

    # Step 1: try to get an existing VirusTotal report
    url_id = url_to_id(url)
    report_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(report_endpoint, headers=headers, timeout=30)

    if response.status_code == 200:
        return response.json()

    # Bad API key / auth issue
    if response.status_code == 401:
        raise Exception("VirusTotal API authentication failed. Check your API key in config.yaml.")

    # Step 2: if report doesn't exist yet, submit URL for scanning
    if response.status_code == 404:
        scan_endpoint = "https://www.virustotal.com/api/v3/urls"
        scan_response = requests.post(
            scan_endpoint,
            headers=headers,
            data={"url": url},
            timeout=30
        )

        if scan_response.status_code == 401:
            raise Exception("VirusTotal API authentication failed during URL submission. Check your API key in config.yaml.")

        scan_response.raise_for_status()

        analysis_id = scan_response.json()["data"]["id"]
        analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        # Step 3: poll until analysis is complete
        max_attempts = 20
        wait_seconds = 5

        for attempt in range(max_attempts):
            analysis_response = requests.get(analysis_endpoint, headers=headers, timeout=30)

            if analysis_response.status_code == 401:
                raise Exception("VirusTotal API authentication failed while polling analysis results.")

            analysis_response.raise_for_status()

            analysis_data = analysis_response.json()
            status = analysis_data["data"]["attributes"]["status"]

            print(f"VirusTotal scan status: {status} (attempt {attempt + 1}/{max_attempts})")

            if status == "completed":
                final_report = requests.get(report_endpoint, headers=headers, timeout=30)

                if final_report.status_code == 401:
                    raise Exception("VirusTotal API authentication failed while retrieving final report.")

                final_report.raise_for_status()
                return final_report.json()

            time.sleep(wait_seconds)

        raise Exception("VirusTotal analysis did not finish in time after waiting longer than expected.")

    # Step 4: raise anything else normally
    response.raise_for_status()


def save_event(event):
    with open("events.jsonl", "a") as file:
        file.write(json.dumps(event) + "\n")


def save_alerts(alerts):
    if not alerts:
        return

    with open("alerts.jsonl", "a") as file:
        for alert in alerts:
            file.write(json.dumps(alert) + "\n")


def load_events():
    path = Path("events.jsonl")
    if not path.exists():
        return []

    events = []
    with open("events.jsonl", "r") as file:
        for line in file:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def print_events(events):
    if not events:
        print("\nNo events found.\n")
        return

    print()
    for i, event in enumerate(events, start=1):
        print(f"Event {i}")
        print(json.dumps(event, indent=4))
        print()


def analyze_file(file_path, api_key):
    headers = {"x-apikey": api_key}

    if not os.path.exists(file_path):
        raise Exception("File not found.")

    file_size = os.path.getsize(file_path)

    # VirusTotal uses a different upload flow for files over 32 MB
    if file_size > 32 * 1024 * 1024:
        upload_url_resp = requests.get(
            "https://www.virustotal.com/api/v3/files/upload_url",
            headers=headers,
            timeout=30
        )
        upload_url_resp.raise_for_status()
        upload_url = upload_url_resp.json()["data"]
    else:
        upload_url = "https://www.virustotal.com/api/v3/files"

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        upload_resp = requests.post(upload_url, headers=headers, files=files, timeout=60)
        upload_resp.raise_for_status()

    analysis_id = upload_resp.json()["data"]["id"]
    analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    max_attempts = 20
    wait_seconds = 5

    for attempt in range(max_attempts):
        analysis_response = requests.get(analysis_endpoint, headers=headers, timeout=30)
        analysis_response.raise_for_status()

        analysis_data = analysis_response.json()
        status = analysis_data["data"]["attributes"]["status"]

        print(f"VirusTotal file scan status: {status} (attempt {attempt + 1}/{max_attempts})")

        if status == "completed":
            file_hash = sha256_file(file_path)
            file_report_endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            final_report = requests.get(file_report_endpoint, headers=headers, timeout=30)
            final_report.raise_for_status()
            return final_report.json(), file_hash

        time.sleep(wait_seconds)

    raise Exception("VirusTotal file analysis did not finish in time.")

def build_event(url, vt_report, indicator_type="url", file_name=None):
    # construct a basic SIEM event from a VirusTotal URL report
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
    import re
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


def main():
    config = load_config()
    api_key = config["virustotal"]["api_key"]

    while True:
        print("\nMini SIEM Menu")
        print("1. Analyze a URL")
        print("2. Analyze a file")
        print("3. Show all saved events")
        print("4. Show suspicious or malicious events")
        print("5. Show HIGH or CRITICAL severity events")
        print("6. Exit")

        choice = input("\nChoose an option: ").strip()

        if choice == "1":
            url = input("Enter a URL to analyze: ").strip()

            try:
                result = analyze_url(url, api_key)
                event = build_event(url, result, indicator_type="url")
                alerts = detect_mitre_threat(event)

                save_event(event)
                save_alerts(alerts)

                try:
                    message_id = publish_event(event)
                    print(f"\nPublished to Pub/Sub. Message ID: {message_id}")
                except Exception as e:
                    print(f"\nFailed to publish to Pub/Sub: {e}")

                print("\nSIEM Event:\n")
                print(json.dumps(event, indent=4))

                if alerts:
                    print("\nGenerated Alerts:\n")
                    for alert in alerts:
                        print(json.dumps(alert, indent=4))

                print("\nEvent saved to events.jsonl")
                if alerts:
                    print("Alert(s) saved to alerts.jsonl")

            except Exception as e:
                print(f"\nAnalysis failed: {e}")

        elif choice == "2":
            file_path = input("Enter a file path: ").strip().strip('"')
            file_path = file_path.replace("file:///", "").replace("%20", " ")

            try:
                result, file_hash = analyze_file(file_path, api_key)
                event = build_event(
                    file_hash,
                    result,
                    indicator_type="file_hash",
                    file_name=os.path.basename(file_path)
                )
                alerts = detect_mitre_threat(event)

                save_event(event)
                save_alerts(alerts)

                try:
                    message_id = publish_event(event)
                    print(f"\nPublished to Pub/Sub. Message ID: {message_id}")
                except Exception as e:
                    print(f"\nFailed to publish to Pub/Sub: {e}")

                print("\nSIEM Event:\n")
                print(json.dumps(event, indent=4))

                if alerts:
                    print("\nGenerated Alerts:\n")
                    for alert in alerts:
                        print(json.dumps(alert, indent=4))

                print("\nEvent saved to events.jsonl")
                if alerts:
                    print("Alert(s) saved to alerts.jsonl")

            except Exception as e:
                print(f"\nAnalysis failed: {e}")

        elif choice == "3":
            events = load_events()
            print_events(events)

        elif choice == "4":
            events = load_events()
            filtered = [
                event for event in events
                if event["final_verdict"] in ["Suspicious", "Malicious"]
            ]
            print_events(filtered)

        elif choice == "5":
            events = load_events()
            filtered = [
                event for event in events
                if event["severity"] in ["HIGH", "CRITICAL"]
            ]
            print_events(filtered)

        elif choice == "6":
            print("\nGoodbye.")
            break

        else:
            print("\nInvalid choice. Try again.")

if __name__ == "__main__":
    main()