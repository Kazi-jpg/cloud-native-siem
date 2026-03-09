import requests
import base64
import yaml
import json
from datetime import datetime, timezone
from pathlib import Path


def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)


def url_to_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def analyze_url(url, api_key):
    url_id = url_to_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}

    response = requests.get(endpoint, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()


def save_event(event):
    with open("events.jsonl", "a") as file:
        file.write(json.dumps(event) + "\n")


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


def build_event(url, result):
    attrs = result["data"]["attributes"]
    stats = attrs["last_analysis_stats"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]
    reputation = attrs.get("reputation", 0)

    if malicious >= 3:
        verdict = "Malicious"
    elif malicious > 0 or suspicious > 0:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    if malicious == 0:
        severity = "LOW"
    elif malicious <= 2:
        severity = "MEDIUM"
    elif malicious <= 5:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    mitre_techniques = []

    if verdict in ["Suspicious", "Malicious"]:
        mitre_techniques.append("T1204")  # User Execution

    url_lower = url.lower()
    if "login" in url_lower or "verify" in url_lower or "account" in url_lower:
        mitre_techniques.append("T1566")  # Phishing

    event = {
        "event_time": datetime.now(timezone.utc).isoformat(),
        "source": "VirusTotal",
        "indicator_type": "url",
        "indicator_value": url,
        "vt_malicious": malicious,
        "vt_suspicious": suspicious,
        "vt_harmless": harmless,
        "reputation_score": reputation,
        "final_verdict": verdict,
        "severity": severity,
        "mitre_techniques": mitre_techniques
    }

    return event


def main():
    config = load_config()
    api_key = config["virustotal"]["api_key"]

    while True:
        print("\nMini SIEM Menu")
        print("1. Analyze a new URL")
        print("2. Show all saved events")
        print("3. Show suspicious or malicious events")
        print("4. Show HIGH or CRITICAL severity events")
        print("5. Exit")

        choice = input("\nChoose an option: ").strip()

        if choice == "1":
            url = input("Enter a URL to analyze: ").strip()
            result = analyze_url(url, api_key)
            event = build_event(url, result)
            save_event(event)

            print("\nSIEM Event:\n")
            print(json.dumps(event, indent=4))
            print("\nEvent saved to events.jsonl")

        elif choice == "2":
            events = load_events()
            print_events(events)

        elif choice == "3":
            events = load_events()
            filtered = [
                event for event in events
                if event["final_verdict"] in ["Suspicious", "Malicious"]
            ]
            print_events(filtered)

        elif choice == "4":
            events = load_events()
            filtered = [
                event for event in events
                if event["severity"] in ["HIGH", "CRITICAL"]
            ]
            print_events(filtered)

        elif choice == "5":
            print("\nGoodbye.")
            break

        else:
            print("\nInvalid choice. Try again.")


if __name__ == "__main__":
    main()