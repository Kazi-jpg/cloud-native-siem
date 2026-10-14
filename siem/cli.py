"""Interactive command-line interface."""

import json
import os

import yaml

from .events import build_event, detect_mitre_threat
from .publisher import publish_event
from .storage import load_events, save_alerts, save_event
from .virustotal import analyze_file, analyze_url


def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)


def process_event(event):
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


def print_events(events):
    if not events:
        print("\nNo events found.\n")
        return

    print()
    for i, event in enumerate(events, start=1):
        print(f"Event {i}")
        print(json.dumps(event, indent=4))
        print()


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
                process_event(event)
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
                process_event(event)
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
