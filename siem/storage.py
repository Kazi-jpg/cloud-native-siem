"""Append-only local event and alert storage."""

import json
from pathlib import Path


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
