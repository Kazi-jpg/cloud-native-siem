import json
from pathlib import Path
import unittest

from main import build_event, detect_mitre_threat


class EventTests(unittest.TestCase):
    def report(self, malicious=0, suspicious=0, tags=None):
        return {"data": {"attributes": {"last_analysis_stats": {
            "malicious": malicious, "suspicious": suspicious, "harmless": 3
        }, "tags": tags or []}}}

    def test_severity_boundaries(self):
        for malicious, suspicious, expected in [(0, 0, "LOW"), (0, 1, "MEDIUM"), (1, 0, "HIGH"), (5, 0, "HIGH"), (6, 0, "CRITICAL")]:
            with self.subTest(malicious=malicious, suspicious=suspicious):
                event = build_event("https://example.com", self.report(malicious, suspicious), indicator_type="url")
                self.assertEqual(event["severity"], expected)

    def test_file_event_matches_bigquery_schema(self):
        event = build_event("a" * 64, self.report(), indicator_type="file_hash", file_name="sample.txt")
        schema = json.loads(Path("schema.json").read_text())
        self.assertEqual(set(event), {field["name"] for field in schema})
        self.assertIsNone(event["domain"])
        self.assertEqual(event["file_name"], "sample.txt")

    def test_only_explicit_techniques_generate_alert(self):
        event = build_event("https://example.com", self.report(tags=["phishing", "T1566.002", 42]))
        self.assertEqual(event["mitre_techniques"], ["T1566.002"])
        alerts = detect_mitre_threat(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_event_id"], event["event_id"])
        self.assertEqual(detect_mitre_threat(build_event("https://example.com", self.report(tags=["phishing"]))), [])


if __name__ == "__main__":
    unittest.main()
