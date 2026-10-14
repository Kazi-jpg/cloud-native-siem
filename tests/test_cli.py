"""Check the console workflows without uploading files or contacting cloud APIs."""

import unittest
from unittest.mock import patch

from siem import cli


class ConsoleTests(unittest.TestCase):
    @patch("siem.cli.process_event")
    @patch("siem.cli.analyze_url", return_value={})
    @patch("siem.cli.load_config", return_value={"virustotal": {"api_key": "test"}})
    def test_url_menu_routes_normalized_event(self, config, analyze, process):
        with patch("builtins.input", side_effect=["1", "https://example.com", "6"]), patch("builtins.print"):
            cli.main()
        analyze.assert_called_once_with("https://example.com", "test")
        self.assertEqual(process.call_args.args[0]["indicator_type"], "url")

    @patch("siem.cli.process_event")
    @patch("siem.cli.analyze_file", return_value=({}, "a" * 64))
    @patch("siem.cli.load_config", return_value={"virustotal": {"api_key": "test"}})
    def test_file_menu_routes_hash_and_filename(self, config, analyze, process):
        with patch("builtins.input", side_effect=["2", '"sample.txt"', "6"]), patch("builtins.print"):
            cli.main()
        analyze.assert_called_once_with("sample.txt", "test")
        event = process.call_args.args[0]
        self.assertEqual(event["indicator_type"], "file_hash")
        self.assertEqual(event["indicator_value"], "a" * 64)
        self.assertEqual(event["file_name"], "sample.txt")

    @patch("siem.cli.publish_event", side_effect=RuntimeError("offline"))
    @patch("siem.cli.save_alerts")
    @patch("siem.cli.save_event")
    def test_publish_failure_preserves_local_save(self, save_event, save_alerts, publish):
        event = {"mitre_techniques": []}
        with patch("builtins.print"):
            cli.process_event(event)
        save_event.assert_called_once_with(event)
        save_alerts.assert_called_once_with([])
        publish.assert_called_once_with(event)
