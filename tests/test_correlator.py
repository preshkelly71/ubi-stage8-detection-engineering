"""Tests for the correlator module."""
import pytest
from datetime import datetime, timedelta
from src.correlator import Correlator, parse_timestamp


class TestCorrelator:

    def test_frequency_rule_fires_on_3_events(self):
        """3 non-native events from same host should trigger the frequency rule."""
        corr = Correlator()
        base_time = datetime(2026, 7, 8, 0, 0, 0)

        events = [
            {"host": "NS-WIN-101", "image": "POWERSHELL.EXE", "parent": "winword.exe",
             "command_family": "encoded_or_obfuscated", "timestamp": base_time.isoformat()},
            {"host": "NS-WIN-101", "image": "CERTUTIL.EXE", "parent": "powershell.exe",
             "command_family": "download", "timestamp": (base_time + timedelta(hours=16)).isoformat()},
            {"host": "NS-WIN-101", "image": "REG.EXE", "parent": "cmd.exe",
             "command_family": "registry_run_key", "timestamp": (base_time + timedelta(hours=21)).isoformat()},
        ]

        for ev in events:
            corr.process_event(ev)

        # Should have at least one correlation alert (multiple suspicious events rule)
        assert len(corr.alerts) > 0, "Expected correlation alert for 3 non-native events on same host"

    def test_benign_events_no_correlation(self):
        """Native events should not trigger correlation."""
        corr = Correlator()
        base_time = datetime(2026, 7, 8, 0, 0, 0)

        for i in range(5):
            ev = {
                "host": "NS-WIN-999", "image": "teams.exe", "parent": "explorer.exe",
                "command_family": "native", "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            }
            corr.process_event(ev)

        assert len(corr.alerts) == 0, "Native events should not trigger correlation"

    def test_sequence_office_to_download(self):
        """Office→Shell→Download sequence should trigger within 24h."""
        corr = Correlator()
        base_time = datetime(2026, 7, 8, 5, 0, 0)

        events = [
            {"host": "h1", "image": "powershell.exe", "parent": "winword.exe",
             "command_family": "encoded_or_obfuscated", "timestamp": base_time.isoformat()},
            {"host": "h1", "image": "certutil.exe", "parent": "powershell.exe",
             "command_family": "download", "timestamp": (base_time + timedelta(hours=16)).isoformat()},
        ]

        for ev in events:
            corr.process_event(ev)

        # Should have at least one correlation alert
        assert len(corr.alerts) > 0, "Expected sequence correlation alert"

    def test_parse_timestamp(self):
        assert parse_timestamp("2026-07-08T05:20:30Z") is not None
        assert parse_timestamp(None) is None
        assert parse_timestamp("invalid") is None

    def test_different_hosts_no_correlation(self):
        """Events from different hosts should not correlate."""
        corr = Correlator()
        base_time = datetime(2026, 7, 8, 0, 0, 0)

        for i in range(3):
            ev = {
                "host": f"host_{i}", "image": "powershell.exe", "parent": "winword.exe",
                "command_family": "encoded_or_obfuscated",
                "timestamp": (base_time + timedelta(hours=i)).isoformat(),
            }
            corr.process_event(ev)

        # Each host has only 1 event — no correlation
        assert len(corr.alerts) == 0, "Events from different hosts should not correlate"
