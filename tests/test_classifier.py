"""Tests for the classifier module."""
import pytest
from src.classifier import (
    classify_fixture, FixtureResult,
    NO_TELEMETRY, DECODER_FAILURE, RULE_MISS, SUPPRESSED, ALERTED,
)
from src.rule_engine import Alert


class TestClassifier:
    """Test all 5 classification categories."""

    def test_no_telemetry(self):
        result = classify_fixture("TEST-01", "alert", [], [], [])
        assert result.category == NO_TELEMETRY
        assert not result.matched  # Expected alert, got no telemetry

    def test_no_telemetry_for_benign(self):
        result = classify_fixture("TEST-02", "no_alert", [], [], [])
        assert result.category == NO_TELEMETRY
        assert result.matched  # Expected no_alert, got no telemetry = correct

    def test_decoder_failure(self):
        events = ["bad_line_1", "bad_line_2"]
        decoded = [None, None]
        result = classify_fixture("TEST-03", "alert", events, decoded, [])
        assert result.category == DECODER_FAILURE
        assert not result.matched  # Expected alert, got decoder failure

    def test_decoder_failure_for_benign(self):
        events = ["bad_line"]
        decoded = [None]
        result = classify_fixture("TEST-04", "no_alert", events, decoded, [])
        assert result.category == DECODER_FAILURE
        assert result.matched  # Expected no_alert, can't decode = correct

    def test_rule_miss(self):
        events = ["NETFORGE_TRAINING_PROCESS host=h user=u image=i.exe parent=p.exe family=native"]
        decoded = [{"host": "h", "image": "i.exe", "parent": "p.exe", "command_family": "native"}]
        result = classify_fixture("TEST-05", "alert", events, decoded, [])
        assert result.category == RULE_MISS
        assert not result.matched  # Expected alert, no rule matched

    def test_rule_miss_for_benign(self):
        events = ["NETFORGE_TRAINING_PROCESS host=h user=u image=i.exe parent=p.exe family=native"]
        decoded = [{"host": "h", "image": "i.exe", "parent": "p.exe", "command_family": "native"}]
        result = classify_fixture("TEST-06", "no_alert", events, decoded, [])
        assert result.category == RULE_MISS
        assert result.matched  # Expected no_alert, no rule = correct

    def test_alerted(self):
        events = ["NETFORGE_TRAINING_PROCESS host=h user=u image=powershell.exe parent=winword.exe family=encoded_or_obfuscated"]
        decoded = [{"host": "h", "image": "powershell.exe", "parent": "winword.exe", "command_family": "encoded_or_obfuscated"}]
        alert = Alert(110200, 10, "T1059.001", "PowerShell from Office", decoded[0])
        result = classify_fixture("TEST-07", "alert", events, decoded, [alert])
        assert result.category == ALERTED
        assert result.matched  # Expected alert, got alerted = correct

    def test_alerted_for_benign_mismatch(self):
        events = ["NETFORGE_TRAINING_PROCESS host=h user=u image=powershell.exe parent=winword.exe family=encoded_or_obfuscated"]
        decoded = [{"host": "h", "image": "powershell.exe", "parent": "winword.exe", "command_family": "encoded_or_obfuscated"}]
        alert = Alert(110200, 10, "T1059.001", "False positive", decoded[0])
        result = classify_fixture("TEST-08", "no_alert", events, decoded, [alert])
        assert result.category == ALERTED
        assert not result.matched  # Expected no_alert, got alerted = false positive


class TestFixtureResultProperties:
    def test_verdict_pass(self):
        result = FixtureResult("TEST", "alert", ALERTED, [], 2, 2)
        assert result.verdict == "PASS"

    def test_verdict_mismatch(self):
        result = FixtureResult("TEST", "alert", RULE_MISS, [], 2, 2)
        assert result.verdict == "MISMATCH"

    def test_to_dict(self):
        result = FixtureResult("TEST", "alert", ALERTED, [], 2, 2, "test details")
        d = result.to_dict()
        assert d["case_id"] == "TEST"
        assert d["expected"] == "alert"
        assert d["category"] == "alerted"
        assert d["verdict"] == "PASS"
