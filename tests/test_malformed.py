"""Tests for malformed input and edge conditions."""
import pytest
from src.decoder import decode
from src.rule_engine import RuleEngine
from src.adapter import event_to_logline


class TestMalformedInput:
    """Test that the system handles malformed input gracefully."""

    def test_decoder_empty_string(self):
        assert decode("") is None

    def test_decoder_random_garbage(self):
        assert decode("asdlfkjhasdf987234random") is None

    def test_decoder_partial_prefix(self):
        assert decode("NETFORGE_TRAINING") is None

    def test_decoder_no_fields(self):
        assert decode("NETFORGE_TRAINING_PROCESS") is None

    def test_decoder_binary_data(self):
        assert decode("\x00\x01\x02\x03") is None

    def test_decoder_unicode_garbage(self):
        assert decode("NETFORGE_TRAINING_PROCESS host=héllo image=🎉 parent=p family=native") is not None
        # Should still decode, just with weird values

    def test_rule_engine_none_event(self):
        engine = RuleEngine()
        with pytest.raises(AttributeError):
            engine.process_event(None)

    def test_rule_engine_empty_event(self):
        engine = RuleEngine()
        alerts = engine.process_event({})
        assert len(alerts) == 0

    def test_rule_engine_missing_fields(self):
        engine = RuleEngine()
        alerts = engine.process_event({"host": "h"})
        assert len(alerts) == 0

    def test_adapter_empty_dict(self):
        line = event_to_logline({})
        assert "NETFORGE_TRAINING_PROCESS" in line

    def test_adapter_missing_image(self):
        line = event_to_logline({"host": "h", "parent": "p.exe", "command_family": "native"})
        assert "image=unknown" in line


class TestEdgeConditions:
    """Test edge conditions that hidden fixtures might use."""

    def test_different_process_names_same_class(self):
        """pwsh.exe should be in the same class as powershell.exe."""
        event = {
            "host": "h", "user": "u", "image": "pwsh.exe",
            "parent": "winword.exe", "command_family": "encoded_or_obfuscated",
        }
        engine = RuleEngine()
        alerts = engine.process_event(event)
        assert len(alerts) > 0, "pwsh.exe should be detected like powershell.exe"

    def test_excel_as_office_parent(self):
        """excel.exe should be treated as an Office parent."""
        event = {
            "host": "h", "user": "u", "image": "powershell.exe",
            "parent": "excel.exe", "command_family": "encoded_or_obfuscated",
            "technique_id": "T1059.001",
        }
        engine = RuleEngine()
        alerts = engine.process_event(event)
        assert len(alerts) > 0, "Excel as parent should trigger alert"

    def test_unknown_technique_id_no_alert(self):
        """Unknown technique IDs should not trigger any rule."""
        event = {
            "host": "h", "user": "u", "image": "powershell.exe",
            "parent": "winword.exe", "command_family": "encoded_or_obfuscated",
            "technique_id": "T9999.999",
        }
        engine = RuleEngine()
        alerts = engine.process_event(event)
        assert len(alerts) == 0, "Unknown technique_id should not alert"

    def test_mixed_case_process_names(self):
        """Mixed case process names should be handled."""
        event = {
            "host": "h", "user": "u", "image": "PowerShell.Exe",
            "parent": "WinWord.Exe", "command_family": "encoded_or_obfuscated",
        }
        engine = RuleEngine()
        alerts = engine.process_event(event)
        assert len(alerts) > 0, "Mixed case process names should be detected"
