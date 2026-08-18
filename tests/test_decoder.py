"""Tests for the decoder module."""
import pytest
from src.decoder import decode


class TestDecoder:
    """Positive tests: valid lines decode correctly."""

    def test_decode_basic_replay_event(self):
        line = "NETFORGE_TRAINING_PROCESS host=NS-WIN-101 user=NORTHSTAR\\analyst1 image=powershell.exe parent=winword.exe family=encoded_or_obfuscated"
        result = decode(line)
        assert result is not None
        assert result["host"] == "NS-WIN-101"
        assert result["image"] == "powershell.exe"
        assert result["parent"] == "winword.exe"
        assert result["command_family"] == "encoded_or_obfuscated"
        assert result["technique_id"] is None

    def test_decode_fixture_event_with_technique_id(self):
        line = "NETFORGE_TRAINING_PROCESS host=NS-WIN-101 user=test image=cmd.exe parent=config-agent.exe family=encoded_or_obfuscated technique_id=T1218.011"
        result = decode(line)
        assert result is not None
        assert result["technique_id"] == "T1218.011"
        assert result["image"] == "cmd.exe"
        assert result["parent"] == "config-agent.exe"

    def test_decode_uppercase_process_names(self):
        line = "NETFORGE_TRAINING_PROCESS host=NS-WIN-101 user=analyst image=POWERSHELL.EXE parent=WINWORD.EXE family=encoded_or_obfuscated"
        result = decode(line)
        assert result is not None
        assert result["image"] == "POWERSHELL.EXE"
        assert result["parent"] == "WINWORD.EXE"

    def test_decode_preserves_raw_line(self):
        line = "NETFORGE_TRAINING_PROCESS host=h1 user=u1 image=i.exe parent=p.exe family=native"
        result = decode(line)
        assert result is not None
        assert result["_raw"] == line

    def test_decode_all_command_families(self):
        for family in ["native", "signed_update", "encoded_or_obfuscated",
                       "download", "registry_run_key", "credential_access"]:
            line = f"NETFORGE_TRAINING_PROCESS host=h user=u image=i.exe parent=p.exe family={family}"
            result = decode(line)
            assert result is not None
            assert result["command_family"] == family


class TestDecoderFailures:
    """Negative tests: invalid lines return None."""

    def test_empty_line(self):
        assert decode("") is None

    def test_whitespace_only(self):
        assert decode("   ") is None

    def test_wrong_prefix(self):
        assert decode("SOME_OTHER_FORMAT host=h image=i.exe parent=p.exe family=native") is None

    def test_missing_required_field(self):
        # Missing family
        line = "NETFORGE_TRAINING_PROCESS host=h user=u image=i.exe parent=p.exe"
        assert decode(line) is None

    def test_missing_host(self):
        line = "NETFORGE_TRAINING_PROCESS user=u image=i.exe parent=p.exe family=native"
        assert decode(line) is None

    def test_none_input(self):
        assert decode(None) is None

    def test_non_string_input(self):
        assert decode(12345) is None


class TestDecoderEdgeCases:
    """Edge case tests."""

    def test_extra_fields_ignored(self):
        line = "NETFORGE_TRAINING_PROCESS host=h user=u image=i.exe parent=p.exe family=native extra_field=value"
        result = decode(line)
        assert result is not None
        assert result["host"] == "h"

    def test_backslash_in_user(self):
        line = "NETFORGE_TRAINING_PROCESS host=h user=DOMAIN\\user image=i.exe parent=p.exe family=native"
        result = decode(line)
        assert result is not None
        assert "DOMAIN" in result["user"]
