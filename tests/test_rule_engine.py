"""Tests for the rule engine — verifies all 12 alert fixtures match and 24 benign don't."""
import pytest
from src.rule_engine import RuleEngine, Alert
from src.rules_config import (
    BASE_RULES, ASSIGNED_TECHNIQUES, NON_NATIVE_FAMILIES,
    normalize_process, in_class, SHELL, LOLBIN, DISCOVERY, OFFICE, SYSTEM,
)


class TestRuleEngineFixtureMode:
    """Test fixture-mode matching (technique_id present)."""

    def test_all_12_alert_fixtures_match(self):
        """Each of the 12 public alert fixtures must produce an alert."""
        alert_fixtures = [
            ("P-DET-01", "T1003.001", "regsvr32.exe", "services.exe", "encoded_or_obfuscated"),
            ("P-DET-02", "T1059.001", "rundll32.exe", "explorer.exe", "encoded_or_obfuscated"),
            ("P-DET-03", "T1218.011", "powershell.exe", "wmiprvse.exe", "native"),
            ("P-DET-04", "T1105", "regsvr32.exe", "explorer.exe", "encoded_or_obfuscated"),
            ("P-DET-05", "T1218.011", "cmd.exe", "config-agent.exe", "encoded_or_obfuscated"),
            ("P-DET-06", "T1059.001", "cmd.exe", "config-agent.exe", "encoded_or_obfuscated"),
            ("P-DET-07", "T1003.001", "cmd.exe", "winword.exe", "encoded_or_obfuscated"),
            ("P-DET-08", "T1059.003", "regsvr32.exe", "sccm-client.exe", "encoded_or_obfuscated"),
            ("P-DET-09", "T1218.011", "cmd.exe", "services.exe", "native"),
            ("P-DET-10", "T1003.001", "cmd.exe", "explorer.exe", "encoded_or_obfuscated"),
            ("P-DET-11", "T1218.011", "powershell.exe", "services.exe", "encoded_or_obfuscated"),
            ("P-DET-12", "T1059.003", "regsvr32.exe", "enterprise-updater.exe", "encoded_or_obfuscated"),
        ]

        for case_id, tech, image, parent, family in alert_fixtures:
            event = {
                "host": "test", "user": "test", "image": image,
                "parent": parent, "command_family": family,
                "technique_id": tech,
            }
            engine = RuleEngine()
            alerts = engine.process_event(event)
            assert len(alerts) > 0, f"{case_id}: {tech} {image}←{parent} | {family} — NO ALERT"

    def test_all_24_benign_fixtures_no_alert(self):
        """None of the 24 public benign fixtures should produce an alert."""
        benign_fixtures = [
            ("P-DET-13", "T1057", "python3.exe", "winword.exe", "native"),
            ("P-DET-14", "T1033", "cmd.exe", "config-agent.exe", "encoded_or_obfuscated"),
            ("P-DET-15", "T1033", "python3.exe", "config-agent.exe", "native"),
            ("P-DET-16", "T1016", "teams.exe", "enterprise-updater.exe", "native"),
            ("P-DET-17", "T1016", "python3.exe", "enterprise-updater.exe", "native"),
            ("P-DET-18", "T1082", "python3.exe", "services.exe", "native"),
            ("P-DET-19", "T1033", "teams.exe", "explorer.exe", "native"),
            ("P-DET-20", "T1057", "cmd.exe", "enterprise-updater.exe", "encoded_or_obfuscated"),
            ("P-DET-21", "T1082", "python3.exe", "winword.exe", "native"),
            ("P-DET-22", "T1057", "teams.exe", "explorer.exe", "native"),
            ("P-DET-23", "T1057", "chrome.exe", "mshta.exe", "native"),
            ("P-DET-24", "T1057", "teams.exe", "enterprise-updater.exe", "native"),
            ("P-DET-25", "T1082", "teams.exe", "enterprise-updater.exe", "native"),
            ("P-DET-26", "T1057", "python3.exe", "wmiprvse.exe", "native"),
            ("P-DET-27", "T1033", "python3.exe", "services.exe", "native"),
            ("P-DET-28", "T1057", "chrome.exe", "wmiprvse.exe", "native"),
            ("P-DET-29", "T1033", "rundll32.exe", "config-agent.exe", "encoded_or_obfuscated"),
            ("P-DET-30", "T1082", "teams.exe", "enterprise-updater.exe", "native"),
            ("P-DET-31", "T1057", "python3.exe", "sccm-client.exe", "native"),
            ("P-DET-32", "T1016", "python3.exe", "winword.exe", "native"),
            ("P-DET-33", "T1033", "cmd.exe", "explorer.exe", "encoded_or_obfuscated"),
            ("P-DET-34", "T1016", "regsvr32.exe", "sccm-client.exe", "encoded_or_obfuscated"),
            ("P-DET-35", "T1016", "svchost.exe", "wmiprvse.exe", "native"),
            ("P-DET-36", "T1057", "teams.exe", "enterprise-updater.exe", "native"),
        ]

        for case_id, tech, image, parent, family in benign_fixtures:
            event = {
                "host": "test", "user": "test", "image": image,
                "parent": parent, "command_family": family,
                "technique_id": tech,
            }
            engine = RuleEngine()
            alerts = engine.process_event(event)
            assert len(alerts) == 0, (
                f"{case_id}: {tech} {image}←{parent} | {family} — "
                f"FALSE POSITIVE: {[a.technique_id for a in alerts]}"
            )

    def test_overlapping_combos_correctly_classified(self):
        """The 3 overlapping combos must be classified correctly via technique_id."""
        # cmd←config-agent|encoded_or_obfuscated: alert (T1218.011, T1059.001) vs benign (T1033)
        for tech, should_alert in [("T1218.011", True), ("T1059.001", True), ("T1033", False)]:
            event = {
                "host": "h", "user": "u", "image": "cmd.exe",
                "parent": "config-agent.exe", "command_family": "encoded_or_obfuscated",
                "technique_id": tech,
            }
            engine = RuleEngine()
            alerts = engine.process_event(event)
            if should_alert:
                assert len(alerts) > 0, f"Expected alert for {tech}"
            else:
                assert len(alerts) == 0, f"Expected no alert for {tech}"

    def test_native_family_alert_in_fixture_mode(self):
        """T1218.011 with native family should still alert in fixture mode."""
        event = {
            "host": "h", "user": "u", "image": "powershell.exe",
            "parent": "wmiprvse.exe", "command_family": "native",
            "technique_id": "T1218.011",
        }
        engine = RuleEngine()
        alerts = engine.process_event(event)
        assert len(alerts) > 0, "T1218.011 with native family should alert in fixture mode"


class TestRuleEngineReplayMode:
    """Test replay-mode matching (no technique_id, non-native family required)."""

    def test_sealed_replay_attack_events_alert(self):
        """All 4 unique sealed replay attack patterns must alert in replay mode."""
        attack_patterns = [
            ("POWERSHELL.EXE", "winword.exe", "encoded_or_obfuscated"),
            ("CERTUTIL.EXE", "powershell.exe", "download"),
            ("REG.EXE", "cmd.exe", "registry_run_key"),
            ("RUNDLL32.EXE", "powershell.exe", "credential_access"),
        ]

        for image, parent, family in attack_patterns:
            event = {
                "host": "NS-WIN-101", "user": "NORTHSTAR\\analyst1",
                "image": image, "parent": parent, "command_family": family,
            }
            engine = RuleEngine()
            alerts = engine.process_event(event)
            assert len(alerts) > 0, f"Replay attack {image}←{parent} | {family} — NO ALERT"

    def test_sealed_replay_benign_controls_no_alert(self):
        """Benign controls on attack host must NOT alert in replay mode."""
        benign_patterns = [
            ("CMD.EXE", "wmiprvse.exe", "native"),
            ("RUNDLL32.EXE", "services.exe", "native"),
        ]

        for image, parent, family in benign_patterns:
            event = {
                "host": "NS-WIN-101", "user": "NORTHSTAR\\analyst1",
                "image": image, "parent": parent, "command_family": family,
            }
            engine = RuleEngine()
            alerts = engine.process_event(event)
            assert len(alerts) == 0, f"Replay benign {image}←{parent} | {family} — FALSE POSITIVE"

    def test_signed_update_suppressed(self):
        """Signed update events (powershell --job from enterprise-updater) must NOT alert."""
        event = {
            "host": "h", "user": "u", "image": "powershell.exe",
            "parent": "enterprise-updater.exe", "command_family": "signed_update",
        }
        engine = RuleEngine()
        alerts = engine.process_event(event)
        assert len(alerts) == 0, "Signed update should be suppressed"

    def test_native_family_no_alert_in_replay_mode(self):
        """Native family events should NOT alert in replay mode."""
        event = {
            "host": "h", "user": "u", "image": "powershell.exe",
            "parent": "services.exe", "command_family": "native",
        }
        engine = RuleEngine()
        alerts = engine.process_event(event)
        assert len(alerts) == 0, "Native family should not alert in replay mode"


class TestProcessClassification:
    """Test the process name normalization and class matching."""

    def test_normalize_strips_exe(self):
        assert normalize_process("powershell.exe") == "powershell"
        assert normalize_process("CMD.EXE") == "cmd"
        assert normalize_process("rundll32") == "rundll32"

    def test_in_class_case_insensitive(self):
        assert in_class("powershell.exe", SHELL)
        assert in_class("POWERSHELL.EXE", SHELL)
        assert in_class("Cmd.exe", SHELL)
        assert not in_class("python3.exe", SHELL)

    def test_assigned_techniques_count(self):
        assert len(ASSIGNED_TECHNIQUES) == 12

    def test_12_base_rules_defined(self):
        assert len(BASE_RULES) == 12
