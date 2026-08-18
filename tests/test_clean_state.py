"""Tests for clean-state: verify no residual state between runs."""
import pytest
from src.rule_engine import RuleEngine
from src.correlator import Correlator
from src.harness import run_fixtures
import os

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "public-fixtures.json")


class TestCleanState:
    """Verify that the system produces deterministic results from a clean start."""

    def test_rule_engine_reset(self):
        engine = RuleEngine()
        event = {
            "host": "h", "user": "u", "image": "powershell.exe",
            "parent": "winword.exe", "command_family": "encoded_or_obfuscated",
        }
        engine.process_event(event)
        assert len(engine.alerts) > 0
        engine.reset()
        assert len(engine.alerts) == 0

    def test_correlator_reset(self):
        corr = Correlator()
        corr.process_event({
            "host": "h", "image": "powershell.exe", "parent": "winword.exe",
            "command_family": "encoded_or_obfuscated", "timestamp": "2026-07-08T00:00:00Z",
        })
        assert len(corr.history) > 0
        corr.reset()
        assert len(corr.history) == 0

    def test_deterministic_fixture_results(self):
        """Running fixtures twice should produce identical results."""
        if not os.path.exists(FIXTURES_PATH):
            pytest.skip("Fixtures file not found")

        results1 = run_fixtures(FIXTURES_PATH)
        results2 = run_fixtures(FIXTURES_PATH)

        assert len(results1) == len(results2)
        for r1, r2 in zip(results1, results2):
            assert r1.case_id == r2.case_id
            assert r1.expected == r2.expected
            assert r1.category == r2.category
            assert r1.matched == r2.matched

    def test_no_state_leakage_between_fixtures(self):
        """Processing fixtures sequentially should not leak state."""
        if not os.path.exists(FIXTURES_PATH):
            pytest.skip("Fixtures file not found")

        results = run_fixtures(FIXTURES_PATH)
        # Each fixture should produce results independently
        # The 12 alert fixtures should all alert, regardless of order
        alerts = [r for r in results if r.category == "alerted"]
        assert len(alerts) == 12

    def test_fresh_engine_has_no_alerts(self):
        engine = RuleEngine()
        assert len(engine.alerts) == 0
        assert len(engine.base_rules) == 12
