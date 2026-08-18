"""Tests for the full test harness — end-to-end fixture processing."""
import pytest
import json
import os
import sys

from src.harness import run_fixtures, generate_junit_xml, generate_json_report


# Path to the public fixtures file
FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "public-fixtures.json")


class TestHarnessWithPublicFixtures:
    """Test the harness against the real public fixtures."""

    @pytest.fixture
    def fixtures_available(self):
        if not os.path.exists(FIXTURES_PATH):
            pytest.skip(f"Fixtures file not found at {FIXTURES_PATH}")
        return True

    def test_all_36_fixtures_processed(self, fixtures_available):
        results = run_fixtures(FIXTURES_PATH)
        assert len(results) == 36

    def test_12_alerts_detected(self, fixtures_available):
        results = run_fixtures(FIXTURES_PATH)
        alerted = [r for r in results if r.category == "alerted"]
        assert len(alerted) == 12, f"Expected 12 alerts, got {len(alerted)}: {[r.case_id for r in alerted]}"

    def test_24_benign_not_alerted(self, fixtures_available):
        results = run_fixtures(FIXTURES_PATH)
        benign_alerts = [r for r in results if r.expected == "no_alert" and r.category == "alerted"]
        assert len(benign_alerts) == 0, f"False positives: {[(r.case_id, r.details) for r in benign_alerts]}"

    def test_zero_mismatches(self, fixtures_available):
        results = run_fixtures(FIXTURES_PATH)
        mismatches = [r for r in results if not r.matched]
        assert len(mismatches) == 0, (
            f"{len(mismatches)} mismatches: "
            f"{[(r.case_id, r.expected, r.category) for r in mismatches]}"
        )

    def test_all_categories_represented(self, fixtures_available):
        """At least rule_miss and alerted categories should be present."""
        results = run_fixtures(FIXTURES_PATH)
        categories = {r.category for r in results}
        assert "alerted" in categories
        assert "rule_miss" in categories

    def test_junit_xml_generation(self, fixtures_available):
        results = run_fixtures(FIXTURES_PATH)
        xml = generate_junit_xml(results)
        assert "testsuite" in xml
        assert 'tests="36"' in xml
        assert 'failures="0"' in xml

    def test_json_report_generation(self, fixtures_available):
        results = run_fixtures(FIXTURES_PATH)
        json_str = generate_json_report(results)
        report = json.loads(json_str)
        assert report["summary"]["total_fixtures"] == 36
        assert report["summary"]["passed"] == 36
        assert report["summary"]["failed"] == 0
