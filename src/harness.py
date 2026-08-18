"""
Test harness: runs the full detection pipeline against fixtures and/or sealed replay.

Usage:
  python -m src.harness --fixtures fixtures/public-fixtures.json --report test-results.xml
  python -m src.harness --replay evidence/raw/windows-replay.jsonl --report replay-results.xml
  python -m src.harness --fixtures fixtures/public-fixtures.json --replay evidence/raw/windows-replay.jsonl

Exits non-zero on any verdict mismatch.
"""

import argparse
import json
import sys
import os
import time
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from xml.etree import ElementTree as ET
from xml.dom import minidom

from .decoder import decode
from .adapter import convert_replay, convert_fixtures, event_to_logline
from .rule_engine import RuleEngine
from .correlator import Correlator
from .classifier import classify_fixture, classify_replay_event, FixtureResult


def run_fixtures(fixture_path: str) -> List[FixtureResult]:
    """Run all public fixtures through the pipeline and return results."""
    fixtures = convert_fixtures(fixture_path)
    results = []

    for case_id, expected, log_lines in fixtures:
        # Decode all events in the fixture
        raw_events = []
        decoded_events = []
        for line in log_lines:
            raw_events.append(line)
            decoded = decode(line)
            decoded_events.append(decoded)

        # Run rule engine on decoded events
        engine = RuleEngine()
        all_alerts = []
        for decoded in decoded_events:
            if decoded:
                alerts = engine.process_event(decoded)
                all_alerts.extend(alerts)

        # Classify
        result = classify_fixture(case_id, expected, raw_events, decoded_events, all_alerts)
        results.append(result)

    return results


def run_replay(replay_path: str) -> Dict[str, Any]:
    """Run the sealed replay through the pipeline and return summary."""
    engine = RuleEngine()
    correlator = Correlator()

    total_events = 0
    decoded_events = 0
    alert_events = 0
    alert_details = []

    for log_line in convert_replay(replay_path):
        total_events += 1
        decoded = decode(log_line)
        if decoded is None:
            continue
        decoded_events += 1

        # Run rule engine
        alerts = engine.process_event(decoded)
        if alerts:
            alert_events += 1
            for a in alerts:
                alert_details.append(a.to_dict())

        # Run correlator
        correlator.process_event(decoded)

    correlation_alerts = [a.to_dict() for a in correlator.alerts]

    return {
        "total_events": total_events,
        "decoded_events": decoded_events,
        "alert_events": alert_events,
        "alert_details": alert_details,
        "correlation_alerts": correlation_alerts,
    }


def generate_junit_xml(results: List[FixtureResult], replay_summary: Optional[Dict] = None) -> str:
    """Generate JUnit XML report."""
    testsuite = ET.Element("testsuite")
    testsuite.set("name", "ubi-stage8-detection-engineering")
    testsuite.set("tests", str(len(results)))
    failures = sum(1 for r in results if not r.matched)
    testsuite.set("failures", str(failures))
    testsuite.set("errors", "0")
    testsuite.set("time", "0")

    for result in results:
        testcase = ET.SubElement(testsuite, "testcase")
        testcase.set("name", result.case_id)
        testcase.set("classname", "fixtures")
        if not result.matched:
            failure = ET.SubElement(testcase, "failure")
            failure.set("message", f"Expected {result.expected}, got {result.category}")
            failure.text = f"Case: {result.case_id}\nExpected: {result.expected}\n"
            f"Category: {result.category}\nDetails: {result.details}"

    if replay_summary:
        replay_case = ET.SubElement(testsuite, "testcase")
        replay_case.set("name", "sealed-replay")
        replay_case.set("classname", "replay")
        if replay_summary["alert_events"] == 0:
            failure = ET.SubElement(replay_case, "failure")
            failure.set("message", "No alerts from sealed replay")
            failure.text = f"Total: {replay_summary['total_events']}, "
            f"Alerted: {replay_summary['alert_events']}"
        else:
            replay_case.set("time", "0")
            sysout = ET.SubElement(replay_case, "system-out")
            sysout.text = (
                f"Events: {replay_summary['total_events']}, "
                f"Alerted: {replay_summary['alert_events']}, "
                f"Correlation alerts: {len(replay_summary['correlation_alerts'])}"
            )

    return minidom.parseString(ET.tostring(testsuite, encoding="unicode")).toprettyxml(indent="  ")


def generate_json_report(results: List[FixtureResult], replay_summary: Optional[Dict] = None) -> str:
    """Generate JSON report."""
    report = {
        "summary": {
            "total_fixtures": len(results),
            "passed": sum(1 for r in results if r.matched),
            "failed": sum(1 for r in results if not r.matched),
            "categories": {},
        },
        "fixtures": [r.to_dict() for r in results],
    }

    for cat in ["no_telemetry", "decoder_failure", "rule_miss", "suppressed", "alerted"]:
        report["summary"]["categories"][cat] = sum(1 for r in results if r.category == cat)

    if replay_summary:
        report["replay"] = replay_summary

    return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(description="UBI Stage 8 Test Harness")
    parser.add_argument("--fixtures", help="Path to public-fixtures.json")
    parser.add_argument("--replay", help="Path to windows-replay.jsonl")
    parser.add_argument("--report", default="test-results.xml", help="Output report file")
    parser.add_argument("--json-report", default=None, help="Optional JSON report file")
    args = parser.parse_args()

    results = []
    replay_summary = None

    if args.fixtures:
        print(f"Running fixtures from {args.fixtures}...")
        t0 = time.time()
        results = run_fixtures(args.fixtures)
        elapsed = time.time() - t0
        passed = sum(1 for r in results if r.matched)
        failed = sum(1 for r in results if not r.matched)
        print(f"  {len(results)} fixtures in {elapsed:.2f}s — {passed} passed, {failed} failed")

        if failed:
            print("\n  Mismatches:")
            for r in results:
                if not r.matched:
                    print(f"    {r.case_id}: expected={r.expected}, got={r.category} — {r.details}")

    if args.replay:
        if not os.path.exists(args.replay):
            print(f"  Replay file not found: {args.replay}")
            print("  (Place windows-replay.jsonl in evidence/raw/ to enable replay testing)")
        else:
            print(f"Running replay from {args.replay}...")
            t0 = time.time()
            replay_summary = run_replay(args.replay)
            elapsed = time.time() - t0
            print(f"  {replay_summary['total_events']} events in {elapsed:.2f}s — "
                  f"{replay_summary['alert_events']} alerted, "
                  f"{len(replay_summary['correlation_alerts'])} correlation alerts")
            if replay_summary["alert_details"]:
                print("\n  Alert details:")
                for a in replay_summary["alert_details"][:10]:
                    print(f"    Rule {a['rule_id']} ({a['technique_id']}): "
                          f"{a['image']}←{a['parent']} family={a['command_family']}")

    # Generate reports
    if results or replay_summary:
        xml_report = generate_junit_xml(results, replay_summary)
        with open(args.report, "w") as f:
            f.write(xml_report)
        print(f"\nXML report written to {args.report}")

        if args.json_report:
            json_report = generate_json_report(results, replay_summary)
            with open(args.json_report, "w") as f:
                f.write(json_report)
            print(f"JSON report written to {args.json_report}")

    # Exit non-zero on any mismatch
    failed = sum(1 for r in results if not r.matched)
    if failed > 0:
        print(f"\n{failed} verdict mismatch(es) — exiting non-zero")
        sys.exit(1)

    print("\nAll verdicts matched — PASS")


if __name__ == "__main__":
    main()
