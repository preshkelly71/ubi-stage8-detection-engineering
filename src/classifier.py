"""
Classifier: classifies fixture results into 5 categories.

Categories:
  - no_telemetry: No events were received for the fixture
  - decoder_failure: Events present but could not be decoded
  - rule_miss: Events decoded but no rule matched (expected alert, got nothing)
  - suppressed: Rule matched but was suppressed by an exclusion
  - alerted: Rule matched and alert was produced

The classifier compares the actual outcome against the expected verdict.
"""

from typing import Dict, Any, List, Optional, Tuple
from .rule_engine import Alert


# Classification constants
NO_TELEMETRY = "no_telemetry"
DECODER_FAILURE = "decoder_failure"
RULE_MISS = "rule_miss"
SUPPRESSED = "suppressed"
ALERTED = "alerted"

ALL_CATEGORIES = [NO_TELEMETRY, DECODER_FAILURE, RULE_MISS, SUPPRESSED, ALERTED]


class FixtureResult:
    """Result of running a single fixture through the pipeline."""

    def __init__(self, case_id: str, expected: str, category: str,
                 alerts: List[Alert], events_count: int, decoded_count: int,
                 details: str = ""):
        self.case_id = case_id
        self.expected = expected  # "alert" or "no_alert"
        self.category = category  # One of ALL_CATEGORIES
        self.alerts = alerts
        self.events_count = events_count
        self.decoded_count = decoded_count
        self.details = details

    @property
    def matched(self) -> bool:
        """True if the classification matches the expected verdict."""
        if self.expected == "alert":
            return self.category == ALERTED
        else:  # no_alert
            return self.category != ALERTED

    @property
    def verdict(self) -> str:
        """Human-readable verdict: PASS or MISMATCH."""
        return "PASS" if self.matched else "MISMATCH"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "expected": self.expected,
            "category": self.category,
            "verdict": self.verdict,
            "events_count": self.events_count,
            "decoded_count": self.decoded_count,
            "alert_count": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts],
            "details": self.details,
        }


def classify_fixture(
    case_id: str,
    expected: str,
    events: List[Dict[str, Any]],
    decoded_events: List[Optional[Dict[str, Any]]],
    alerts: List[Alert],
) -> FixtureResult:
    """
    Classify a fixture into one of the 5 categories.

    Args:
        case_id: Fixture case ID (e.g., "P-DET-01")
        expected: Expected verdict ("alert" or "no_alert")
        events: Raw events from the fixture
        decoded_events: Decoded events (None for undecodable)
        alerts: Alerts produced by the rule engine
    """
    events_count = len(events)
    decoded_count = sum(1 for d in decoded_events if d is not None)

    # 1. No telemetry: no events at all
    if events_count == 0:
        return FixtureResult(case_id, expected, NO_TELEMETRY, [], 0, 0,
                             "No events received")

    # 2. Decoder failure: events present but none decoded
    if decoded_count == 0:
        return FixtureResult(case_id, expected, DECODER_FAILURE, [],
                             events_count, 0,
                             f"{events_count} events, 0 decoded")

    # 3. Alerted: at least one alert produced
    if alerts:
        return FixtureResult(case_id, expected, ALERTED, alerts,
                             events_count, decoded_count,
                             f"{len(alerts)} alert(s) from {decoded_count} decoded events")

    # 4. Rule miss: decoded events but no alerts
    # This is the "no alert" case — could be correct (benign) or a miss (attack)
    if expected == "alert":
        return FixtureResult(case_id, expected, RULE_MISS, [],
                             events_count, decoded_count,
                             f"{decoded_count} decoded, no rule matched (missed attack)")
    else:
        return FixtureResult(case_id, expected, RULE_MISS, [],
                             events_count, decoded_count,
                             f"{decoded_count} decoded, no rule matched (correct benign)")


def classify_replay_event(
    event: Dict[str, Any],
    decoded: Optional[Dict[str, Any]],
    alerts: List[Alert],
) -> str:
    """Classify a single replay event (for replay mode reporting)."""
    if not event:
        return NO_TELEMETRY
    if decoded is None:
        return DECODER_FAILURE
    if alerts:
        return ALERTED
    return RULE_MISS
