"""
Correlator: applies correlation rules that match sequences of events
within time windows on the same host.

Correlation rules fire when N matching events occur within a timeframe,
optionally in a specific sequence order.
"""

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from .rules_config import (
    CORRELATION_RULES, NON_NATIVE_FAMILIES,
    in_class, normalize_process,
)


class CorrelationAlert:
    """An alert produced by a correlation rule."""

    def __init__(self, rule_id: int, level: int, name: str,
                 host: str, events: List[Dict[str, Any]], mitre: str = None):
        self.rule_id = rule_id
        self.level = level
        self.name = name
        self.host = host
        self.events = events
        self.mitre = mitre

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "level": self.level,
            "name": self.name,
            "host": self.host,
            "event_count": len(self.events),
            "mitre": self.mitre,
            "events": [e.get("event_id", "unknown") for e in self.events],
        }

    def __repr__(self):
        return f"CorrelationAlert(rule={self.rule_id}, host={self.host}, events={len(self.events)})"


def parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


class Correlator:
    """Applies correlation rules to a stream of events."""

    def __init__(self, rules=None):
        self.rules = rules or CORRELATION_RULES
        # Per-host event history: {host: [(timestamp, event), ...]}
        self.history: Dict[str, List[Tuple[datetime, Dict]]] = defaultdict(list)
        self.alerts: List[CorrelationAlert] = []

    def _event_matches_criteria(self, event: Dict, criteria: Dict) -> bool:
        """Check if an event matches the criteria for a sequence step."""
        if "family" in criteria:
            if event.get("command_family") != criteria["family"]:
                return False
        if "image_class" in criteria:
            if not in_class(event.get("image", ""), criteria["image_class"]):
                return False
        if "parent_class" in criteria:
            if not in_class(event.get("parent", ""), criteria["parent_class"]):
                return False
        return True

    def _check_sequence(self, host: str, events_with_ts: List, rule: Dict) -> bool:
        """
        Check if the events match a sequence pattern.
        Each step must match in order, within the timeframe.
        """
        sequence = rule.get("sequence")
        if not sequence:
            return False

        # Find events matching each step in order
        matched_events = []
        search_start = 0

        for step in sequence:
            found = False
            for i in range(search_start, len(events_with_ts)):
                ts, event = events_with_ts[i]
                if self._event_matches_criteria(event, step):
                    matched_events.append(event)
                    search_start = i + 1
                    found = True
                    break
            if not found:
                return False

        # Check timeframe: first and last matched events within window
        if len(matched_events) >= 2:
            first_ts = None
            last_ts = None
            for ts, event in events_with_ts:
                if event in matched_events:
                    if first_ts is None:
                        first_ts = ts
                    last_ts = ts
            if first_ts and last_ts:
                delta = (last_ts - first_ts).total_seconds()
                if delta > rule["timeframe"]:
                    return False

        return len(matched_events) >= 2

    def _check_frequency(self, host: str, events_with_ts: List, rule: Dict) -> bool:
        """Check if N non-native events from same host within timeframe."""
        timeframe = rule["timeframe"]
        non_native = [(ts, ev) for ts, ev in events_with_ts
                      if ev.get("command_family") in NON_NATIVE_FAMILIES]

        if len(non_native) < rule["frequency"]:
            return False

        # Check if frequency events fit within timeframe
        if len(non_native) >= rule["frequency"]:
            first = non_native[0][0]
            last = non_native[-1][0]
            if (last - first).total_seconds() <= timeframe:
                return True

        return False

    def process_event(self, event: Dict[str, Any]) -> List[CorrelationAlert]:
        """Process a single event and check all correlation rules."""
        host = event.get("host", "unknown")
        ts = parse_timestamp(event.get("timestamp") or event.get("_timestamp"))

        if ts is None:
            ts = datetime.now()

        # Skip benign events entirely - they can never trigger correlation rules
        family = event.get("command_family", "")
        if family in ("native", "signed_update", ""):
            return []

        # Add to history
        self.history[host].append((ts, event))

        # Prune old events (keep last 24h + buffer)
        cutoff = ts - timedelta(seconds=90000)  # 25h
        self.history[host] = [(t, e) for t, e in self.history[host] if t >= cutoff]

        alerts = []
        events_with_ts = self.history[host]

        for rule in self.rules:
            fired = False

            if rule.get("sequence"):
                fired = self._check_sequence(host, events_with_ts, rule)
            else:
                # Frequency-based rule
                fired = self._check_frequency(host, events_with_ts, rule)

            if fired:
                # Get the matching events
                if rule.get("sequence"):
                    matched = [e for _, e in events_with_ts
                               if e.get("command_family") in NON_NATIVE_FAMILIES]
                else:
                    matched = [e for _, e in events_with_ts
                                if e.get("command_family") in NON_NATIVE_FAMILIES]

                alert = CorrelationAlert(
                    rule_id=rule["rule_id"],
                    level=rule["level"],
                    name=rule["name"],
                    host=host,
                    events=matched[-rule["frequency"]:] if matched else [],
                    mitre=rule.get("mitre"),
                )
                alerts.append(alert)
                self.alerts.append(alert)

        return alerts

    def process_events(self, events: List[Dict[str, Any]]) -> List[CorrelationAlert]:
        """Process a list of events and return all correlation alerts."""
        all_alerts = []
        for event in events:
            alerts = self.process_event(event)
            all_alerts.extend(alerts)
        return all_alerts

    def reset(self):
        """Reset correlator state."""
        self.history.clear()
        self.alerts.clear()
