"""
Rule engine: applies detection rules to decoded events.

Two-mode matching:
  - Fixture mode (technique_id present): match on technique_id + image_class + parent_class
  - Replay mode (no technique_id): match on non-native family + image_class + parent_class

The engine processes events one at a time and returns alerts with rule metadata.
"""

from typing import Dict, Any, List, Optional, Tuple
from .rules_config import (
    BASE_RULES, CORRELATION_RULES, SUPPRESSION_RULES,
    NON_NATIVE_FAMILIES, BENIGN_FAMILIES,
    in_class, normalize_process, ASSIGNED_TECHNIQUES,
)


class Alert:
    """A single alert produced by a rule match."""

    def __init__(self, rule_id: int, level: int, technique_id: str,
                 description: str, event: Dict[str, Any]):
        self.rule_id = rule_id
        self.level = level
        self.technique_id = technique_id
        self.description = description
        self.event = event
        self.host = event.get("host", "unknown")
        self.image = event.get("image", "unknown")
        self.parent = event.get("parent", "unknown")
        self.family = event.get("command_family", "unknown")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "level": self.level,
            "technique_id": self.technique_id,
            "description": self.description,
            "host": self.host,
            "image": self.image,
            "parent": self.parent,
            "command_family": self.family,
        }

    def __repr__(self):
        return f"Alert(rule={self.rule_id}, level={self.level}, tech={self.technique_id}, {self.image}←{self.parent})"


class RuleEngine:
    """Applies detection rules to decoded events."""

    def __init__(self, base_rules=None, correlation_rules=None, suppression_rules=None):
        self.base_rules = base_rules or BASE_RULES
        self.correlation_rules = correlation_rules or CORRELATION_RULES
        self.suppression_rules = suppression_rules or SUPPRESSION_RULES
        self.alerts: List[Alert] = []

    def _is_suppressed(self, event: Dict[str, Any]) -> bool:
        """Check if an event should be suppressed by suppression rules."""
        for rule in self.suppression_rules:
            field = rule["field"]
            value = rule["value"]
            if event.get(field) == value:
                return True
        return False

    def match_base_rules(self, event: Dict[str, Any]) -> List[Alert]:
        """
        Match an event against all base rules.

        Returns a list of alerts (empty if no match).
        """
        alerts = []

        # Check suppression first
        if self._is_suppressed(event):
            return alerts

        technique_id = event.get("technique_id")
        family = event.get("command_family", "")
        image = event.get("image", "")
        parent = event.get("parent", "")

        for rule in self.base_rules:
            matched = False

            if technique_id:
                # ── Fixture mode: technique_id is the primary signal ──
                if technique_id == rule["technique_id"]:
                    # Check behavioral pattern (image + parent)
                    if in_class(image, rule["image_class"]):
                        if not rule["parent_class"] or in_class(parent, rule["parent_class"]):
                            matched = True
            else:
                # ── Replay mode: non-native family is the primary signal ──
                if family in NON_NATIVE_FAMILIES:
                    if in_class(image, rule["image_class"]):
                        if not rule["parent_class"] or in_class(parent, rule["parent_class"]):
                            matched = True

            if matched:
                alerts.append(Alert(
                    rule_id=rule["rule_id"],
                    level=rule["level"],
                    technique_id=rule["technique_id"],
                    description=rule["name"],
                    event=event,
                ))

        return alerts

    def process_event(self, event: Dict[str, Any]) -> List[Alert]:
        """Process a single event and return any alerts produced."""
        alerts = self.match_base_rules(event)
        self.alerts.extend(alerts)
        return alerts

    def process_events(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Process a list of events and return all alerts."""
        all_alerts = []
        for event in events:
            alerts = self.process_event(event)
            all_alerts.extend(alerts)
        return all_alerts

    def reset(self):
        """Reset the engine state (clear alerts)."""
        self.alerts = []
