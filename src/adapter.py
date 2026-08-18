"""
Adapter: converts raw event sources to Wazuh-decodable NETFORGE_TRAINING_PROCESS format.

Two sources:
  1. windows-replay.jsonl (sealed replay, 250K events, no technique_id)
  2. public-fixtures.json (36 fixtures, each with 2 events, technique_id in Sysmon event)

Output format:
  NETFORGE_TRAINING_PROCESS host=NS-WIN-101 user=NORTHSTAR\\analyst1 image=powershell.exe parent=winword.exe family=encoded_or_obfuscated [technique_id=T1059.001]

The adapter streams events to avoid loading 250K events into memory.
"""

import json
from typing import Iterator, Dict, Any, List, Tuple


def event_to_logline(event: Dict[str, Any]) -> str:
    """Convert a single event dict to NETFORGE_TRAINING_PROCESS format."""
    parts = [
        f"host={event.get('host', event.get('computer', 'unknown'))}",
        f"user={event.get('user', 'unknown')}",
        f"image={event.get('image', 'unknown')}",
        f"parent={event.get('parent', event.get('parent_image', 'unknown'))}",
        f"family={event.get('command_family', event.get('family', 'native'))}",
    ]
    # Add technique_id if present (fixture mode only)
    tech = event.get("technique_id")
    if tech:
        parts.append(f"technique_id={tech}")

    return "NETFORGE_TRAINING_PROCESS " + " ".join(parts)


def convert_replay(jsonl_path: str) -> Iterator[str]:
    """
    Stream-convert windows-replay.jsonl to NETFORGE_TRAINING_PROCESS lines.

    Each JSONL event becomes one log line.
    """
    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield event_to_logline(event)


def convert_fixtures(json_path: str) -> List[Tuple[str, List[str]]]:
    """
    Convert public-fixtures.json to a list of (case_id, [log_lines]) tuples.

    Each fixture produces 1-2 log lines (one per event).
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    fixtures = data.get("fixtures", [])
    results = []

    for fixture in fixtures:
        case_id = fixture.get("case_id", "unknown")
        expected = fixture.get("expected", "no_alert")
        log_lines = []

        for ev in fixture.get("events", []):
            # Build event dict from fixture event
            event = {
                "host": ev.get("host", "NS-WIN-101"),
                "user": ev.get("user", "NORTHSTAR\\analyst1"),
                "image": ev.get("image", "unknown.exe"),
                "parent": ev.get("parent_image", "unknown.exe"),
                "command_family": ev.get("command_family", "native"),
                "technique_id": ev.get("technique_id"),
            }
            log_lines.append(event_to_logline(event))

        results.append((case_id, expected, log_lines))

    return results


def get_fixture_metadata(json_path: str) -> Dict[str, Any]:
    """Extract metadata from the fixtures file (interface_version, schema_version, etc.)."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        "interface_version": data.get("interface_version"),
        "schema_version": data.get("schema_version"),
        "project": data.get("project"),
        "fixture_count": len(data.get("fixtures", [])),
    }
