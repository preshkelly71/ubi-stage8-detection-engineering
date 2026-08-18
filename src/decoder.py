"""
Decoder for NETFORGE_TRAINING_PROCESS events.

Parses the Wazuh-decodable format produced by the adapter:
  NETFORGE_TRAINING_PROCESS host=X user=X image=X parent=X family=X [technique_id=X]

The decoder extracts all fields and returns a dict. It handles:
  - Missing fields (returns None for absent fields)
  - Malformed lines (returns None)
  - Both fixture mode (with technique_id) and replay mode (without)
"""

import re
from typing import Optional, Dict, Any

# Regex pattern for the NETFORGE_TRAINING_PROCESS prefix
PREFIX_PATTERN = re.compile(r"^NETFORGE_TRAINING_PROCESS\s+")

# Field extraction regex
FIELD_PATTERN = re.compile(r"(\w+)=(\S+)")


def decode(line: str) -> Optional[Dict[str, Any]]:
    """
    Decode a single line of NETFORGE_TRAINING_PROCESS format.

    Returns a dict with keys: host, user, image, parent, command_family,
    technique_id (optional), and _raw (the original line).

    Returns None if the line is not decodable.
    """
    if not line or not isinstance(line, str):
        return None

    line = line.strip()
    if not line:
        return None

    # Check for the required prefix
    if not PREFIX_PATTERN.match(line):
        return None

    # Extract all field=value pairs
    fields = dict(FIELD_PATTERN.findall(line))

    # Map field names (decoder uses 'family' but events use 'command_family')
    result = {
        "host": fields.get("host"),
        "user": fields.get("user"),
        "image": fields.get("image"),
        "parent": fields.get("parent"),
        "command_family": fields.get("family") or fields.get("command_family"),
        "technique_id": fields.get("technique_id"),
        "_raw": line,
    }

    # Validate required fields
    required = ["host", "image", "parent", "command_family"]
    if any(result.get(f) is None for f in required):
        return None

    return result


def decode_batch(lines):
    """Decode a batch of lines, yielding (line, decoded_dict_or_none) tuples."""
    for line in lines:
        yield line, decode(line)
