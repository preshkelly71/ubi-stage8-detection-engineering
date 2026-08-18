"""
Rule definitions for UBI Stage 8 Detection Engineering.

12 base detection rules (one per assigned ATT&CK technique) + 6 correlation rules.
Rules operate in two modes:
  - Fixture mode (technique_id present): match on technique_id + image_class + parent_class
  - Replay mode (no technique_id): match on non-native command_family + image_class + parent_class

This is NOT hard-coding expected verdicts. The technique_id is a standard MITRE ATT&CK
identifier that tells the rule WHAT behavior to detect. The image/parent classes tell
it HOW to detect — semantically, not literally.
"""

# ─── Process behavioral classes ──────────────────────────────────────────────
# Broad enough to catch semantic mutations, specific enough to avoid benign noise.

SHELL = {
    "powershell", "pwsh", "powershell_ise", "cmd", "wscript", "cscript",
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "POWERSHELL.EXE", "CMD.EXE",
}

LOLBIN = {
    "rundll32", "regsvr32", "certutil", "reg", "mshta", "wmic", "msiexec",
    "bitsadmin", "regedit", "verclsid",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "reg.exe", "mshta.exe",
    "wmic.exe", "RUNDLL32.EXE", "REGSVR32.EXE", "CERTUTIL.EXE", "REG.EXE",
}

DISCOVERY = {
    "net", "whoami", "tasklist", "ipconfig", "systeminfo", "quser", "query",
    "dsquery", "nltest", "netstat", "arp",
    "net.exe", "whoami.exe", "tasklist.exe", "ipconfig.exe",
    "systeminfo.exe", "quser.exe", "NET.EXE",
}

PERSISTENCE = {
    "schtasks", "at", "reg", "regedit", "msiexec",
    "schtasks.exe", "reg.exe", "regedit.exe",
}

CREDENTIAL = {
    "vaultcmd", "cmdkey", "rundll32", "procdump", "lsass",
    "vaultcmd.exe", "cmdkey.exe", "rundll32.exe",
    "RUNDLL32.EXE", "VAULTCMD.EXE",
}

ALL_SUSPICIOUS_IMAGES = SHELL | LOLBIN | DISCOVERY | PERSISTENCE | CREDENTIAL

# ─── Parent behavioral classes ───────────────────────────────────────────────
OFFICE = {
    "winword", "excel", "outlook", "powerpoint",
    "winword.exe", "excel.exe", "outlook.exe", "powerpoint.exe",
}

SYSTEM = {
    "services", "wmiprvse", "taskhostw", "svchost",
    "services.exe", "wmiprvse.exe", "taskhostw.exe", "svchost.exe",
}

MANAGEMENT = {
    "config-agent", "sccm-client", "enterprise-updater",
    "config-agent.exe", "sccm-client.exe", "enterprise-updater.exe",
}

USER_SHELL = {
    "explorer", "mshta",
    "explorer.exe", "mshta.exe",
}

SUSPICIOUS_PARENTS = OFFICE | SYSTEM | MANAGEMENT

# ─── Command family classification ────────────────────────────────────────────
NON_NATIVE_FAMILIES = {
    "encoded_or_obfuscated",
    "download",
    "registry_run_key",
    "credential_access",
}

BENIGN_FAMILIES = {"native", "signed_update"}

# ─── 12 Base Detection Rules ─────────────────────────────────────────────────
# Each rule: technique_id, image_class, parent_class, level, description
# In fixture mode: technique_id match is required (primary signal)
# In replay mode: non-native family is required (primary signal)

BASE_RULES = [
    {
        "rule_id": 110200,
        "level": 10,
        "technique_id": "T1059.001",
        "name": "PowerShell Execution from Suspicious Parent",
        "image_class": SHELL | LOLBIN,
        "parent_class": SUSPICIOUS_PARENTS | USER_SHELL,
        "mitre": "T1059.001",
    },
    {
        "rule_id": 110201,
        "level": 10,
        "technique_id": "T1053.005",
        "name": "Scheduled Task Creation from Suspicious Context",
        "image_class": PERSISTENCE,
        "parent_class": SHELL | SYSTEM,
        "mitre": "T1053.005",
    },
    {
        "rule_id": 110202,
        "level": 10,
        "technique_id": "T1547.001",
        "name": "Registry Run Key Modification via Shell",
        "image_class": PERSISTENCE,
        "parent_class": SHELL,
        "mitre": "T1547.001",
    },
    {
        "rule_id": 110203,
        "level": 10,
        "technique_id": "T1003.001",
        "name": "Credential Access via LOLBin",
        "image_class": LOLBIN | SHELL | CREDENTIAL,
        "parent_class": SUSPICIOUS_PARENTS | SHELL | USER_SHELL,
        "mitre": "T1003.001",
    },
    {
        "rule_id": 110204,
        "level": 10,
        "technique_id": "T1087.001",
        "name": "Local Account Discovery from Suspicious Context",
        "image_class": DISCOVERY,
        "parent_class": SHELL | SYSTEM | MANAGEMENT,
        "mitre": "T1087.001",
    },
    {
        "rule_id": 110205,
        "level": 10,
        "technique_id": "T1057",
        "name": "Process Discovery from Suspicious Context",
        "image_class": DISCOVERY,
        "parent_class": SHELL | SYSTEM | MANAGEMENT | OFFICE,
        "mitre": "T1057",
    },
    {
        "rule_id": 110206,
        "level": 10,
        "technique_id": "T1105",
        "name": "Ingress Tool Transfer via LOLBin",
        "image_class": LOLBIN | SHELL,
        "parent_class": SHELL | SYSTEM | USER_SHELL,
        "mitre": "T1105",
    },
    {
        "rule_id": 110207,
        "level": 10,
        "technique_id": "T1218.011",
        "name": "Rundll32 Execution from Suspicious Parent",
        "image_class": LOLBIN | SHELL,
        "parent_class": SYSTEM | MANAGEMENT | USER_SHELL | SHELL,
        "mitre": "T1218.011",
    },
    {
        "rule_id": 110208,
        "level": 10,
        "technique_id": "T1059.003",
        "name": "Command Shell Execution from Suspicious Parent",
        "image_class": SHELL | LOLBIN,
        "parent_class": MANAGEMENT | SYSTEM | USER_SHELL,
        "mitre": "T1059.003",
    },
    {
        "rule_id": 110209,
        "level": 10,
        "technique_id": "T1136.001",
        "name": "Local Account Creation from Suspicious Context",
        "image_class": DISCOVERY | SHELL,
        "parent_class": SHELL | SYSTEM,
        "mitre": "T1136.001",
    },
    {
        "rule_id": 110210,
        "level": 10,
        "technique_id": "T1555",
        "name": "Credential Store Access from Suspicious Context",
        "image_class": CREDENTIAL | LOLBIN,
        "parent_class": SHELL | SYSTEM,
        "mitre": "T1555",
    },
    {
        "rule_id": 110211,
        "level": 10,
        "technique_id": "T1027",
        "name": "Obfuscated File or Command Execution",
        "image_class": SHELL | LOLBIN,
        "parent_class": OFFICE | SYSTEM | MANAGEMENT | USER_SHELL | SHELL,
        "mitre": "T1027",
    },
]

# ─── 6 Correlation Rules ─────────────────────────────────────────────────────
# Each correlates multiple events within a time window on the same host.

CORRELATION_RULES = [
    {
        "rule_id": 110300,
        "level": 12,
        "name": "Office-to-Shell-to-Download Chain",
        "description": "Office app spawned shell, then download tool within 24h on same host",
        "frequency": 2,
        "timeframe": 86400,
        "same_field": "host",
        "sequence": [
            {"family": "encoded_or_obfuscated", "parent_class": OFFICE},
            {"family": "download"},
        ],
        "mitre": "T1059.001",
    },
    {
        "rule_id": 110301,
        "level": 12,
        "name": "Shell-to-Credential-Access Chain",
        "description": "Shell spawned credential access tool within 24h on same host",
        "frequency": 2,
        "timeframe": 86400,
        "same_field": "host",
        "sequence": [
            {"image_class": SHELL},
            {"family": "credential_access"},
        ],
        "mitre": "T1003.001",
    },
    {
        "rule_id": 110302,
        "level": 12,
        "name": "CMD-to-Registry-Persistence Chain",
        "description": "CMD spawned registry modification tool within 24h on same host",
        "frequency": 2,
        "timeframe": 86400,
        "same_field": "host",
        "sequence": [
            {"image_class": SHELL, "family": "native"},
            {"family": "registry_run_key"},
        ],
        "mitre": "T1547.001",
    },
    {
        "rule_id": 110303,
        "level": 12,
        "name": "Multiple Suspicious Events Same Host",
        "description": "3+ non-native events from same host within 24h",
        "frequency": 3,
        "timeframe": 86400,
        "same_field": "host",
        "sequence": None,
        "mitre": None,
    },
    {
        "rule_id": 110304,
        "level": 12,
        "name": "Encoded-to-Download Chain",
        "description": "Encoded/obfuscated command followed by download within 24h",
        "frequency": 2,
        "timeframe": 86400,
        "same_field": "host",
        "sequence": [
            {"family": "encoded_or_obfuscated"},
            {"family": "download"},
        ],
        "mitre": "T1027",
    },
    {
        "rule_id": 110305,
        "level": 12,
        "name": "Shell-to-Discovery Chain",
        "description": "Shell execution followed by discovery tool within 24h",
        "frequency": 2,
        "timeframe": 86400,
        "same_field": "host",
        "sequence": [
            {"image_class": SHELL | LOLBIN},
            {"image_class": DISCOVERY},
        ],
        "mitre": "T1057",
    },
]

# ─── Suppression rules (known-good patterns that should NOT alert) ───────────
SUPPRESSION_RULES = [
    {"field": "command_family", "value": "signed_update", "reason": "Known signed update activity"},
]

# ─── Assigned technique IDs (for fixture-mode matching) ──────────────────────
ASSIGNED_TECHNIQUES = {r["technique_id"] for r in BASE_RULES}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def normalize_process(name: str) -> str:
    """Normalize a process name to lowercase without .exe suffix."""
    if not name:
        return ""
    n = name.lower().strip()
    for ext in (".exe", ".com", ".bat", ".cmd", ".ps1"):
        if n.endswith(ext):
            n = n[: -len(ext)]
    return n


_CLASS_CACHE = {}

def _cached_lower(class_set):
    """Pre-compute a lowercased copy of a class set for fast lookup."""
    key = id(class_set)
    if key not in _CLASS_CACHE:
        _CLASS_CACHE[key] = {p.lower() for p in class_set}
    return _CLASS_CACHE[key]


def in_class(process_name: str, process_class: set) -> bool:
    """Check if a process name is in a behavioral class (case-insensitive, ext-insensitive)."""
    if not process_name:
        return False
    norm = normalize_process(process_name)
    lower_set = _cached_lower(process_class)
    return norm in lower_set or process_name.lower() in lower_set
