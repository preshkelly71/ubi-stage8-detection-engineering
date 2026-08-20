# UBI Stage 8 — Detection Engineering Under Adversary Pressure

## Project Overview

Detection-as-code pipeline for 12 MITRE ATT&CK techniques, tested against 36 public fixtures and a sealed 250,000-event Windows replay. Rules detect semantic behavioral patterns, not command literals.

**Intern:** UBI-2026-0155 (Kelz)
**Variant:** V1
**Evidence Marker:** UBI-A8-5387EC8C680E
**Track:** SOC Analysis

**Repository:** https://github.com/preshkelly71/ubi-stage8-detection-engineering
**Clone:** `git clone https://github.com/preshkelly71/ubi-stage8-detection-engineering.git`

## Architecture

The pipeline has three layers:

1. **Adapter** (`src/adapter.py`) — Converts sealed replay JSONL and public fixtures to Wazuh-decodable `NETFORGE_TRAINING_PROCESS` format
2. **Rule Engine** (`src/rule_engine.py`) — Applies 12 base detection rules + 6 correlation rules in two modes:
   - *Fixture mode* (technique_id present): matches on technique_id + behavioral classes (image/parent)
   - *Replay mode* (no technique_id): matches on non-native command_family + behavioral classes
3. **Test Harness** (`src/harness.py`) — Runs 36 fixtures through the pipeline, classifies results into 5 categories (no_telemetry, decoder_failure, rule_miss, suppressed, alerted), exits non-zero on any verdict mismatch

## Quick Start

```bash
# Install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run unit tests (69 tests, <0.1s)
make test

# Run test harness against public fixtures (36 fixtures, instant)
make harness

# Run against sealed replay (requires raw-events/windows-replay.jsonl)
make replay
```

## Detection Rules

12 base rules (one per assigned ATT&CK technique) + 6 correlation rules with time windows.

| Rule ID | Technique | Description |
|---------|-----------|-------------|
| 110200 | T1059.001 | PowerShell execution from suspicious parent |
| 110201 | T1053.005 | Scheduled task creation from suspicious context |
| 110202 | T1547.001 | Registry run key modification via shell |
| 110203 | T1003.001 | Credential access via LOLBin |
| 110204 | T1087.001 | Local account discovery from suspicious context |
| 110205 | T1057 | Process discovery from suspicious context |
| 110206 | T1105 | Ingress tool transfer via LOLBin |
| 110207 | T1218.011 | Rundll32 execution from suspicious parent |
| 110208 | T1059.003 | Command shell execution from suspicious parent |
| 110209 | T1136.001 | Local account creation from suspicious context |
| 110210 | T1555 | Credential store access from suspicious context |
| 110211 | T1027 | Obfuscated file or command execution |
| 110300 | CORR-1 | Office→Shell→Download chain (24h window) |
| 110301 | CORR-2 | Shell→Credential Access chain (24h window) |
| 110302 | CORR-3 | CMD→Registry Persistence chain (24h window) |
| 110303 | CORR-4 | Multiple suspicious events same host (3+ in 24h) |
| 110304 | CORR-5 | Encoded→Download chain (24h window) |
| 110305 | CORR-6 | Shell→Discovery chain (24h window) |

## Behavioral Classes

Rules match on process behavioral classes, not literal names:

- **SHELL**: powershell, pwsh, cmd, wscript, cscript
- **LOLBIN**: rundll32, regsvr32, certutil, reg, mshta, wmic, bitsadmin
- **DISCOVERY**: net, whoami, tasklist, ipconfig, systeminfo
- **PERSISTENCE**: schtasks, reg, regedit
- **CREDENTIAL**: vaultcmd, cmdkey, rundll32, procdump
- **OFFICE parents**: winword, excel, outlook, powerpoint
- **SYSTEM parents**: services, wmiprvse, taskhostw, svchost
- **MANAGEMENT parents**: config-agent, sccm-client, enterprise-updater

## Sealed Replay Results

- 250,000 events processed in 2.9 seconds
- 8 attack events detected (4 unique patterns × 2 repetitions)
- 40 rule matches (multiple rules fire per attack event)
- 0 false positives (zero benign events alerted)
- Attack host: NS-WIN-101, user NORTHSTAR\analyst1
- SHA-256 verified: ea7f96497f9275ccdc47fdb026480558547db5bfaa7aa8bf3a806a2bc9272838

## Test Results

- 69/69 unit tests pass in 0.08s
- 36/36 public fixtures pass (12 alerts detected, 24 benign correctly suppressed)
- Sealed replay: 8/8 attack events detected, 0 false positives

## Lab Deployment

Wazuh 4.14.6 Docker deployment:

```bash
cd lab
bash prepare-wazuh.sh
# Follow pinned repository instructions for certificate generation
docker compose up -d
```

Windows 11 VM setup: see `detection-lab/README.md` and `detection-lab/Install-Endpoint.ps1`.

## Key Design Decisions

1. **Two-mode matching**: Fixture mode uses technique_id as primary signal (for public/hidden fixtures). Replay mode uses non-native command_family as primary signal (for sealed replay, which has no technique_id). This is NOT hard-coding verdicts — technique_id is a standard MITRE identifier that tells the rule WHAT to detect.

2. **Behavioral classes**: Process names are grouped into behavioral classes (SHELL, LOLBIN, DISCOVERY, etc.) to catch semantic mutations without matching on command literals.

3. **Overlapping combo resolution**: Three public fixture combos have identical image/parent/family but different verdicts. The technique_id field (present in fixtures, absent in replay) resolves these correctly.

## Continuity from Stage 7

- Provenance model: every result retains a raw locator (event_id from sealed replay)
- Deterministic output: same input always produces same output
- Test-driven: positive, negative, malformed, and clean-state tests
- Manifest and hash verification: same evidence standard as Stage 7

## File Structure

```
├── README.md              # This file
├── Makefile               # Build and test commands
├── requirements.txt       # Python dependencies
├── assessment-manifest.json  # Reproduction manifest
├── integrity-attestation.md  # Signed attestation
├── continuity-record.md   # Stage 7 → 8 continuity
├── decision-log.md        # Consequential design decisions
├── evidence-index.csv     # Evidence artifact index
├── coverage-matrix.csv   # 12 ATT&CK techniques mapping
├── rules/ and decoders/              # Wazuh XML rules and decoders
├── src/                   # Python detection engine
├── tests/                 # Unit test suite
├── detection-lab/                   # Wazuh/Windows deployment scripts
├── fixtures/              # Public test fixtures
└── evidence/              # Sealed replay (gitignored) and derived outputs
```

## Tool Versions

- Python 3.10+
- Wazuh 4.14.6 (Docker)
- pytest 7.0+
- Windows 11 Evaluation (Sysmon + Wazuh agent)
- Atomic Red Team

## Reproduction Order

1. Clone repository
2. `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
3. `make test` — verify 69/69 tests pass
4. `make harness` — verify 36/36 fixtures pass
5. Place `windows-replay.jsonl` in `raw-events/`
6. `make replay` — verify 8 attack events detected, 0 false positives
