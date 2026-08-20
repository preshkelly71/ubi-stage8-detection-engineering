# Continuity Record — Stage 7 to Stage 8

## Previous-stage component reused

**Stage 7:** Network Range Design and Verification
**Commit:** 2ba6daa (https://github.com/preshkelly71/ubi-stage7-network-range)
**Component reused:** Test-driven verification model, manifest/hash evidence standard, deterministic output verification

## Interface consumed

1. **Provenance model**: Every detection result retains a raw locator (event_id from sealed replay, case_id from fixtures). This extends Stage 7's path-ID provenance to detection events.
2. **Manifest verification**: Same `manifest.sha256` and `assessment-manifest.json` pattern as Stage 7, extended with replay-specific output hashes.
3. **Test structure**: Positive, negative, malformed-input, and clean-state tests — same four categories as Stage 7's fault cycle tests.

## Backward-compatible extensions

- Stage 7's `test-results.xml` (JUnit format) is preserved as the test output format
- Stage 7's Makefile pattern (`make test`, `make harness`) is extended with `make replay`
- Stage 7's `.gitignore` pattern for excluding raw evidence is preserved (`raw-events/` is gitignored)

## Evidence that prior raw-to-result provenance remains intact

- Sealed replay SHA-256 verified against source-manifest.json: `ea7f96497f9275ccdc47fdb026480558547db5bfaa7aa8bf3a806a2bc9272838`
- Every alert from the sealed replay includes the source event_id (EVT-14b4bf-XXXXX)
- Fixture results map each case_id (P-DET-01 through P-DET-36) to its decoded events and alerts

## Migration record

No incompatible changes. The Stage 7 test framework was general (pytest + JUnit XML) and required no migration. The detection rule format (Wazuh XML) is new to Stage 8 but follows the same evidence standard.

## Next-stage handoff

The following components are handed to Stage 9:
- 12 Wazuh-compatible detection rules (rules/ and decoders/local_rules.xml)
- 1 Wazuh decoder (rules/ and decoders/local_decoder.xml)
- Python test harness with 5-way classification (src/harness.py)
- 6 correlation rules with time-window sequences (src/correlator.py)
- Behavioral process classification system (src/rules_config.py)
- Coverage gaps documented in coverage-matrix.csv (5 techniques have no sealed replay or public fixture evidence — require live lab testing)
