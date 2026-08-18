.PHONY: test harness replay clean lint deploy

PYTHON := python3
PIP := pip3

# Create venv and install deps
setup:
	$(PYTHON) -m venv .venv
	. .venv/bin/activate && $(PIP) install -q -r requirements.txt

# Run unit tests (fast, no replay required)
test:
	$(PYTHON) -m pytest tests/ -v --junitxml=test-results.xml

# Run the test harness against public fixtures
harness:
	$(PYTHON) -m src.harness --fixtures fixtures/public-fixtures.json --report test-results.xml --json-report test-results.json

# Run the harness against sealed replay (requires evidence/raw/windows-replay.jsonl)
replay:
	$(PYTHON) -m src.harness --replay evidence/raw/windows-replay.jsonl --report replay-results.xml --json-report replay-results.json

# Run both fixtures and replay
all:
	$(PYTHON) -m src.harness --fixtures fixtures/public-fixtures.json --replay evidence/raw/windows-replay.jsonl --report test-results.xml --json-report test-results.json

# Deploy Wazuh Docker (requires Docker)
deploy:
	cd lab && bash prepare-wazuh.sh
	@echo "Generate certificates with the pinned repository instructions before docker compose up."

clean:
	rm -rf test-results.xml test-results.json replay-results.xml replay-results.json
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name ".pytest_cache" -type d -exec rm -rf {} + 2>/dev/null || true

lint:
	$(PYTHON) -m py_compile src/*.py tests/*.py
