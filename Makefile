PYTHON ?= python3
export PYTHONPATH := src

.PHONY: test run install

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest --cov=src/decoy --cov-report=term-missing --cov-fail-under=80

run:
	$(PYTHON) -m decoy serve
